//! Azure Service Bus `watch_strategy` plugin (`dev.mcpg.watch.servicebus`).
//!
//! The `servicebus_entity` strategy receives from a queue, a topic
//! subscription, or the dead-letter queue of either, in peek-lock mode
//! through the SDK's queue helper. Each message is one `servicebus.message`
//! event. It is completed once the gateway has stored the event and
//! abandoned when the gateway has not done so in `ack_timeout_ms`, so
//! delivery is at-least-once; the broker's sequence number is the event id,
//! so the gateway takes a redelivered message once. The message's lock is
//! renewed while the gateway has it. A session-enabled entity is read one
//! session at a time: each session the broker offers in turn, or one named
//! session.

mod auth;
mod link;
mod management;
mod message;
#[cfg(test)]
mod recording_http;

use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::queue::{
    QueueOptions, acknowledge_queue_watch, cancel_queue_watch, defaults, spawn_queue_watch,
};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::{ConnectionString, Credential, CredentialSpec, Endpoint};
use crate::link::SessionMode;

/// The plugin id.
pub const PLUGIN_ID: &str = "dev.mcpg.watch.servicebus";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "servicebus_entity";

/// The event type each message makes.
pub const MESSAGE_EVENT_TYPE: &str = "servicebus.message";

/// Largest `max_body_bytes`: the event must stay under the host's 256 KiB.
const MAX_BODY_BYTES: usize = 192 * 1024;

fn default_receive_wait_secs() -> u64 {
    10
}

/// A subqueue of the entity, read instead of the entity itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SubQueue {
    /// Messages the broker or a receiver dead-lettered.
    DeadLetter,
    /// Messages that could not be forwarded or sent in a transaction.
    TransferDeadLetter,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// `Endpoint=sb://…;SharedAccessKeyName=…;SharedAccessKey=…`, with an
    /// optional `EntityPath` and `UseDevelopmentEmulator=true`.
    #[serde(default)]
    connection_string: Option<String>,
    /// The fully qualified namespace, `<name>.servicebus.windows.net`.
    #[serde(default)]
    namespace: Option<String>,
    /// How a `namespace` watch proves who it is.
    #[serde(default)]
    credential: Option<CredentialSpec>,
    #[serde(default)]
    queue: Option<String>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    subscription: Option<String>,
    #[serde(default)]
    sub_queue: Option<SubQueue>,
    /// The entity requires sessions: take each session the broker offers,
    /// one at a time.
    #[serde(default)]
    sessions: bool,
    /// The entity requires sessions: take this one.
    #[serde(default)]
    session_id: Option<String>,
    /// Longest one receive waits for a message, seconds (1 to 20).
    #[serde(default = "default_receive_wait_secs")]
    receive_wait_secs: u64,
    /// Most messages received and not yet settled.
    #[serde(default = "defaults::max_in_flight")]
    max_in_flight: usize,
    /// How long a message waits for the gateway before it is abandoned.
    #[serde(default = "defaults::ack_timeout_ms")]
    ack_timeout_ms: u64,
    /// A body past this is left out of the event, with its size.
    #[serde(default = "defaults::max_body_bytes")]
    max_body_bytes: usize,
}

/// What a valid spec resolves to.
struct Plan {
    endpoint: Endpoint,
    /// The entity path the receiver attaches to.
    entity: String,
    credential: CredentialSpec,
    sessions: Option<SessionMode>,
    options: QueueOptions,
    max_body_bytes: usize,
}

/// A queue, topic or subscription name: letters, digits, `.`, `-`, `_`,
/// and for a queue or topic `/` between segments.
fn check_name(field: &str, name: &str, segments: bool) -> Result<(), String> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
    let valid = !name.is_empty()
        && name.len() <= 260
        && name
            .split('/')
            .all(|segment| !segment.is_empty() && segment.chars().all(allowed))
        && (segments || !name.contains('/'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{field} {name:?} is not an entity name: letters, digits, '.', '-' and '_'{}",
            if segments {
                ", segments split by '/'"
            } else {
                ""
            }
        ))
    }
}

fn plan(spec: WatchSpec) -> Result<Plan, String> {
    let (endpoint, credential, entity_path) = match (spec.connection_string, spec.namespace) {
        (Some(_), Some(_)) => {
            return Err("give connection_string or namespace, not both".into());
        }
        (None, None) => {
            return Err("give connection_string, or namespace and credential".into());
        }
        (Some(text), None) => {
            if text.starts_with("cred://") {
                return Err(cred_uri_refused("connection_string"));
            }
            if spec.credential.is_some() {
                return Err(
                    "a connection_string carries its own credential; drop credential".into(),
                );
            }
            let parsed = ConnectionString::parse(&text)?;
            let endpoint = Endpoint::parse(&parsed.endpoint, parsed.emulator)
                .map_err(|e| format!("connection_string: {e}"))?;
            (endpoint, parsed.credential()?, parsed.entity_path)
        }
        (None, Some(namespace)) => {
            let credential = spec
                .credential
                .ok_or_else(|| "a namespace watch needs credential".to_owned())?;
            if credential
                .secrets()
                .iter()
                .any(|s| s.starts_with("cred://"))
            {
                return Err(cred_uri_refused("credential"));
            }
            (Endpoint::parse(&namespace, false)?, credential, None)
        }
    };

    let (queue, topic) = match (spec.queue, spec.topic, entity_path) {
        (Some(_), Some(_), _) => return Err("give queue, or topic and subscription".into()),
        (Some(queue), None, path) => {
            if path.as_ref().is_some_and(|p| *p != queue) {
                return Err(format!(
                    "the connection string's EntityPath is {:?}, not the queue {queue:?}",
                    path.unwrap_or_default()
                ));
            }
            (Some(queue), None)
        }
        (None, Some(topic), path) => {
            if path.as_ref().is_some_and(|p| *p != topic) {
                return Err(format!(
                    "the connection string's EntityPath is {:?}, not the topic {topic:?}",
                    path.unwrap_or_default()
                ));
            }
            (None, Some(topic))
        }
        (None, None, Some(path)) if spec.subscription.is_some() => (None, Some(path)),
        (None, None, Some(path)) => (Some(path), None),
        (None, None, None) => return Err("give queue, or topic and subscription".into()),
    };
    let mut entity = match (queue, topic, spec.subscription) {
        (Some(queue), None, None) => {
            check_name("queue", &queue, true)?;
            queue
        }
        (Some(_), None, Some(_)) => {
            return Err("a subscription belongs to a topic; give topic, not queue".into());
        }
        (None, Some(topic), Some(subscription)) => {
            check_name("topic", &topic, true)?;
            check_name("subscription", &subscription, false)?;
            format!("{topic}/Subscriptions/{subscription}")
        }
        (None, Some(_), None) => return Err("a topic watch needs subscription".into()),
        _ => return Err("give queue, or topic and subscription".into()),
    };
    match spec.sub_queue {
        Some(SubQueue::DeadLetter) => entity.push_str("/$DeadLetterQueue"),
        Some(SubQueue::TransferDeadLetter) => entity.push_str("/$Transfer/$DeadLetterQueue"),
        None => {}
    }
    let sessions = match (spec.sessions, spec.session_id) {
        (_, Some(id)) if id.is_empty() || id.len() > 128 => {
            return Err("session_id must be 1 to 128 characters".into());
        }
        (_, Some(id)) => Some(SessionMode::Id(id)),
        (true, None) => Some(SessionMode::Any),
        (false, None) => None,
    };
    if sessions.is_some() && spec.sub_queue.is_some() {
        return Err("a dead-letter queue has no sessions; drop sessions and session_id".into());
    }

    if !(1..=20).contains(&spec.receive_wait_secs) {
        return Err("receive_wait_secs must be 1 to 20".into());
    }
    if !(1..=MAX_BODY_BYTES).contains(&spec.max_body_bytes) {
        return Err(format!("max_body_bytes must be 1 to {MAX_BODY_BYTES}"));
    }
    let options = QueueOptions {
        source: format!("servicebus {}/{entity}", endpoint.host),
        max_in_flight: spec.max_in_flight,
        ack_timeout: Duration::from_millis(spec.ack_timeout_ms),
        receive_wait: Duration::from_secs(spec.receive_wait_secs),
    };
    options.validate()?;
    Ok(Plan {
        endpoint,
        entity,
        credential,
        sessions,
        options,
        max_body_bytes: spec.max_body_bytes,
    })
}

fn cred_uri_refused(field: &str) -> String {
    format!(
        "{field} must not hold cred:// URIs — per-caller credentials are unsupported; use \
         ${{env.X}} / ${{secret.X}} / vault:// (resolved before the watch starts)"
    )
}

/// `watch_strategy` entity. Stateless beyond its manifest — each watcher's
/// entity and credential arrive on the per-watch spec.
pub struct ServiceBusWatchPlugin {
    manifest: PluginManifest,
}

impl ServiceBusWatchPlugin {
    /// Infallible cdylib factory; the watch carries no plugin-level config.
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.watch.servicebus",
                name: "Azure Service Bus Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

impl SyncWatchStrategyPlugin for ServiceBusWatchPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let (spec, _) = mcpg_plugin_protocol::take_watch_resume(spec);
        let invalid = |message: String| WatchError::InvalidSpec {
            message: format!("servicebus_entity: {message}"),
        };
        let parsed: WatchSpec = serde_json::from_value(spec)
            .map_err(|e| invalid(format!("invalid watch spec: {e}")))?;
        let plan = plan(parsed).map_err(invalid)?;
        let credential = Credential::from_spec(plan.credential).map_err(invalid)?;
        let source = link::ServiceBusQueue::new(
            plan.endpoint,
            plan.entity,
            credential,
            plan.sessions,
            plan.max_body_bytes,
        )
        .map_err(|message| WatchError::Subscribe {
            message: format!("servicebus_entity: {message}"),
        })?;
        spawn_queue_watch(resource_uri, plan.options, emit_event, source)
    }

    fn acknowledge(&self, watch_handle: &WatchHandleBox, position: &Value) {
        acknowledge_queue_watch(watch_handle, position);
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_queue_watch(watch_handle);
    }
}

mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.watch.servicebus",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        watch_strategy as watch {
            inner_name: "",
            plugin_type: ServiceBusWatchPlugin,
            factory: |cfg: &str, host: ::mcpg_plugin_sdk::HostHandle|
                ServiceBusWatchPlugin::from_host_config(cfg, host),
        },
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> ServiceBusWatchPlugin {
        ServiceBusWatchPlugin::from_host_config("", stub_host())
    }

    const CONNECTION: &str = "Endpoint=sb://acme.servicebus.windows.net/;\
        SharedAccessKeyName=listen;SharedAccessKey=c2VjcmV0";

    fn planned(spec: Value) -> Result<Plan, String> {
        plan(serde_json::from_value(spec).map_err(|e| e.to_string())?)
    }

    fn refused(spec: Value) -> String {
        match plugin().watch("mcpg-event://orders", &spec, Box::new(|_| {})) {
            Err(WatchError::InvalidSpec { message }) => message,
            Err(other) => panic!("not a spec error: {other:?}"),
            Ok(handle) => {
                plugin().cancel(handle);
                panic!("accepted {spec}");
            }
        }
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        assert_eq!(SyncWatchStrategyPlugin::manifest(&p).id, PLUGIN_ID);
        assert_eq!(
            SyncWatchStrategyPlugin::manifest(&p).plugin_class,
            PluginClass::WatchStrategy
        );
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn a_queue_a_subscription_and_their_dead_letters_resolve_to_entity_paths() {
        let queue = planned(json!({ "connection_string": CONNECTION, "queue": "orders" })).unwrap();
        assert_eq!(queue.entity, "orders");
        assert_eq!(
            queue.endpoint.url(),
            "amqps://acme.servicebus.windows.net:5671"
        );
        assert_eq!(queue.options.receive_wait, Duration::from_secs(10));
        assert_eq!(queue.options.max_in_flight, 256);
        assert_eq!(queue.max_body_bytes, 128 * 1024);

        let subscription = planned(json!({
            "namespace": "acme.servicebus.windows.net",
            "credential": { "type": "managed_identity" },
            "topic": "events", "subscription": "gateway", "sub_queue": "dead_letter"
        }))
        .unwrap();
        assert_eq!(
            subscription.entity,
            "events/Subscriptions/gateway/$DeadLetterQueue"
        );

        let transfer = planned(json!({
            "connection_string": CONNECTION, "queue": "app/orders",
            "sub_queue": "transfer_dead_letter"
        }))
        .unwrap();
        assert_eq!(transfer.entity, "app/orders/$Transfer/$DeadLetterQueue");
    }

    #[test]
    fn the_entity_path_of_a_connection_string_names_the_entity() {
        let scoped = format!("{CONNECTION};EntityPath=orders");
        assert_eq!(
            planned(json!({ "connection_string": scoped }))
                .unwrap()
                .entity,
            "orders"
        );
        assert_eq!(
            planned(json!({ "connection_string": scoped, "subscription": "gw" }))
                .unwrap()
                .entity,
            "orders/Subscriptions/gw"
        );
        assert!(
            planned(json!({ "connection_string": scoped, "queue": "other" }))
                .err()
                .unwrap()
                .contains("EntityPath")
        );
    }

    #[test]
    fn sessions_are_any_or_one_named() {
        let any =
            planned(json!({ "connection_string": CONNECTION, "queue": "q", "sessions": true }))
                .unwrap();
        assert_eq!(any.sessions, Some(SessionMode::Any));
        let one =
            planned(json!({ "connection_string": CONNECTION, "queue": "q", "session_id": "s-1" }))
                .unwrap();
        assert_eq!(one.sessions, Some(SessionMode::Id("s-1".into())));
        let none = planned(json!({ "connection_string": CONNECTION, "queue": "q" })).unwrap();
        assert_eq!(none.sessions, None);
        assert!(
            planned(json!({ "connection_string": CONNECTION, "queue": "q", "session_id": "" }))
                .err()
                .unwrap()
                .contains("session_id")
        );
        assert!(
            planned(
                json!({ "connection_string": CONNECTION, "queue": "q", "sessions": true,
                "sub_queue": "dead_letter" })
            )
            .err()
            .unwrap()
            .contains("no sessions")
        );
    }

    #[test]
    fn the_emulator_is_plain_amqp() {
        let plan = planned(json!({
            "connection_string": "Endpoint=sb://localhost:33289;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=SAS_KEY_VALUE;UseDevelopmentEmulator=true;",
            "queue": "q"
        }))
        .unwrap();
        assert_eq!(plan.endpoint.url(), "amqp://localhost:33289");
    }

    #[test]
    fn a_bad_spec_is_refused_before_anything_is_called() {
        let with = |extra: Value| {
            let mut spec = json!({ "connection_string": CONNECTION, "queue": "orders" });
            for (k, v) in extra.as_object().unwrap() {
                if v.is_null() {
                    spec.as_object_mut().unwrap().remove(k);
                } else {
                    spec[k] = v.clone();
                }
            }
            spec
        };
        assert!(refused(with(json!({ "bogus": 1 }))).contains("unknown field"));
        assert!(
            refused(with(json!({ "namespace": "acme.servicebus.windows.net" })))
                .contains("not both")
        );
        assert!(refused(with(json!({ "connection_string": null }))).contains("namespace"));
        assert!(
            refused(with(json!({ "connection_string": "cred://vault/sb" }))).contains("cred://")
        );
        assert!(
            refused(with(
                json!({ "credential": { "type": "managed_identity" } })
            ))
            .contains("drop credential")
        );
        assert!(refused(with(json!({ "queue": null }))).contains("give queue"));
        assert!(refused(with(json!({ "topic": "events" }))).contains("give queue"));
        assert!(refused(with(json!({ "queue": "a b" }))).contains("entity name"));
        assert!(refused(with(json!({ "queue": "orders/" }))).contains("entity name"));
        assert!(refused(with(json!({ "subscription": "gw" }))).contains("belongs to a topic"));
        assert!(
            refused(with(json!({ "queue": null, "topic": "events" })))
                .contains("needs subscription")
        );
        assert!(
            refused(with(
                json!({ "queue": null, "topic": "events", "subscription": "a/b" })
            ))
            .contains("entity name")
        );
        assert!(refused(with(json!({ "sub_queue": "deferred" }))).contains("unknown variant"));
        assert!(refused(with(json!({ "receive_wait_secs": 0 }))).contains("receive_wait_secs"));
        assert!(refused(with(json!({ "max_in_flight": 0 }))).contains("max_in_flight"));
        assert!(refused(with(json!({ "ack_timeout_ms": 0 }))).contains("ack_timeout_ms"));
        assert!(refused(with(json!({ "max_body_bytes": 300_000 }))).contains("max_body_bytes"));
        assert!(
            refused(with(
                json!({ "connection_string": "Endpoint=sb://acme.servicebus.windows.net/" })
            ))
            .contains("SharedAccessKey")
        );

        let namespace = |credential: Value| json!({ "namespace": "acme.servicebus.windows.net", "queue": "orders", "credential": credential });
        assert!(
            refused(json!({ "namespace": "acme.servicebus.windows.net", "queue": "orders" }))
                .contains("needs credential")
        );
        assert!(
            refused(namespace(
                json!({ "type": "client_secret", "tenant_id": "t", "client_id": "c",
                "client_secret": "cred://vault/x" })
            ))
            .contains("cred://")
        );
        assert!(refused(namespace(json!({ "type": "password" }))).contains("unknown variant"));
        assert!(
            refused(namespace(
                json!({ "type": "shared_access_key", "key_name": "n", "key": "k",
                "extra": 1 })
            ))
            .contains("unknown field")
        );
        assert!(
            refused(json!({ "namespace": "acme", "queue": "orders",
                "credential": { "type": "managed_identity" } }))
            .contains("fully qualified")
        );
    }
}
