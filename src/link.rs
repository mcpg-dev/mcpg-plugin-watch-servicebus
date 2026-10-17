//! The broker side of one `servicebus_entity` watch: a peek-lock receive
//! link on the entity, the entity's `$management` node, and the locks of the
//! messages the watch holds.
//!
//! A message stays locked while the gateway has it: each lock is renewed at
//! half its span until the message is completed or abandoned. A message is
//! settled on the link that received it, or through `$management` by its
//! lock token once that link is gone, so an acknowledgement that arrives
//! after a reconnect still completes it.
//!
//! On a session-enabled entity the link holds one session at a time, whose
//! lock covers its messages: the watch renews the session lock instead, and
//! lets a session go only once it is idle and nothing from it is still
//! held.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fe2o3_amqp::connection::ConnectionHandle;
use fe2o3_amqp::link::delivery::DeliveryInfo;
use fe2o3_amqp::link::{CreditMode, Receiver, ReceiverDisposer};
use fe2o3_amqp::sasl_profile::SaslProfile;
use fe2o3_amqp::session::SessionHandle;
use fe2o3_amqp::types::definitions::{Fields, ReceiverSettleMode};
use fe2o3_amqp::types::messaging::{Body, Modified, Source};
use fe2o3_amqp::types::primitives::{Symbol, Timestamp, Value};
use fe2o3_amqp::{Connection, Session};
use fe2o3_amqp_cbs::client::CbsClient;
use fe2o3_amqp_cbs::token::CbsToken;
use fe2o3_amqp_management::client::MgmtClient;
use fe2o3_amqp_management::error::Error as ManagementError;
use mcpg_plugin_sdk::queue::{Delivery, QueueSource};
use serde_json::{Value as Json, json};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::auth::{Credential, Endpoint};
use crate::management::{Disposition, RenewLock, RenewSessionLock, UpdateDisposition};
use crate::message;

/// Longest one step may take: the TCP and TLS handshake, the AMQP open, a
/// session, a link, a token, a management call.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest a close step waits for the broker.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The AMQP idle timeout the watch offers, milliseconds.
const IDLE_TIMEOUT_MS: u32 = 60_000;

/// How long a receive waits for one more message once it has the first.
const BATCH_GAP: Duration = Duration::from_millis(20);

/// A receive waits in slices of this, letting an abandon use the receiver
/// in between.
const RECEIVE_SLICE: Duration = Duration::from_millis(200);

/// How often the held locks are looked at.
const RENEW_TICK: Duration = Duration::from_millis(250);

/// Most lock tokens one renewal names.
const RENEW_BATCH: usize = 100;

/// A renewal that failed on the connection is tried again after this.
const RENEW_RETRY_MS: i64 = 1_000;

/// A token is put again this long before it expires.
const TOKEN_REFRESH_MARGIN_MS: i64 = 300_000;

/// A token refresh that failed is tried again after this.
const TOKEN_RETRY_MS: i64 = 30_000;

/// Bounds on the span of a lock as the watch measures it, so a broker
/// clock far from the local one neither stops renewals nor floods them.
const MIN_LOCK_SPAN_MS: i64 = 5_000;
const MAX_LOCK_SPAN_MS: i64 = 300_000;

/// The source filter that asks for a session: its id, or null for the next
/// one the broker has.
const SESSION_FILTER: &str = "com.microsoft:session-filter";

/// How long the broker may wait for a session to accept, milliseconds.
const LINK_TIMEOUT: &str = "com.microsoft:timeout";

/// When the session lock of an accepted session expires.
const SESSION_LOCKED_UNTIL: &str = "com.microsoft:locked-until-utc";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The lock token of a delivery tag. The broker writes the token's GUID
/// in its little-endian form as the tag; on the management node the token
/// is an AMQP uuid, in network order.
pub(crate) fn lock_token(tag: &[u8]) -> Option<[u8; 16]> {
    uuid::Uuid::from_slice_le(tag)
        .ok()
        .map(|uuid| *uuid.as_bytes())
}

/// `future`, or an error naming `what` once it fails or runs past `limit`.
async fn within<T, E: std::fmt::Display>(
    what: &str,
    limit: Duration,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    match timeout(limit, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{what}: {error}")),
        Err(_) => Err(format!("{what}: no answer in {}s", limit.as_secs())),
    }
}

/// [`within`] the step timeout.
async fn step<T, E: std::fmt::Display>(
    what: &str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    within(what, STEP_TIMEOUT, future).await
}

/// The TLS connector, with its crypto provider named: a build that links
/// both rustls providers has no process default.
fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto};
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        ClientConfig::builder_with_provider(Arc::new(crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS configuration: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// Which sessions of a session-enabled entity the watch takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionMode {
    /// Each session the broker offers, one at a time.
    Any,
    /// The one session named.
    Id(String),
}

/// The session the receive link holds.
struct ActiveSession {
    id: String,
    /// The receive link that accepted it.
    generation: u64,
    /// When to renew its lock, local Unix milliseconds.
    renew_at_ms: i64,
}

/// A message emitted and not yet settled.
struct Held {
    /// The receive link that received it.
    generation: u64,
    info: DeliveryInfo,
    lock: Option<[u8; 16]>,
    session_id: Option<String>,
    /// When to renew the lock, local Unix milliseconds.
    renew_at_ms: i64,
    /// False for a session's message, whose lock is the session's, and
    /// once the broker reports the lock lost.
    renewable: bool,
}

/// The open connection, its session and the task that keeps its tokens.
struct Connected {
    connection: ConnectionHandle<()>,
    session: SessionHandle<()>,
    refresher: Option<JoinHandle<()>>,
}

/// What the receiving thread, the settling thread and the renewal task
/// share. Locks are taken in the order receiver, management, connection.
struct Shared {
    endpoint: Endpoint,
    entity: String,
    credential: Arc<Credential>,
    sessions: Option<SessionMode>,
    /// Bumped on each receive link; a held message from an older one is
    /// settled through `$management`.
    generation: AtomicU64,
    receiver: tokio::sync::Mutex<Option<Receiver>>,
    disposer: Mutex<Option<(u64, ReceiverDisposer)>>,
    management: tokio::sync::Mutex<Option<MgmtClient>>,
    connection: tokio::sync::Mutex<Option<Connected>>,
    session: Mutex<Option<ActiveSession>>,
    held: Mutex<HashMap<Vec<u8>, Held>>,
}

enum CallError {
    /// The broker answered with an error status: a lost lock, a missing
    /// right.
    Status(String),
    /// The link or the connection failed.
    Link(String),
}

/// A lock's span from its expiry, within the bounds.
fn lock_span(until_ms: i64, now_ms: i64) -> i64 {
    until_ms
        .saturating_sub(now_ms)
        .clamp(MIN_LOCK_SPAN_MS, MAX_LOCK_SPAN_MS)
}

/// The session id the broker put in the attached link's source filter.
fn accepted_session(receiver: &Receiver) -> Option<String> {
    let filter = receiver.source().as_ref()?.filter.as_ref()?;
    match filter.get(&Symbol::from(SESSION_FILTER))? {
        Value::String(id) => Some(id.clone()),
        Value::Described(described) => match &described.value {
            Value::String(id) => Some(id.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// When the accepted session's lock expires, Unix milliseconds.
fn session_locked_until(receiver: &Receiver) -> Option<i64> {
    receiver.properties(|properties| {
        match properties
            .as_ref()?
            .get(&Symbol::from(SESSION_LOCKED_UNTIL))?
        {
            Value::Timestamp(at) => Some(at.milliseconds()),
            _ => None,
        }
    })
}

impl Shared {
    fn held(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, Held>> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn active_session(&self) -> std::sync::MutexGuard<'_, Option<ActiveSession>> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn management_address(&self) -> String {
        format!("{}/$management", self.entity)
    }

    /// Put a token for the entity and one for its management node on the
    /// CBS node; the earliest expiry, Unix milliseconds.
    async fn put_tokens(&self, cbs: &mut CbsClient) -> Result<Option<i64>, String> {
        let mut earliest: Option<i64> = None;
        for path in [self.entity.clone(), self.management_address()] {
            let audience = self.endpoint.audience(&path);
            let token = self.credential.token(&audience).await?;
            let expires_at_ms = token.expires_at_ms;
            let cbs_token = CbsToken::new(
                token.value,
                token.kind,
                expires_at_ms.map(Timestamp::from_milliseconds),
            );
            step(
                &format!("authorize {path}"),
                cbs.put_token(audience.as_str(), cbs_token),
            )
            .await?;
            earliest = match (earliest, expires_at_ms) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        Ok(earliest)
    }

    /// Attach a peek-lock receive link. On a session-enabled entity it
    /// accepts a session, waiting up to `wait` for the broker to offer one;
    /// `None` when it has none to offer.
    async fn attach_receiver(
        &self,
        session: &mut SessionHandle<()>,
        wait: Duration,
    ) -> Result<Option<(Receiver, Option<String>)>, String> {
        let mut source = Source::builder().address(self.entity.clone());
        let mut properties = None;
        if let Some(mode) = &self.sessions {
            let filter = match mode {
                SessionMode::Any => Value::Null,
                SessionMode::Id(id) => Value::String(id.clone()),
            };
            source = source.add_to_filter_using_legacy_format(SESSION_FILTER, filter);
            let mut fields = Fields::new();
            fields.insert(
                Symbol::from(LINK_TIMEOUT),
                Value::Uint(u32::try_from(wait.as_millis()).unwrap_or(u32::MAX)),
            );
            properties = Some(fields);
        }
        let mut builder = Receiver::builder()
            .name(format!("mcpg-{}-receiver", uuid::Uuid::new_v4().simple()))
            .source(source.build())
            .receiver_settle_mode(ReceiverSettleMode::Second)
            .credit_mode(CreditMode::Manual);
        if let Some(properties) = properties {
            builder = builder.properties(properties);
        }
        let what = format!("attach a receiver to {}", self.entity);
        let receiver = match timeout(wait + STEP_TIMEOUT, builder.attach(session)).await {
            Ok(Ok(receiver)) => receiver,
            // The broker answers a session it cannot offer in time with a
            // timeout.
            Ok(Err(error))
                if self.sessions == Some(SessionMode::Any)
                    && error.to_string().contains("timeout") =>
            {
                return Ok(None);
            }
            Ok(Err(error)) => return Err(format!("{what}: {error}")),
            Err(_) => return Err(format!("{what}: no answer")),
        };
        let session_id = match &self.sessions {
            None => None,
            Some(_) => Some(
                accepted_session(&receiver)
                    .ok_or_else(|| format!("{what}: the broker named no session"))?,
            ),
        };
        Ok(Some((receiver, session_id)))
    }

    /// Make `receiver` the receive link of the watch.
    async fn install(&self, receiver: Receiver, session_id: Option<String>) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        *self.disposer.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((generation, receiver.disposer()));
        *self.active_session() = session_id.map(|id| {
            let now = now_ms();
            let span = session_locked_until(&receiver)
                .map_or(MIN_LOCK_SPAN_MS, |until| lock_span(until, now));
            tracing::debug!(entity = %self.entity, session = %id, "servicebus watch: accepted a session");
            ActiveSession {
                id,
                generation,
                renew_at_ms: now + span / 2,
            }
        });
        *self.receiver.lock().await = Some(receiver);
    }

    /// Let the session go once nothing received from it is still held, so
    /// the next receive takes another.
    async fn release_idle_session(&self) {
        let generation = self.generation.load(Ordering::Acquire);
        if self
            .held()
            .values()
            .any(|held| held.generation == generation)
        {
            return;
        }
        let receiver = self.receiver.lock().await.take();
        *self.disposer.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.active_session() = None;
        if let Some(receiver) = receiver {
            let _ = timeout(CLOSE_TIMEOUT, receiver.close()).await;
        }
    }

    /// The management client of the current connection, attached on first
    /// use and again after a call left it out of step.
    async fn with_management<T>(
        &self,
        call: impl AsyncFnOnce(&mut MgmtClient) -> Result<T, ManagementError>,
    ) -> Result<T, CallError> {
        let mut management = self.management.lock().await;
        if management.is_none() {
            let mut connection = self.connection.lock().await;
            let connected = connection
                .as_mut()
                .ok_or_else(|| CallError::Link("not connected".into()))?;
            let client = step(
                "attach the management link",
                MgmtClient::builder()
                    .management_node_address(self.management_address())
                    .client_node_addr(format!("mcpg-{}-management", uuid::Uuid::new_v4().simple()))
                    .attach(&mut connected.session),
            )
            .await
            .map_err(CallError::Link)?;
            *management = Some(client);
        }
        let Some(client) = management.as_mut() else {
            return Err(CallError::Link("not connected".into()));
        };
        match timeout(STEP_TIMEOUT, call(client)).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(ManagementError::Status(status))) => Err(CallError::Status(status.to_string())),
            Ok(Err(error)) => {
                // Responses are matched by order, so a link that failed
                // mid-call is not used again.
                *management = None;
                Err(CallError::Link(error.to_string()))
            }
            Err(_) => {
                *management = None;
                Err(CallError::Link(format!(
                    "no answer in {}s",
                    STEP_TIMEOUT.as_secs()
                )))
            }
        }
    }

    /// Renew the due locks in `chunk`; one by one when a batch is refused,
    /// so one lost lock does not stop the others.
    async fn renew(&self, chunk: &[(Vec<u8>, [u8; 16])]) {
        let tokens: Vec<[u8; 16]> = chunk.iter().map(|(_, lock)| *lock).collect();
        let result = self
            .with_management(async |client| client.call(RenewLock::new(&tokens)).await)
            .await;
        let now = now_ms();
        match result {
            Ok(renewed) if renewed.expirations.len() == chunk.len() => {
                let mut held = self.held();
                for ((tag, _), until) in chunk.iter().zip(renewed.expirations) {
                    if let Some(entry) = held.get_mut(tag) {
                        entry.renew_at_ms = now + lock_span(until, now) / 2;
                    }
                }
            }
            Ok(_) | Err(CallError::Status(_)) if chunk.len() > 1 => {
                for one in chunk {
                    Box::pin(self.renew(std::slice::from_ref(one))).await;
                }
            }
            Ok(_) => {}
            Err(CallError::Status(status)) => {
                tracing::warn!(entity = %self.entity, status = %status, "servicebus watch: a lock could not be renewed; the message will be delivered again");
                if let Some(entry) = self.held().get_mut(&chunk[0].0) {
                    entry.renewable = false;
                }
            }
            Err(CallError::Link(error)) => {
                tracing::debug!(entity = %self.entity, error = %error, "servicebus watch: lock renewal failed; retrying");
                let mut held = self.held();
                for (tag, _) in chunk {
                    if let Some(entry) = held.get_mut(tag) {
                        entry.renew_at_ms = now + RENEW_RETRY_MS;
                    }
                }
            }
        }
    }

    /// Renew the lock of the session the receive link holds.
    async fn renew_session(&self, id: &str, generation: u64) {
        let result = self
            .with_management(async |client| client.call(RenewSessionLock::new(id)).await)
            .await;
        let now = now_ms();
        let next = match result {
            Ok(renewed) => {
                tracing::debug!(entity = %self.entity, session = %id, "servicebus watch: renewed the session lock");
                now + lock_span(renewed.expiration, now) / 2
            }
            Err(CallError::Status(status)) => {
                // The broker detaches the link of a lost session; the watch
                // connects again.
                tracing::warn!(entity = %self.entity, session = %id, status = %status, "servicebus watch: the session lock could not be renewed");
                i64::MAX
            }
            Err(CallError::Link(error)) => {
                tracing::debug!(entity = %self.entity, error = %error, "servicebus watch: session lock renewal failed; retrying");
                now + RENEW_RETRY_MS
            }
        };
        if let Some(active) = self.active_session().as_mut()
            && active.generation == generation
        {
            active.renew_at_ms = next;
        }
    }

    /// Close the connection and everything on it.
    async fn close(&self) {
        let receiver = self.receiver.lock().await.take();
        let management = self.management.lock().await.take();
        let connected = self.connection.lock().await.take();
        *self.disposer.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.active_session() = None;
        if let Some(receiver) = receiver {
            let _ = timeout(CLOSE_TIMEOUT, receiver.close()).await;
        }
        if let Some(management) = management {
            let _ = timeout(CLOSE_TIMEOUT, management.close()).await;
        }
        if let Some(mut connected) = connected {
            if let Some(refresher) = connected.refresher.take() {
                refresher.abort();
            }
            let _ = timeout(CLOSE_TIMEOUT, connected.session.end()).await;
            let _ = timeout(CLOSE_TIMEOUT, connected.connection.close()).await;
        }
    }
}

/// Renew each held lock, and the session lock, at half its span, until the
/// watch stops.
async fn renew_locks(shared: Weak<Shared>) {
    let mut tick = tokio::time::interval(RENEW_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let now = now_ms();
        let session = shared
            .active_session()
            .as_ref()
            .filter(|active| active.renew_at_ms <= now)
            .map(|active| (active.id.clone(), active.generation));
        if let Some((id, generation)) = session {
            shared.renew_session(&id, generation).await;
        }
        let due: Vec<(Vec<u8>, [u8; 16])> = shared
            .held()
            .iter()
            .filter(|(_, held)| held.renewable && held.renew_at_ms <= now)
            .filter_map(|(tag, held)| held.lock.map(|lock| (tag.clone(), lock)))
            .collect();
        for chunk in due.chunks(RENEW_BATCH) {
            shared.renew(chunk).await;
        }
    }
}

/// Put fresh tokens before the last ones expire, until aborted.
async fn refresh_tokens(shared: Weak<Shared>, mut cbs: CbsClient, mut expires_at_ms: i64) {
    loop {
        let wait = expires_at_ms
            .saturating_sub(TOKEN_REFRESH_MARGIN_MS)
            .saturating_sub(now_ms())
            .max(1_000);
        tokio::time::sleep(Duration::from_millis(u64::try_from(wait).unwrap_or(1_000))).await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        match shared.put_tokens(&mut cbs).await {
            Ok(Some(next)) => expires_at_ms = next,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(entity = %shared.entity, error = %error, "servicebus watch: token refresh failed; retrying");
                expires_at_ms = now_ms() + TOKEN_REFRESH_MARGIN_MS + TOKEN_RETRY_MS;
            }
        }
    }
}

/// The broker side of one `servicebus_entity` watch.
pub(crate) struct ServiceBusQueue {
    shared: Arc<Shared>,
    max_body_bytes: usize,
    renewer: JoinHandle<()>,
    rt: Option<tokio::runtime::Runtime>,
}

impl ServiceBusQueue {
    pub(crate) fn new(
        endpoint: Endpoint,
        entity: String,
        credential: Credential,
        sessions: Option<SessionMode>,
        max_body_bytes: usize,
    ) -> Result<Self, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mcpg-servicebus-watch")
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime init failed: {e}"))?;
        let shared = Arc::new(Shared {
            endpoint,
            entity,
            credential: Arc::new(credential),
            sessions,
            generation: AtomicU64::new(0),
            receiver: tokio::sync::Mutex::new(None),
            disposer: Mutex::new(None),
            management: tokio::sync::Mutex::new(None),
            connection: tokio::sync::Mutex::new(None),
            session: Mutex::new(None),
            held: Mutex::new(HashMap::new()),
        });
        let renewer = rt.spawn(renew_locks(Arc::downgrade(&shared)));
        Ok(Self {
            shared,
            max_body_bytes,
            renewer,
            rt: Some(rt),
        })
    }

    fn rt(&self) -> &tokio::runtime::Runtime {
        self.rt.as_ref().expect("the runtime lives until drop")
    }

    async fn open(&self) -> Result<(), String> {
        let shared = &self.shared;
        let id = uuid::Uuid::new_v4().simple().to_string();
        let mut connection = step(
            &format!("connect to {}", shared.endpoint.url()),
            Connection::builder()
                .container_id(format!("mcpg-{id}"))
                .hostname(shared.endpoint.host.as_str())
                .sasl_profile(SaslProfile::Anonymous)
                .alt_tls_establishment(true)
                .idle_time_out(IDLE_TIMEOUT_MS)
                .rustls_connector(tls_connector()?)
                .open(shared.endpoint.url().as_str()),
        )
        .await?;
        let opened = async {
            let mut session = step("begin a session", Session::begin(&mut connection)).await?;
            let mut cbs = step("attach the CBS node", CbsClient::attach(&mut session)).await?;
            let expires_at_ms = shared.put_tokens(&mut cbs).await?;
            // Every session the broker offers is taken by a receive, which
            // can wait for one; any other link is attached now, so a wrong
            // entity shows at once.
            let receiver = match shared.sessions {
                Some(SessionMode::Any) => None,
                _ => shared.attach_receiver(&mut session, STEP_TIMEOUT).await?,
            };
            let management = step(
                "attach the management link",
                MgmtClient::builder()
                    .management_node_address(shared.management_address())
                    .client_node_addr(format!("mcpg-{id}-management"))
                    .attach(&mut session),
            )
            .await?;
            let refresher =
                match expires_at_ms {
                    Some(at) if shared.credential.renewable() => Some(tokio::spawn(
                        refresh_tokens(Arc::downgrade(shared), cbs, at),
                    )),
                    _ => None,
                };
            Ok::<_, String>((session, receiver, management, refresher))
        }
        .await;
        let (session, receiver, management, refresher) = match opened {
            Ok(parts) => parts,
            Err(error) => {
                let _ = timeout(CLOSE_TIMEOUT, connection.close()).await;
                return Err(error);
            }
        };
        *shared.management.lock().await = Some(management);
        *shared.connection.lock().await = Some(Connected {
            connection,
            session,
            refresher,
        });
        if let Some((receiver, session_id)) = receiver {
            shared.install(receiver, session_id).await;
        }
        Ok(())
    }

    /// Accept the next session the broker offers within `wait`; false when
    /// it has none.
    async fn accept_session(&self, wait: Duration) -> Result<bool, String> {
        let attached = {
            let mut connection = self.shared.connection.lock().await;
            let connected = connection
                .as_mut()
                .ok_or_else(|| "not connected".to_owned())?;
            self.shared
                .attach_receiver(&mut connected.session, wait)
                .await?
        };
        match attached {
            Some((receiver, session_id)) => {
                self.shared.install(receiver, session_id).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Hold one delivery until it is settled, and make its event.
    fn track(
        &self,
        generation: u64,
        session_id: Option<String>,
        delivery: fe2o3_amqp::link::delivery::Delivery<Body<Value>>,
    ) -> Delivery {
        let (info, message) = delivery.into_parts();
        let tag = info.delivery_tag().to_vec();
        let lock = lock_token(&tag);
        let now = now_ms();
        let span = message::locked_until_ms(&message)
            .map_or(MIN_LOCK_SPAN_MS, |until| lock_span(until, now));
        let event = message::message_event(
            &self.shared.endpoint.host,
            &self.shared.entity,
            &message,
            self.max_body_bytes,
        );
        let receipt = json!({ "tag": hex(&tag) });
        let renewable = lock.is_some() && session_id.is_none();
        self.shared.held().insert(
            tag,
            Held {
                generation,
                info,
                lock,
                session_id,
                renew_at_ms: now + span / 2,
                renewable,
            },
        );
        Delivery { event, receipt }
    }

    /// Settle one held message: on the link that received it while that
    /// link is the current one, else through `$management`.
    async fn settle_held(
        &self,
        generation: u64,
        info: DeliveryInfo,
        lock: Option<[u8; 16]>,
        session_id: Option<String>,
        disposition: Disposition,
    ) -> Result<(), String> {
        let shared = &self.shared;
        let sent = match disposition {
            Disposition::Completed => {
                let current = shared
                    .disposer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                    .filter(|(current, _)| *current == generation)
                    .map(|(_, disposer)| disposer);
                match current {
                    Some(disposer) => Some(disposer.accept(info).await.map_err(|e| e.to_string())),
                    None => None,
                }
            }
            // An abandon counts as a delivery, so a message the gateway
            // never takes reaches the dead-letter queue; the disposer has
            // no such outcome, the receiver does. Under the receiver's lock
            // a matching generation is that receiver's.
            Disposition::Abandoned => {
                let receiver = shared.receiver.lock().await;
                match receiver.as_ref() {
                    Some(receiver) if shared.generation.load(Ordering::Acquire) == generation => {
                        let modified = Modified {
                            delivery_failed: Some(true),
                            undeliverable_here: None,
                            message_annotations: None,
                        };
                        Some(
                            receiver
                                .modify(info, modified)
                                .await
                                .map_err(|e| e.to_string()),
                        )
                    }
                    _ => None,
                }
            }
        };
        match sent {
            Some(Ok(())) => return Ok(()),
            Some(Err(error)) => {
                tracing::debug!(entity = %shared.entity, error = %error, "servicebus watch: the link could not settle; using the management node");
            }
            None => {}
        }
        let lock =
            lock.ok_or_else(|| "the message has no lock token; its lock lapses".to_owned())?;
        shared
            .with_management(async |client| {
                client
                    .call(UpdateDisposition::new(
                        disposition,
                        &[lock],
                        session_id.as_deref(),
                    ))
                    .await
            })
            .await
            .map(|_| ())
            .map_err(|error| match error {
                CallError::Status(status) | CallError::Link(status) => {
                    format!("settle through $management: {status}")
                }
            })
    }

    fn settle(&self, receipt: &Json, disposition: Disposition) -> Result<(), String> {
        let Some(tag) = receipt.get("tag").and_then(Json::as_str).and_then(unhex) else {
            return Ok(());
        };
        // The message stays held until it is settled, so its session is not
        // let go in between.
        let Some((generation, info, lock, session_id)) = self.shared.held().get(&tag).map(|held| {
            (
                held.generation,
                held.info.clone(),
                held.lock,
                held.session_id.clone(),
            )
        }) else {
            return Ok(());
        };
        let result =
            self.rt()
                .block_on(self.settle_held(generation, info, lock, session_id, disposition));
        self.shared.held().remove(&tag);
        result
    }
}

impl QueueSource for ServiceBusQueue {
    fn connect(&self) -> Result<(), String> {
        self.rt().block_on(async {
            self.shared.close().await;
            self.open().await
        })
    }

    fn receive(&self, max: usize, wait: Duration) -> Result<Vec<Delivery>, String> {
        self.rt().block_on(async {
            let deadline = tokio::time::Instant::now() + wait;
            if self.shared.receiver.lock().await.is_none() {
                if self.shared.sessions != Some(SessionMode::Any) {
                    return Err("not connected".into());
                }
                if !self.accept_session(wait).await? {
                    return Ok(Vec::new());
                }
            }
            {
                let mut guard = self.shared.receiver.lock().await;
                let receiver = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
                // Absolute credit: what arrived but is not read yet counts
                // against it, so the window never exceeds `max`.
                receiver
                    .set_credit(u32::try_from(max).unwrap_or(u32::MAX))
                    .await
                    .map_err(|e| format!("grant credit: {e}"))?;
            }
            loop {
                let slice = deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(RECEIVE_SLICE);
                if slice.is_zero() {
                    if self.shared.sessions == Some(SessionMode::Any) {
                        self.shared.release_idle_session().await;
                    }
                    return Ok(Vec::new());
                }
                let mut guard = self.shared.receiver.lock().await;
                let receiver = guard.as_mut().ok_or_else(|| "not connected".to_owned())?;
                let first = match timeout(slice, receiver.recv::<Body<Value>>()).await {
                    Err(_) => continue,
                    Ok(Err(error)) => return Err(format!("receive: {error}")),
                    Ok(Ok(delivery)) => delivery,
                };
                let mut received = vec![first];
                while received.len() < max {
                    match timeout(BATCH_GAP, receiver.recv::<Body<Value>>()).await {
                        Ok(Ok(delivery)) => received.push(delivery),
                        _ => break,
                    }
                }
                drop(guard);
                let generation = self.shared.generation.load(Ordering::Acquire);
                let session_id = self
                    .shared
                    .active_session()
                    .as_ref()
                    .map(|active| active.id.clone());
                return Ok(received
                    .into_iter()
                    .map(|delivery| self.track(generation, session_id.clone(), delivery))
                    .collect());
            }
        })
    }

    fn ack(&self, receipt: &Json) -> Result<(), String> {
        self.settle(receipt, Disposition::Completed)
    }

    fn release(&self, receipt: &Json) -> Result<(), String> {
        self.settle(receipt, Disposition::Abandoned)
    }
}

impl Drop for ServiceBusQueue {
    fn drop(&mut self) {
        self.renewer.abort();
        if let Some(rt) = self.rt.take() {
            let shared = Arc::clone(&self.shared);
            rt.block_on(async move { shared.close().await });
            rt.shutdown_timeout(CLOSE_TIMEOUT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_becomes_a_lock_token_in_network_order() {
        let tag = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(
            uuid::Uuid::from_bytes(lock_token(&tag).unwrap()).to_string(),
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        assert_eq!(lock_token(&[1, 2, 3]), None);
    }

    #[test]
    fn a_receipt_round_trips_its_tag() {
        let tag = vec![0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&tag)), Some(tag));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn the_tls_connector_needs_no_default_provider() {
        assert!(tls_connector().is_ok());
    }

    #[test]
    fn a_lock_span_stays_within_bounds() {
        assert_eq!(lock_span(61_000, 1_000), 60_000);
        assert_eq!(lock_span(0, 1_000), MIN_LOCK_SPAN_MS);
        assert_eq!(lock_span(i64::MAX, 0), MAX_LOCK_SPAN_MS);
    }
}
