//! Where a watch connects and how it proves who it is: a connection string,
//! or a namespace with a shared access key, a shared access signature or an
//! Entra ID identity. Every credential becomes a token the watch puts on the
//! connection's claims-based security node, one per entity it opens.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use azure_core::credentials::{Secret, TokenCredential};
use azure_core::http::ClientOptions;
use azure_identity::{
    ClientAssertionCredentialOptions, ClientSecretCredential, ClientSecretCredentialOptions,
    ManagedIdentityCredential, ManagedIdentityCredentialOptions, UserAssignedId,
    WorkloadIdentityCredential, WorkloadIdentityCredentialOptions,
};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

/// The scope of an Entra ID token for Service Bus, in every cloud.
const ENTRA_SCOPE: &str = "https://servicebus.azure.net/.default";

/// The token type of a shared access signature on the CBS node.
const SAS_TOKEN_TYPE: &str = "servicebus.windows.net:sastoken";

/// The token type of an Entra ID token on the CBS node.
const JWT_TOKEN_TYPE: &str = "jwt";

/// How long a signature made from a shared access key stays valid.
const SAS_LIFETIME: Duration = Duration::from_secs(3_600);

/// AMQP over TLS.
const AMQPS_PORT: u16 = 5671;

/// Plain AMQP, which only the emulator serves.
const AMQP_PORT: u16 = 5672;

/// How a watch with a `namespace` proves who it is.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CredentialSpec {
    /// A shared access policy's name and key; the watch signs its own
    /// tokens with it.
    SharedAccessKey { key_name: String, key: String },
    /// A ready signature, `SharedAccessSignature sr=…&sig=…&se=…&skn=…`.
    /// It is used until its `se` and not renewed.
    SharedAccessSignature { signature: String },
    /// An Entra ID application and its client secret.
    ClientSecret {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    /// A Kubernetes service account federated with an Entra ID identity.
    /// Each field defaults to the `AZURE_*` variable the webhook sets.
    WorkloadIdentity {
        #[serde(default)]
        tenant_id: Option<String>,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        token_file: Option<String>,
    },
    /// The host's managed identity: the system-assigned one, or a
    /// user-assigned one named by one of its ids.
    ManagedIdentity {
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        object_id: Option<String>,
        #[serde(default)]
        resource_id: Option<String>,
    },
}

impl fmt::Debug for CredentialSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::SharedAccessKey { .. } => "shared_access_key",
            Self::SharedAccessSignature { .. } => "shared_access_signature",
            Self::ClientSecret { .. } => "client_secret",
            Self::WorkloadIdentity { .. } => "workload_identity",
            Self::ManagedIdentity { .. } => "managed_identity",
        };
        f.debug_struct("CredentialSpec")
            .field("type", &kind)
            .finish_non_exhaustive()
    }
}

impl CredentialSpec {
    /// The fields that hold a secret, for the `cred://` check.
    pub(crate) fn secrets(&self) -> Vec<&str> {
        match self {
            Self::SharedAccessKey { key_name, key } => vec![key_name, key],
            Self::SharedAccessSignature { signature } => vec![signature],
            Self::ClientSecret {
                tenant_id,
                client_id,
                client_secret,
            } => vec![tenant_id, client_id, client_secret],
            Self::WorkloadIdentity { .. } | Self::ManagedIdentity { .. } => Vec::new(),
        }
    }
}

/// The parts of a Service Bus connection string.
#[derive(Default)]
pub(crate) struct ConnectionString {
    pub endpoint: String,
    pub key_name: Option<String>,
    pub key: Option<String>,
    pub signature: Option<String>,
    pub entity_path: Option<String>,
    pub emulator: bool,
}

impl ConnectionString {
    /// Read `Key=Value;` pairs. Keys are case-insensitive; a value may hold
    /// `=`, as a base64 key does.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let mut parsed = Self::default();
        let mut endpoint = None;
        for pair in text.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| "connection_string: each part must be Key=Value".to_owned())?;
            let value = value.trim().to_owned();
            match key.trim().to_ascii_lowercase().as_str() {
                "endpoint" => endpoint = Some(value),
                "sharedaccesskeyname" => parsed.key_name = Some(value),
                "sharedaccesskey" => parsed.key = Some(value),
                "sharedaccesssignature" => parsed.signature = Some(value),
                "entitypath" => parsed.entity_path = Some(value).filter(|v| !v.is_empty()),
                "usedevelopmentemulator" => parsed.emulator = value.eq_ignore_ascii_case("true"),
                other => {
                    return Err(format!(
                        "connection_string: unknown part {other:?}; expected Endpoint, \
                         SharedAccessKeyName, SharedAccessKey, SharedAccessSignature, EntityPath \
                         or UseDevelopmentEmulator"
                    ));
                }
            }
        }
        parsed.endpoint =
            endpoint.ok_or_else(|| "connection_string: Endpoint is missing".to_owned())?;
        Ok(parsed)
    }

    /// The credential the string carries: a key, or a signature.
    pub(crate) fn credential(&self) -> Result<CredentialSpec, String> {
        match (&self.key_name, &self.key, &self.signature) {
            (_, _, Some(signature)) => Ok(CredentialSpec::SharedAccessSignature {
                signature: signature.clone(),
            }),
            (Some(key_name), Some(key), None) => Ok(CredentialSpec::SharedAccessKey {
                key_name: key_name.clone(),
                key: key.clone(),
            }),
            _ => Err(
                "connection_string: needs SharedAccessKeyName and SharedAccessKey, or \
                 SharedAccessSignature"
                    .into(),
            ),
        }
    }
}

/// Where the AMQP connection goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    /// The namespace host: also the `hostname` of the AMQP open and the
    /// host of every token audience.
    pub host: String,
    pub port: u16,
    /// TLS on 5671 for Azure; plain AMQP for the emulator.
    pub tls: bool,
}

impl Endpoint {
    /// From `sb://host[:port][/]`, or a bare `host[:port]`.
    pub(crate) fn parse(text: &str, emulator: bool) -> Result<Self, String> {
        let rest = text
            .strip_prefix("sb://")
            .or_else(|| text.strip_prefix("amqps://"))
            .unwrap_or(text);
        let authority = rest.trim_end_matches('/');
        if authority.is_empty() || authority.contains('/') {
            return Err(format!(
                "{text:?} is not a namespace: expected sb://<namespace>.servicebus.windows.net"
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                Some(
                    port.parse::<u16>()
                        .map_err(|_| format!("{text:?}: the port is not a number"))?,
                ),
            ),
            None => (authority, None),
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(format!("{text:?}: not a host name"));
        }
        if !emulator && !host.contains('.') {
            return Err(format!(
                "{text:?}: give the fully qualified namespace, such as \
                 <namespace>.servicebus.windows.net"
            ));
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port: port.unwrap_or(if emulator { AMQP_PORT } else { AMQPS_PORT }),
            tls: !emulator,
        })
    }

    /// The URL fe2o3 opens.
    pub(crate) fn url(&self) -> String {
        let scheme = if self.tls { "amqps" } else { "amqp" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    /// The audience of a token for `path`, an entity or one of its nodes.
    pub(crate) fn audience(&self, path: &str) -> String {
        format!("sb://{}/{path}", self.host)
    }
}

/// A token for the CBS node.
pub(crate) struct Token {
    pub value: String,
    pub kind: &'static str,
    /// When the token stops being valid, Unix milliseconds; `None` when
    /// unknown.
    pub expires_at_ms: Option<i64>,
}

/// A credential, ready to make tokens.
pub(crate) enum Credential {
    Key {
        name: String,
        key: String,
    },
    Signature {
        token: String,
        expires_at_ms: Option<i64>,
    },
    Entra(Arc<dyn TokenCredential>),
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Key { .. } => "Credential::Key",
            Self::Signature { .. } => "Credential::Signature",
            Self::Entra(_) => "Credential::Entra",
        })
    }
}

fn azure_error(what: &str, error: azure_core::Error) -> String {
    format!("{what}: {error}")
}

impl Credential {
    /// Build the credential; nothing is fetched yet.
    pub(crate) fn from_spec(spec: CredentialSpec) -> Result<Self, String> {
        Self::from_spec_with(spec, ClientOptions::default())
    }

    /// [`Self::from_spec`], with the HTTP pipeline options of the Entra ID
    /// and managed identity requests.
    pub(crate) fn from_spec_with(
        spec: CredentialSpec,
        client_options: ClientOptions,
    ) -> Result<Self, String> {
        Ok(match spec {
            CredentialSpec::SharedAccessKey { key_name, key } => {
                if key_name.is_empty() || key.is_empty() {
                    return Err("shared_access_key needs key_name and key".into());
                }
                Self::Key {
                    name: key_name,
                    key,
                }
            }
            CredentialSpec::SharedAccessSignature { signature } => {
                let expires_at_ms = signature_expiry(&signature)?;
                Self::Signature {
                    token: signature,
                    expires_at_ms,
                }
            }
            CredentialSpec::ClientSecret {
                tenant_id,
                client_id,
                client_secret,
            } => Self::Entra(
                ClientSecretCredential::new(
                    &tenant_id,
                    client_id,
                    Secret::new(client_secret),
                    Some(ClientSecretCredentialOptions { client_options }),
                )
                .map_err(|e| azure_error("client_secret", e))?,
            ),
            CredentialSpec::WorkloadIdentity {
                tenant_id,
                client_id,
                token_file,
            } => Self::Entra(
                WorkloadIdentityCredential::new(Some(WorkloadIdentityCredentialOptions {
                    credential_options: ClientAssertionCredentialOptions { client_options },
                    tenant_id,
                    client_id,
                    token_file_path: token_file.map(PathBuf::from),
                }))
                .map_err(|e| azure_error("workload_identity", e))?,
            ),
            CredentialSpec::ManagedIdentity {
                client_id,
                object_id,
                resource_id,
            } => {
                let user_assigned_id = match (client_id, object_id, resource_id) {
                    (None, None, None) => None,
                    (Some(id), None, None) => Some(UserAssignedId::ClientId(id)),
                    (None, Some(id), None) => Some(UserAssignedId::ObjectId(id)),
                    (None, None, Some(id)) => Some(UserAssignedId::ResourceId(id)),
                    _ => {
                        return Err("managed_identity takes at most one of client_id, \
                                    object_id and resource_id"
                            .into());
                    }
                };
                Self::Entra(
                    ManagedIdentityCredential::new(Some(ManagedIdentityCredentialOptions {
                        user_assigned_id,
                        client_options,
                    }))
                    .map_err(|e| azure_error("managed_identity", e))?,
                )
            }
        })
    }

    /// A token for `audience`.
    pub(crate) async fn token(&self, audience: &str) -> Result<Token, String> {
        match self {
            Self::Key { name, key } => {
                let expiry = unix_seconds(SystemTime::now() + SAS_LIFETIME);
                Ok(Token {
                    value: shared_access_signature(audience, name, key, expiry),
                    kind: SAS_TOKEN_TYPE,
                    expires_at_ms: Some(expiry.saturating_mul(1_000)),
                })
            }
            Self::Signature {
                token,
                expires_at_ms,
            } => Ok(Token {
                value: token.clone(),
                kind: SAS_TOKEN_TYPE,
                expires_at_ms: *expires_at_ms,
            }),
            Self::Entra(credential) => {
                let token = credential
                    .get_token(&[ENTRA_SCOPE], None)
                    .await
                    .map_err(|e| azure_error("Entra ID token", e))?;
                Ok(Token {
                    value: token.token.secret().to_owned(),
                    kind: JWT_TOKEN_TYPE,
                    expires_at_ms: Some(token.expires_on.unix_timestamp().saturating_mul(1_000)),
                })
            }
        }
    }

    /// Whether a token can be made again before the last one expires.
    pub(crate) fn renewable(&self) -> bool {
        !matches!(self, Self::Signature { .. })
    }
}

fn unix_seconds(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn form_encode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

/// A shared access signature for `audience`, valid until `expiry` (Unix
/// seconds): HMAC-SHA256 with the key over the encoded audience and the
/// expiry.
pub(crate) fn shared_access_signature(
    audience: &str,
    key_name: &str,
    key: &str,
    expiry: i64,
) -> String {
    let resource = form_encode(audience);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC takes a key of any length");
    mac.update(format!("{resource}\n{expiry}").as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    format!(
        "SharedAccessSignature sr={resource}&sig={}&se={expiry}&skn={}",
        form_encode(&signature),
        form_encode(key_name)
    )
}

/// The `se` of a signature, in Unix milliseconds.
fn signature_expiry(signature: &str) -> Result<Option<i64>, String> {
    let fields = signature
        .strip_prefix("SharedAccessSignature ")
        .ok_or_else(|| {
            "shared_access_signature must start with \"SharedAccessSignature \"".to_owned()
        })?;
    Ok(fields
        .split('&')
        .find_map(|field| field.strip_prefix("se="))
        .and_then(|se| se.parse::<i64>().ok())
        .map(|se| se.saturating_mul(1_000)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use azure_core::cloud::{CloudConfiguration, CustomConfiguration};
    use azure_core::http::{Method, StatusCode};
    use serde_json::json;

    use super::*;
    use crate::recording_http::{Recorded, Recorder};

    const TENANT: &str = "7b795fb9-09d3-42f4-a494-38864f99ba3c";
    const CLIENT: &str = "0d6f1f8a-6c3e-4a0e-9a59-3b1f7c2b1e11";
    const CLIENT_SECRET: &str = "test-client-secret-value";
    const AUDIENCE: &str = "sb://acme.servicebus.windows.net/orders";
    const TOKEN_ENDPOINT: &str =
        "https://login.microsoftonline.com/7b795fb9-09d3-42f4-a494-38864f99ba3c/oauth2/v2.0/token";

    fn now_ms() -> i64 {
        unix_seconds(SystemTime::now()).saturating_mul(1_000)
    }

    /// Entra ID's answer to a token request.
    fn entra_token(expires_in: i64) -> (StatusCode, serde_json::Value) {
        (
            StatusCode::Ok,
            json!({
                "token_type": "Bearer",
                "expires_in": expires_in,
                "ext_expires_in": expires_in,
                "access_token": "entra-access-token",
            }),
        )
    }

    /// The recorder's client options in the public cloud. With no cloud set,
    /// azure_identity reads the authority host from AZURE_AUTHORITY_HOST.
    fn public_cloud(recorder: &Arc<Recorder>) -> ClientOptions {
        ClientOptions {
            cloud: Some(Arc::new(CloudConfiguration::AzurePublic)),
            ..recorder.client_options()
        }
    }

    fn the_only_request(recorder: &Recorder) -> Recorded {
        let mut requests = recorder.requests();
        assert_eq!(requests.len(), 1, "one token request: {requests:?}");
        requests.remove(0)
    }

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn client_secret() -> CredentialSpec {
        CredentialSpec::ClientSecret {
            tenant_id: TENANT.into(),
            client_id: CLIENT.into(),
            client_secret: CLIENT_SECRET.into(),
        }
    }

    fn workload_identity(token_file: &std::path::Path) -> CredentialSpec {
        CredentialSpec::WorkloadIdentity {
            tenant_id: Some(TENANT.into()),
            client_id: Some(CLIENT.into()),
            token_file: Some(token_file.to_str().unwrap().to_owned()),
        }
    }

    #[tokio::test]
    async fn a_client_secret_asks_entra_id_for_a_service_bus_token() {
        let recorder = Recorder::answering([entra_token(3_599)]);
        let credential =
            Credential::from_spec_with(client_secret(), public_cloud(&recorder)).unwrap();
        let asked_at = now_ms();
        let token = credential.token(AUDIENCE).await.unwrap();

        let request = the_only_request(&recorder);
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.endpoint(), TOKEN_ENDPOINT);
        assert!(request.query().is_empty());
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            request.form,
            fields(&[
                ("client_id", CLIENT),
                ("client_secret", CLIENT_SECRET),
                ("grant_type", "client_credentials"),
                ("scope", "https://servicebus.azure.net/.default"),
            ])
        );
        assert_eq!(token.value, "entra-access-token");
        assert_eq!(token.kind, "jwt");
        let expected = asked_at + 3_599_000;
        let expires_at_ms = token.expires_at_ms.unwrap();
        assert!(
            (expected - 2_000..=expected + 5_000).contains(&expires_at_ms),
            "expires at {expires_at_ms}, expected about {expected}"
        );
    }

    #[tokio::test]
    async fn a_workload_identity_sends_its_token_file_as_the_assertion() {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "federated-service-account-token").unwrap();
        let recorder = Recorder::answering([entra_token(3_600)]);
        let credential =
            Credential::from_spec_with(workload_identity(&token_file), public_cloud(&recorder))
                .unwrap();
        let token = credential.token(AUDIENCE).await.unwrap();

        let request = the_only_request(&recorder);
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.endpoint(), TOKEN_ENDPOINT);
        assert_eq!(
            request.form,
            fields(&[
                ("client_assertion", "federated-service-account-token"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                ),
                ("client_id", CLIENT),
                ("grant_type", "client_credentials"),
                ("scope", "https://servicebus.azure.net/.default"),
            ])
        );
        assert_eq!(token.kind, "jwt");
        assert_eq!(token.value, "entra-access-token");
    }

    #[test]
    fn a_workload_identity_without_its_token_file_does_not_start() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = Recorder::answering([]);
        let refused = Credential::from_spec_with(
            workload_identity(&dir.path().join("absent")),
            public_cloud(&recorder),
        );
        let error = refused.unwrap_err();
        assert!(
            error.starts_with("workload_identity: failed to read federated token from file"),
            "{error}"
        );
        assert!(recorder.requests().is_empty());
    }

    #[tokio::test]
    async fn an_entra_id_refusal_does_not_show_the_client_secret() {
        let recorder = Recorder::answering([(
            StatusCode::BadRequest,
            json!({
                "error": "invalid_client",
                "error_description": "AADSTS7000215: Invalid client secret provided. Ensure the \
                    secret being sent in the request is the client secret value, not the client \
                    secret ID.",
                "error_codes": [7_000_215],
                "timestamp": "2026-10-11 09:00:00Z",
                "trace_id": "5e4b2f3a-0000-0000-0000-000000000000",
                "correlation_id": "6f5c3a4b-0000-0000-0000-000000000000",
            }),
        )]);
        let credential =
            Credential::from_spec_with(client_secret(), public_cloud(&recorder)).unwrap();
        let Err(error) = credential.token(AUDIENCE).await else {
            panic!("a refused request made a token");
        };

        assert_eq!(recorder.requests().len(), 1, "a 400 is not retried");
        assert!(error.starts_with("Entra ID token: "), "{error}");
        assert!(error.contains("AADSTS7000215"), "{error}");
        assert!(!error.contains(CLIENT_SECRET), "the error shows the secret");
    }

    #[test]
    fn entra_id_is_reached_over_https_only() {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "federated-service-account-token").unwrap();
        let mut custom = CustomConfiguration::default();
        custom.authority_host = "http://127.0.0.1:8080".into();
        let recorder = Recorder::answering([]);
        let options = ClientOptions {
            cloud: Some(Arc::new(CloudConfiguration::Custom(custom))),
            ..recorder.client_options()
        };
        for spec in [client_secret(), workload_identity(&token_file)] {
            let error = Credential::from_spec_with(spec, options.clone()).unwrap_err();
            assert!(
                error.contains("authority host doesn't use HTTPS scheme"),
                "{error}"
            );
        }
        assert!(recorder.requests().is_empty());
    }

    #[test]
    fn a_connection_string_is_read_part_by_part() {
        let parsed = ConnectionString::parse(
            "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=listen;\
             SharedAccessKey=abc+/de==;EntityPath=orders",
        )
        .unwrap();
        assert_eq!(parsed.endpoint, "sb://acme.servicebus.windows.net/");
        assert_eq!(parsed.key.as_deref(), Some("abc+/de=="));
        assert_eq!(parsed.entity_path.as_deref(), Some("orders"));
        assert!(!parsed.emulator);
        assert!(matches!(
            parsed.credential().unwrap(),
            CredentialSpec::SharedAccessKey { .. }
        ));

        let emulator = ConnectionString::parse(
            "Endpoint=sb://localhost;SharedAccessKeyName=RootManageSharedAccessKey;\
             SharedAccessKey=SAS_KEY_VALUE;UseDevelopmentEmulator=true;",
        )
        .unwrap();
        assert!(emulator.emulator);

        assert!(ConnectionString::parse("SharedAccessKey=x").is_err());
        assert!(ConnectionString::parse("Endpoint=sb://a.b;Bogus=1").is_err());
        assert!(
            ConnectionString::parse("Endpoint=sb://a.b;SharedAccessKeyName=n")
                .unwrap()
                .credential()
                .is_err()
        );
    }

    #[test]
    fn an_endpoint_names_the_host_the_port_and_tls() {
        assert_eq!(
            Endpoint::parse("sb://Acme.servicebus.windows.net/", false).unwrap(),
            Endpoint {
                host: "acme.servicebus.windows.net".into(),
                port: 5671,
                tls: true
            }
        );
        let emulator = Endpoint::parse("sb://localhost:33289", true).unwrap();
        assert_eq!(emulator.url(), "amqp://localhost:33289");
        assert_eq!(Endpoint::parse("sb://localhost", true).unwrap().port, 5672);
        assert!(Endpoint::parse("acme", false).is_err());
        assert!(Endpoint::parse("sb://acme.servicebus.windows.net/orders", false).is_err());
        assert!(Endpoint::parse("sb://a.b:x", false).is_err());
        assert_eq!(
            Endpoint::parse("acme.servicebus.windows.net", false)
                .unwrap()
                .audience("orders/$management"),
            "sb://acme.servicebus.windows.net/orders/$management"
        );
    }

    #[test]
    fn a_signature_signs_the_encoded_audience_and_the_expiry() {
        let token = shared_access_signature(
            "sb://acme.servicebus.windows.net/orders",
            "listen",
            "c2VjcmV0",
            1_700_000_000,
        );
        assert!(token.starts_with(
            "SharedAccessSignature sr=sb%3A%2F%2Facme.servicebus.windows.net%2Forders&sig="
        ));
        assert!(token.ends_with("&se=1700000000&skn=listen"));
        let mut mac = Hmac::<Sha256>::new_from_slice(b"c2VjcmV0").unwrap();
        mac.update(b"sb%3A%2F%2Facme.servicebus.windows.net%2Forders\n1700000000");
        let expected =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert!(token.contains(&format!("sig={}&", form_encode(&expected))));
    }

    #[test]
    fn a_ready_signature_keeps_its_expiry() {
        assert_eq!(
            signature_expiry("SharedAccessSignature sr=x&sig=y&se=1700000000&skn=z").unwrap(),
            Some(1_700_000_000_000)
        );
        assert!(signature_expiry("sr=x&sig=y").is_err());
        let credential = Credential::from_spec(CredentialSpec::SharedAccessSignature {
            signature: "SharedAccessSignature sr=x&sig=y&se=1&skn=z".into(),
        })
        .unwrap();
        assert!(!credential.renewable());
    }

    #[test]
    fn a_managed_identity_takes_one_id_at_most() {
        let refused = Credential::from_spec(CredentialSpec::ManagedIdentity {
            client_id: Some("a".into()),
            object_id: Some("b".into()),
            resource_id: None,
        });
        assert!(refused.unwrap_err().contains("at most one"));
    }

    #[test]
    fn the_debug_form_shows_no_secret() {
        let spec = CredentialSpec::SharedAccessKey {
            key_name: "listen".into(),
            key: "TOPSECRET".into(),
        };
        assert!(!format!("{spec:?}").contains("TOPSECRET"));
    }
}
