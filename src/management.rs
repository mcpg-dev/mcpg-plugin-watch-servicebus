//! The operations of an entity's `$management` node the watch uses:
//! renewing the locks of the messages it holds and of the session it holds,
//! and settling a message by its lock token when the link that received it
//! is gone.

use fe2o3_amqp::types::messaging::{ApplicationProperties, Body, Message};
use fe2o3_amqp::types::primitives::{Array, OrderedMap, SimpleValue, Timestamp, Uuid, Value};
use fe2o3_amqp_management::error::Error as ManagementError;
use fe2o3_amqp_management::request::Request;
use fe2o3_amqp_management::response::Response;

const RENEW_LOCK: &str = "com.microsoft:renew-lock";
const RENEW_SESSION_LOCK: &str = "com.microsoft:renew-session-lock";
const UPDATE_DISPOSITION: &str = "com.microsoft:update-disposition";
const SERVER_TIMEOUT: &str = "com.microsoft:server-timeout";
const LOCK_TOKENS: &str = "lock-tokens";
const EXPIRATIONS: &str = "expirations";
const EXPIRATION: &str = "expiration";
const DISPOSITION_STATUS: &str = "disposition-status";
const SESSION_ID: &str = "session-id";

/// How long the broker may take over one operation, milliseconds.
const SERVER_TIMEOUT_MS: u32 = 30_000;

fn server_timeout() -> Option<ApplicationProperties> {
    Some(
        ApplicationProperties::builder()
            .insert(SERVER_TIMEOUT, SimpleValue::Uint(SERVER_TIMEOUT_MS))
            .build(),
    )
}

/// `com.microsoft:renew-lock`: extend the locks of `lock-tokens`.
pub(crate) struct RenewLock {
    body: OrderedMap<String, Array<Uuid>>,
}

impl RenewLock {
    pub(crate) fn new(tokens: &[[u8; 16]]) -> Self {
        let mut body = OrderedMap::new();
        body.insert(
            LOCK_TOKENS.to_owned(),
            Array::from(tokens.iter().copied().map(Uuid::from).collect::<Vec<_>>()),
        );
        Self { body }
    }
}

impl Request for RenewLock {
    const OPERATION: &'static str = RENEW_LOCK;
    type Response = RenewedLocks;
    type Body = OrderedMap<String, Array<Uuid>>;

    fn encode_application_properties(&mut self) -> Option<ApplicationProperties> {
        server_timeout()
    }

    fn encode_body(self) -> Self::Body {
        self.body
    }
}

/// The new expiry of each renewed lock, in request order, Unix
/// milliseconds.
pub(crate) struct RenewedLocks {
    pub expirations: Vec<i64>,
}

impl Response for RenewedLocks {
    const STATUS_CODE: u16 = 200;
    type Body = Option<OrderedMap<String, Array<Timestamp>>>;
    type Error = ManagementError;

    fn decode_message(message: Message<Self::Body>) -> Result<Self, Self::Error> {
        let expirations = message
            .body
            .and_then(|mut body| body.swap_remove(EXPIRATIONS))
            .ok_or(ManagementError::DecodeError(None))?;
        Ok(Self {
            expirations: expirations
                .into_iter()
                .map(|at| at.milliseconds())
                .collect(),
        })
    }
}

/// `com.microsoft:renew-session-lock`: extend the lock of a session.
pub(crate) struct RenewSessionLock {
    body: OrderedMap<String, String>,
}

impl RenewSessionLock {
    pub(crate) fn new(session_id: &str) -> Self {
        let mut body = OrderedMap::new();
        body.insert(SESSION_ID.to_owned(), session_id.to_owned());
        Self { body }
    }
}

impl Request for RenewSessionLock {
    const OPERATION: &'static str = RENEW_SESSION_LOCK;
    type Response = RenewedSessionLock;
    type Body = OrderedMap<String, String>;

    fn encode_application_properties(&mut self) -> Option<ApplicationProperties> {
        server_timeout()
    }

    fn encode_body(self) -> Self::Body {
        self.body
    }
}

/// The session lock's new expiry, Unix milliseconds.
pub(crate) struct RenewedSessionLock {
    pub expiration: i64,
}

impl Response for RenewedSessionLock {
    const STATUS_CODE: u16 = 200;
    type Body = Option<OrderedMap<String, Timestamp>>;
    type Error = ManagementError;

    fn decode_message(message: Message<Self::Body>) -> Result<Self, Self::Error> {
        let expiration = message
            .body
            .and_then(|mut body| body.swap_remove(EXPIRATION))
            .ok_or(ManagementError::DecodeError(None))?;
        Ok(Self {
            expiration: expiration.milliseconds(),
        })
    }
}

/// How `com.microsoft:update-disposition` settles a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Remove it from the entity.
    Completed,
    /// Let it go for redelivery.
    Abandoned,
}

/// `com.microsoft:update-disposition`: settle `lock-tokens` without the
/// link that received them. A message of a session names its session.
pub(crate) struct UpdateDisposition {
    body: OrderedMap<String, Value>,
}

impl UpdateDisposition {
    pub(crate) fn new(
        disposition: Disposition,
        tokens: &[[u8; 16]],
        session_id: Option<&str>,
    ) -> Self {
        let status = match disposition {
            Disposition::Completed => "completed",
            Disposition::Abandoned => "abandoned",
        };
        let mut body = OrderedMap::new();
        body.insert(
            DISPOSITION_STATUS.to_owned(),
            Value::String(status.to_owned()),
        );
        body.insert(
            LOCK_TOKENS.to_owned(),
            Value::from(Array::from(
                tokens.iter().copied().map(Uuid::from).collect::<Vec<_>>(),
            )),
        );
        if let Some(session_id) = session_id {
            body.insert(SESSION_ID.to_owned(), Value::String(session_id.to_owned()));
        }
        Self { body }
    }
}

impl Request for UpdateDisposition {
    const OPERATION: &'static str = UPDATE_DISPOSITION;
    type Response = Settled;
    type Body = OrderedMap<String, Value>;

    fn encode_application_properties(&mut self) -> Option<ApplicationProperties> {
        server_timeout()
    }

    fn encode_body(self) -> Self::Body {
        self.body
    }
}

/// The broker took the disposition.
pub(crate) struct Settled;

impl Response for Settled {
    const STATUS_CODE: u16 = 200;
    type Body = Body<Value>;
    type Error = ManagementError;

    fn decode_message(_message: Message<Self::Body>) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}
