//! A received Service Bus message as a `servicebus.message` event.

use base64::Engine as _;
use fe2o3_amqp::types::messaging::annotations::AnnotationKey;
use fe2o3_amqp::types::messaging::{Body, Message, MessageId};
use fe2o3_amqp::types::primitives::{SimpleValue, Value};
use mcpg_plugin_protocol::backend::{WatchEvent, body_encoding};
use serde_json::{Map, Value as Json, json};

use crate::MESSAGE_EVENT_TYPE;

const SEQUENCE_NUMBER: &str = "x-opt-sequence-number";
const ENQUEUED_TIME: &str = "x-opt-enqueued-time";
const SCHEDULED_ENQUEUE_TIME: &str = "x-opt-scheduled-enqueue-time";
const LOCKED_UNTIL: &str = "x-opt-locked-until";
const PARTITION_KEY: &str = "x-opt-partition-key";
const DEAD_LETTER_SOURCE: &str = "x-opt-deadletter-source";
const DEAD_LETTER_REASON: &str = "DeadLetterReason";
const DEAD_LETTER_DESCRIPTION: &str = "DeadLetterErrorDescription";

fn annotation<'a>(message: &'a Message<Body<Value>>, name: &str) -> Option<&'a Value> {
    message
        .message_annotations
        .as_ref()?
        .0
        .get(&name as &dyn AnnotationKey)
}

/// The broker's sequence number: unique in the entity and kept across
/// redeliveries.
pub(crate) fn sequence_number(message: &Message<Body<Value>>) -> Option<i64> {
    match annotation(message, SEQUENCE_NUMBER)? {
        Value::Long(n) => Some(*n),
        Value::Ulong(n) => i64::try_from(*n).ok(),
        Value::Int(n) => Some(i64::from(*n)),
        _ => None,
    }
}

/// When the broker lets the lock go, Unix milliseconds.
pub(crate) fn locked_until_ms(message: &Message<Body<Value>>) -> Option<i64> {
    match annotation(message, LOCKED_UNTIL)? {
        Value::Timestamp(at) => Some(at.milliseconds()),
        _ => None,
    }
}

fn timestamp_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Timestamp(at) => mcpg_plugin_protocol::occurred_at_from_millis(at.milliseconds()),
        _ => None,
    }
}

fn message_id_text(id: &MessageId) -> Json {
    match id {
        MessageId::String(text) => json!(text),
        MessageId::Ulong(n) => json!(n.to_string()),
        MessageId::Uuid(uuid) => json!(uuid::Uuid::from_bytes(*uuid.as_inner()).to_string()),
        MessageId::Binary(bytes) => {
            json!(base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()))
        }
    }
}

/// An AMQP value as JSON: numbers, text and booleans as such, a timestamp
/// as RFC 3339, a uuid as its text, binary as standard base64, a decimal
/// as its hex encoding, a map with its keys as text.
pub(crate) fn amqp_to_json(value: &Value) -> Json {
    match value {
        Value::Described(described) => amqp_to_json(&described.value),
        Value::Null => Json::Null,
        Value::Bool(b) => json!(b),
        Value::Ubyte(n) => json!(n),
        Value::Ushort(n) => json!(n),
        Value::Uint(n) => json!(n),
        Value::Ulong(n) => json!(n),
        Value::Byte(n) => json!(n),
        Value::Short(n) => json!(n),
        Value::Int(n) => json!(n),
        Value::Long(n) => json!(n),
        Value::Float(f) => json!(f.into_inner()),
        Value::Double(f) => json!(f.into_inner()),
        Value::Decimal32(d) => json!(hex(d.as_inner())),
        Value::Decimal64(d) => json!(hex(d.as_inner())),
        Value::Decimal128(d) => json!(hex(d.as_inner())),
        Value::Char(c) => json!(c.to_string()),
        Value::Timestamp(at) => mcpg_plugin_protocol::occurred_at_from_millis(at.milliseconds())
            .map_or_else(|| json!(at.milliseconds()), Json::String),
        Value::Uuid(uuid) => json!(uuid::Uuid::from_bytes(*uuid.as_inner()).to_string()),
        Value::Binary(bytes) => {
            json!(base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()))
        }
        Value::String(text) => json!(text),
        Value::Symbol(symbol) => json!(symbol.as_str()),
        Value::List(items) => Json::Array(items.iter().map(amqp_to_json).collect()),
        Value::Array(items) => Json::Array(items.iter().map(amqp_to_json).collect()),
        Value::Map(map) => Json::Object(
            map.iter()
                .map(|(key, value)| (key_text(key), amqp_to_json(value)))
                .collect(),
        ),
    }
}

fn key_text(key: &Value) -> String {
    match key {
        Value::String(text) => text.clone(),
        Value::Symbol(symbol) => symbol.as_str().to_owned(),
        other => match amqp_to_json(other) {
            Json::String(text) => text,
            json => json.to_string(),
        },
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The body as event data: data sections as their bytes read like any
/// queue body, an AMQP string or binary value likewise, and any other
/// AMQP value or sequence as its JSON.
fn body(body: &Body<Value>) -> (Json, &'static str, usize) {
    match body {
        Body::Data(sections) => {
            let bytes: Vec<u8> = sections
                .iter()
                .flat_map(|data| data.0.iter().copied())
                .collect();
            let (value, encoding) = mcpg_plugin_protocol::event_body(&bytes);
            (value, encoding, bytes.len())
        }
        Body::Value(value) => match &value.0 {
            Value::String(text) => {
                let (value, encoding) = mcpg_plugin_protocol::event_body(text.as_bytes());
                (value, encoding, text.len())
            }
            Value::Binary(bytes) => {
                let (value, encoding) = mcpg_plugin_protocol::event_body(bytes.as_slice());
                (value, encoding, bytes.len())
            }
            other => sized(amqp_to_json(other)),
        },
        Body::Sequence(sequences) => sized(Json::Array(
            sequences
                .iter()
                .map(|sequence| Json::Array(sequence.0.iter().map(amqp_to_json).collect()))
                .collect(),
        )),
        Body::Empty => (Json::String(String::new()), body_encoding::TEXT, 0),
    }
}

fn sized(value: Json) -> (Json, &'static str, usize) {
    let size = value.to_string().len();
    (value, body_encoding::JSON, size)
}

fn simple_to_json(value: &SimpleValue) -> Json {
    amqp_to_json(&Value::from(value.clone()))
}

/// The `servicebus.message` event of one message received from `entity`.
pub(crate) fn message_event(
    namespace: &str,
    entity: &str,
    message: &Message<Body<Value>>,
    max_body_bytes: usize,
) -> WatchEvent {
    let mut data = Map::new();
    data.insert("namespace".into(), json!(namespace));
    data.insert("entity".into(), json!(entity));
    let sequence = sequence_number(message);
    if let Some(sequence) = sequence {
        data.insert("sequenceNumber".into(), json!(sequence));
    }
    let properties = message.properties.as_ref();
    let message_id = properties
        .and_then(|p| p.message_id.as_ref())
        .map(message_id_text);
    if let Some(id) = &message_id {
        data.insert("messageId".into(), id.clone());
    }

    let (value, encoding, size) = body(&message.body);
    if size > max_body_bytes {
        data.insert("body".into(), Json::Null);
        data.insert("bodyEncoding".into(), Json::Null);
        data.insert("bodyTruncated".into(), json!(true));
        data.insert("bodySize".into(), json!(size));
    } else {
        data.insert("body".into(), value);
        data.insert("bodyEncoding".into(), json!(encoding));
    }

    if let Some(properties) = properties {
        let texts = [
            ("subject", properties.subject.clone()),
            (
                "contentType",
                properties
                    .content_type
                    .as_ref()
                    .map(|s| s.as_str().to_owned()),
            ),
            ("to", properties.to.clone()),
            ("replyTo", properties.reply_to.clone()),
            ("sessionId", properties.group_id.clone()),
            ("replyToSessionId", properties.reply_to_group_id.clone()),
        ];
        for (field, text) in texts {
            if let Some(text) = text {
                data.insert(field.into(), json!(text));
            }
        }
        if let Some(id) = &properties.correlation_id {
            data.insert("correlationId".into(), message_id_text(id));
        }
        if let Some(at) = properties
            .absolute_expiry_time
            .as_ref()
            .and_then(|at| mcpg_plugin_protocol::occurred_at_from_millis(at.milliseconds()))
        {
            data.insert("expiresAt".into(), json!(at));
        }
    }
    let enqueued_at = timestamp_text(annotation(message, ENQUEUED_TIME));
    if let Some(at) = &enqueued_at {
        data.insert("enqueuedAt".into(), json!(at));
    }
    if let Some(at) = timestamp_text(annotation(message, SCHEDULED_ENQUEUE_TIME)) {
        data.insert("scheduledEnqueueAt".into(), json!(at));
    }
    if let Some(Value::String(key)) = annotation(message, PARTITION_KEY) {
        data.insert("partitionKey".into(), json!(key));
    }
    if let Some(Value::String(source)) = annotation(message, DEAD_LETTER_SOURCE) {
        data.insert("deadLetterSource".into(), json!(source));
    }
    // The broker counts earlier deliveries; this one is the next.
    if let Some(header) = &message.header {
        data.insert(
            "deliveryCount".into(),
            json!(u64::from(header.delivery_count) + 1),
        );
    }

    let mut application = Map::new();
    if let Some(properties) = &message.application_properties {
        for (name, value) in properties.0.iter() {
            let value = simple_to_json(value);
            match name.as_str() {
                DEAD_LETTER_REASON => {
                    data.insert("deadLetterReason".into(), value.clone());
                }
                DEAD_LETTER_DESCRIPTION => {
                    data.insert("deadLetterErrorDescription".into(), value.clone());
                }
                _ => {}
            }
            application.insert(name.clone(), value);
        }
    }
    data.insert("applicationProperties".into(), Json::Object(application));

    let message_id = match message_id {
        Some(Json::String(id)) => Some(id),
        _ => None,
    };
    let event_id = sequence.map(|n| n.to_string()).or(message_id);
    WatchEvent {
        event_id,
        event_type: Some(MESSAGE_EVENT_TYPE.to_owned()),
        occurred_at: enqueued_at,
        data: Some(Json::Object(data)),
        ..WatchEvent::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fe2o3_amqp::types::messaging::{
        AmqpValue, ApplicationProperties, Data, Header, MessageAnnotations, Properties,
    };
    use fe2o3_amqp::types::primitives::{Binary, OrderedMap, Symbol, Timestamp};

    fn annotations(pairs: Vec<(&str, Value)>) -> MessageAnnotations {
        let mut builder = MessageAnnotations::builder();
        for (key, value) in pairs {
            builder = builder.insert(Symbol::from(key), value);
        }
        builder.build()
    }

    fn message(body: Body<Value>) -> Message<Body<Value>> {
        Message::builder()
            .header(Header {
                delivery_count: 1,
                ..Default::default()
            })
            .message_annotations(annotations(vec![
                (SEQUENCE_NUMBER, Value::Long(42)),
                (
                    ENQUEUED_TIME,
                    Value::Timestamp(Timestamp::from_milliseconds(1_700_000_000_123)),
                ),
                (
                    LOCKED_UNTIL,
                    Value::Timestamp(Timestamp::from_milliseconds(1_700_000_060_000)),
                ),
                (PARTITION_KEY, Value::String("p1".into())),
            ]))
            .properties(Properties {
                message_id: Some(MessageId::String("order-7".into())),
                subject: Some("created".into()),
                content_type: Some(Symbol::from("application/json")),
                correlation_id: Some(MessageId::Ulong(9)),
                group_id: Some("s-1".into()),
                ..Default::default()
            })
            .application_properties(
                ApplicationProperties::builder()
                    .insert("tenant", SimpleValue::String("acme".into()))
                    .insert("attempt", SimpleValue::Int(3))
                    .build(),
            )
            .body(body)
            .build()
    }

    fn data_body(bytes: &[u8]) -> Body<Value> {
        Body::Data(vec![Data(Binary::from(bytes.to_vec()))].into())
    }

    #[test]
    fn a_message_becomes_a_servicebus_message_event() {
        let message = message(data_body(br#"{"order":7}"#));
        assert_eq!(sequence_number(&message), Some(42));
        assert_eq!(locked_until_ms(&message), Some(1_700_000_060_000));
        let event = message_event("acme.servicebus.windows.net", "orders", &message, 1024);
        assert_eq!(event.event_id.as_deref(), Some("42"));
        assert_eq!(event.event_type.as_deref(), Some(MESSAGE_EVENT_TYPE));
        assert_eq!(
            event.occurred_at.as_deref(),
            Some("2023-11-14T22:13:20.123Z")
        );
        let data = event.data.unwrap();
        assert_eq!(data["entity"], json!("orders"));
        assert_eq!(data["body"], json!({ "order": 7 }));
        assert_eq!(data["bodyEncoding"], json!("json"));
        assert_eq!(data["messageId"], json!("order-7"));
        assert_eq!(data["correlationId"], json!("9"));
        assert_eq!(data["subject"], json!("created"));
        assert_eq!(data["contentType"], json!("application/json"));
        assert_eq!(data["sessionId"], json!("s-1"));
        assert_eq!(data["partitionKey"], json!("p1"));
        assert_eq!(data["deliveryCount"], json!(2));
        assert_eq!(
            data["applicationProperties"],
            json!({ "tenant": "acme", "attempt": 3 })
        );
    }

    #[test]
    fn a_large_body_is_left_out_with_its_size() {
        let event = message_event("ns", "orders", &message(data_body(b"0123456789")), 4);
        let data = event.data.unwrap();
        assert_eq!(data["body"], Json::Null);
        assert_eq!(data["bodyTruncated"], json!(true));
        assert_eq!(data["bodySize"], json!(10));
    }

    #[test]
    fn amqp_bodies_read_as_text_or_json() {
        let text = message(Body::Value(AmqpValue(Value::String("hello".into()))));
        let data = message_event("ns", "q", &text, 1024).data.unwrap();
        assert_eq!(
            (data["body"].clone(), data["bodyEncoding"].clone()),
            (json!("hello"), json!("text"))
        );

        let mut map = OrderedMap::new();
        map.insert(Value::Symbol(Symbol::from("n")), Value::Uint(1));
        let value = message(Body::Value(AmqpValue(Value::Map(map))));
        let data = message_event("ns", "q", &value, 1024).data.unwrap();
        assert_eq!(
            (data["body"].clone(), data["bodyEncoding"].clone()),
            (json!({ "n": 1 }), json!("json"))
        );

        let binary = message(data_body(&[0xff, 0x00]));
        let data = message_event("ns", "q", &binary, 1024).data.unwrap();
        assert_eq!(data["bodyEncoding"], json!("base64"));
    }

    #[test]
    fn a_dead_lettered_message_carries_its_reason() {
        let mut message = message(data_body(b"x"));
        message.application_properties = Some(
            ApplicationProperties::builder()
                .insert(
                    DEAD_LETTER_REASON,
                    SimpleValue::String("MaxDeliveryCountExceeded".into()),
                )
                .insert(
                    DEAD_LETTER_DESCRIPTION,
                    SimpleValue::String("too many".into()),
                )
                .build(),
        );
        let data = message_event("ns", "q/$DeadLetterQueue", &message, 1024)
            .data
            .unwrap();
        assert_eq!(data["deadLetterReason"], json!("MaxDeliveryCountExceeded"));
        assert_eq!(data["deadLetterErrorDescription"], json!("too many"));
    }

    #[test]
    fn amqp_values_map_to_json() {
        assert_eq!(
            amqp_to_json(&Value::Timestamp(Timestamp::from_milliseconds(0))),
            json!("1970-01-01T00:00:00.000Z")
        );
        assert_eq!(
            amqp_to_json(&Value::Binary(Binary::from(vec![1u8, 2, 3]))),
            json!("AQID")
        );
        assert_eq!(
            amqp_to_json(&Value::List(vec![Value::Bool(true), Value::Null])),
            json!([true, null])
        );
    }
}
