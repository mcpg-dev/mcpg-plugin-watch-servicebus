//! Send messages to a Service Bus queue on the emulator, for the plugin e2e
//! case. Plain AMQP, a CBS token signed with the emulator's shared key.
//!
//! `send <host:port> <queue> <key-name> <key> <body> [<body> ...]`
//! `send <host:port> <queue> <key-name> <key> --drain` receives what is left
//! on the queue and prints the count.

use base64::Engine as _;
use fe2o3_amqp::sasl_profile::SaslProfile;
use fe2o3_amqp::types::messaging::Message;
use fe2o3_amqp::{Connection, Receiver, Sender, Session};
use fe2o3_amqp_cbs::client::CbsClient;
use fe2o3_amqp_cbs::token::CbsToken;
use fe2o3_amqp_types::primitives::Timestamp;
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn form_encode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

fn sas(audience: &str, key_name: &str, key: &str, expiry: i64) -> String {
    let resource = form_encode(audience);
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("any key length");
    mac.update(format!("{resource}\n{expiry}").as_bytes());
    let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    format!(
        "SharedAccessSignature sr={resource}&sig={}&se={expiry}&skn={}",
        form_encode(&sig),
        form_encode(key_name)
    )
}

async fn send(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [addr, queue, key_name, key, bodies @ ..] = args else {
        return Err("usage: send <host:port> <queue> <key-name> <key> <body>...".into());
    };
    let host = addr.split(':').next().unwrap_or(addr);
    let mut connection = Connection::builder()
        .container_id("pe2e-sender")
        .hostname(host)
        .sasl_profile(SaslProfile::Anonymous)
        .open(format!("amqp://{addr}").as_str())
        .await?;
    let mut session = Session::begin(&mut connection).await?;
    let mut cbs = CbsClient::attach(&mut session).await?;
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64
        + 600;
    let audience = format!("sb://{host}/{queue}");
    let token = CbsToken::new(
        sas(&audience, key_name, key, expiry),
        "servicebus.windows.net:sastoken",
        Some(Timestamp::from_milliseconds(expiry * 1000)),
    );
    cbs.put_token(audience.as_str(), token).await?;
    if bodies == ["--drain"] {
        let mut receiver =
            Receiver::attach(&mut session, "pe2e-drain-link", queue.as_str()).await?;
        let mut left = 0;
        while let Ok(delivery) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receiver.recv::<fe2o3_amqp::types::primitives::Value>(),
        )
        .await
        {
            receiver.accept(&delivery?).await?;
            left += 1;
        }
        receiver.close().await?;
        println!("{left}");
    } else {
        let mut sender = Sender::attach(&mut session, "pe2e-sender-link", queue.as_str()).await?;
        for body in bodies {
            sender
                .send(Message::from(body.clone()))
                .await?
                .accepted_or("not accepted")?;
        }
        sender.close().await?;
    }
    cbs.close().await?;
    session.end().await?;
    connection.close().await?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    if let Err(e) = runtime.block_on(send(&args)) {
        eprintln!("send: {e}");
        std::process::exit(1);
    }
}
