//! The SMTP transport against the in-process mock server, so delivery is tested
//! end to end without a real mail server.

#![cfg(feature = "test-utils")]

#[path = "support/mock_smtp.rs"]
mod mock_smtp;

use better_auth::{
    email::{verification_message, EmailMessage, EmailSender},
    smtp::{SmtpConfig, SmtpEmailSender, SmtpSecurity},
};
use mock_smtp::{MockOptions, MockSmtp};

fn sender(port: u16) -> SmtpEmailSender {
    SmtpEmailSender::new(SmtpConfig {
        host: "127.0.0.1".into(),
        port,
        security: SmtpSecurity::Plaintext,
        credentials: None,
        from: "sender@example.com".into(),
    })
    .unwrap()
}

#[tokio::test]
async fn a_verification_link_is_delivered_with_its_envelope_and_headers() {
    let server = MockSmtp::start(MockOptions::default()).await;
    let link = "https://example.com/verify?token=abc123";
    sender(server.port)
        .send(verification_message("reader@example.com", link))
        .await
        .unwrap();

    let deliveries = server.deliveries();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].mail_from, "sender@example.com");
    assert_eq!(deliveries[0].rcpt_to, "reader@example.com");
    let data = &deliveries[0].data;
    assert!(data.contains("From: sender@example.com\r\n"));
    assert!(data.contains("To: reader@example.com\r\n"));
    assert!(data.contains("Subject: "));
    assert!(data.contains(link));
}

#[tokio::test]
async fn lines_that_start_with_a_dot_arrive_unchanged() {
    let server = MockSmtp::start(MockOptions::default()).await;
    let text = "first line\n.leading dot\n..two dots\nlast line\n";
    sender(server.port)
        .send(EmailMessage {
            to: "reader@example.com".into(),
            subject: "Dots".into(),
            text: text.into(),
        })
        .await
        .unwrap();

    let data = &server.deliveries()[0].data;
    assert!(data.ends_with("\r\nfirst line\r\n.leading dot\r\n..two dots\r\nlast line\r\n"));
}

#[tokio::test]
async fn a_refused_recipient_fails_delivery_and_stores_nothing() {
    let server = MockSmtp::start(MockOptions {
        reject_recipient: Some("nobody@example.com".into()),
        ..MockOptions::default()
    })
    .await;
    let result = sender(server.port)
        .send(EmailMessage {
            to: "nobody@example.com".into(),
            subject: "Hi".into(),
            text: "body".into(),
        })
        .await;
    assert!(result.is_err());
    assert!(server.deliveries().is_empty());
}

#[tokio::test]
async fn an_unreachable_server_is_an_error_not_a_hang() {
    // Bind and drop a listener to get a port nothing is listening on.
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let result = sender(port)
        .send(EmailMessage {
            to: "reader@example.com".into(),
            subject: "Hi".into(),
            text: "body".into(),
        })
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn an_address_that_could_inject_commands_never_reaches_the_network() {
    let server = MockSmtp::start(MockOptions::default()).await;
    let result = sender(server.port)
        .send(EmailMessage {
            to: "reader@example.com\r\nRCPT TO:<evil@example.com>".into(),
            subject: "Hi".into(),
            text: "body".into(),
        })
        .await;
    assert!(result.is_err());
    assert!(server.deliveries().is_empty());
}

#[tokio::test]
async fn encrypted_modes_fail_closed_against_a_server_without_tls() {
    // The mock offers no STARTTLS, so the upgrade is refused before anything is sent.
    let server = MockSmtp::start(MockOptions::default()).await;
    let starttls = SmtpEmailSender::new(SmtpConfig {
        host: "127.0.0.1".into(),
        port: server.port,
        security: SmtpSecurity::StartTls,
        credentials: None,
        from: "sender@example.com".into(),
    })
    .unwrap();
    let message = EmailMessage {
        to: "reader@example.com".into(),
        subject: "Hi".into(),
        text: "body".into(),
    };
    assert!(starttls.send(message.clone()).await.is_err());

    // A plaintext greeting fails the TLS handshake, so nothing is delivered.
    let implicit = SmtpEmailSender::new(SmtpConfig {
        host: "127.0.0.1".into(),
        port: server.port,
        security: SmtpSecurity::ImplicitTls,
        credentials: None,
        from: "sender@example.com".into(),
    })
    .unwrap();
    assert!(implicit.send(message).await.is_err());
    assert!(server.deliveries().is_empty());
}
