//! SMTP delivery for [`EmailSender`].
//!
//! The client speaks the protocol directly, so the crate needs no mail library.
//! Credentials are sent only over TLS, which is verified against the Mozilla
//! root set. Plaintext exists only for tests against a local server, and it is
//! compiled only with the `test-utils` feature.

use crate::email::{EmailMessage, EmailSender};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use better_auth_core::error::{AuthError, Result};
use std::{fmt, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};

/// Whole-delivery budget, from connect to the server's answer to the message.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest single reply line accepted. Servers send short lines, so a longer
/// one means the peer is not behaving like an SMTP server.
const MAX_LINE_BYTES: usize = 2048;
/// Most lines accepted in one multi-line reply.
const MAX_REPLY_LINES: usize = 100;

#[derive(Clone, PartialEq, Eq)]
pub struct SmtpCredentials {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for SmtpCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmtpCredentials")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// TLS from the first byte (SMTPS, usually port 465).
    ImplicitTls,
    /// A plaintext greeting upgraded with `STARTTLS` (usually port 587). Delivery
    /// stops if the server does not offer the upgrade.
    StartTls,
    /// No encryption, for a local test server only. Refused for other hosts.
    #[cfg(any(test, feature = "test-utils"))]
    Plaintext,
}

#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub credentials: Option<SmtpCredentials>,
    /// Envelope sender and `From:` address.
    pub from: String,
}

/// Delivers messages through an SMTP server, one connection per message.
pub struct SmtpEmailSender {
    config: SmtpConfig,
}

impl SmtpEmailSender {
    pub fn new(config: SmtpConfig) -> Result<Self> {
        validate_address(&config.from).map_err(|_| {
            AuthError::InvalidConfiguration("the SMTP sender address is not valid".into())
        })?;
        if config.host.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "the SMTP host is empty".into(),
            ));
        }
        #[cfg(any(test, feature = "test-utils"))]
        if config.security == SmtpSecurity::Plaintext {
            if config.credentials.is_some() {
                return Err(AuthError::InvalidConfiguration(
                    "credentials are never sent without TLS".into(),
                ));
            }
            if !is_loopback(&config.host) {
                return Err(AuthError::InvalidConfiguration(
                    "plaintext SMTP is only allowed to a loopback host".into(),
                ));
            }
        }
        Ok(Self { config })
    }
}

#[async_trait]
impl EmailSender for SmtpEmailSender {
    async fn send(&self, message: EmailMessage) -> Result<()> {
        validate_address(&message.to)?;
        validate_header_text("subject", &message.subject)?;
        let data = render(&self.config.from, &message)?;
        timeout(DELIVERY_TIMEOUT, deliver(&self.config, &message.to, &data))
            .await
            .map_err(|_| delivery_error("the server did not answer in time"))?
    }
}

async fn deliver(config: &SmtpConfig, to: &str, data: &[u8]) -> Result<()> {
    let tcp = TcpStream::connect((config.host.as_str(), config.port))
        .await
        .map_err(|error| delivery_error(&format!("connect failed ({:?})", error.kind())))?;
    match config.security {
        SmtpSecurity::ImplicitTls => {
            let tls = connect_tls(&config.host, tcp).await?;
            let mut conversation = Conversation::new(tls);
            conversation.expect(220).await?;
            let capabilities = conversation.ehlo().await?;
            transact(&mut conversation, &capabilities, config, to, data).await
        }
        SmtpSecurity::StartTls => {
            let mut conversation = Conversation::new(tcp);
            conversation.expect(220).await?;
            let capabilities = conversation.ehlo().await?;
            if !capabilities.has("STARTTLS") {
                return Err(delivery_error("the server does not offer STARTTLS"));
            }
            conversation.command("STARTTLS", 220).await?;
            let tls = connect_tls(&config.host, conversation.into_inner()).await?;
            let mut conversation = Conversation::new(tls);
            let capabilities = conversation.ehlo().await?;
            transact(&mut conversation, &capabilities, config, to, data).await
        }
        #[cfg(any(test, feature = "test-utils"))]
        SmtpSecurity::Plaintext => {
            let mut conversation = Conversation::new(tcp);
            conversation.expect(220).await?;
            let capabilities = conversation.ehlo().await?;
            transact(&mut conversation, &capabilities, config, to, data).await
        }
    }
}

/// The envelope and data phases, after the connection is set up and, where
/// needed, encrypted.
async fn transact<S: AsyncRead + AsyncWrite + Unpin>(
    conversation: &mut Conversation<S>,
    capabilities: &Capabilities,
    config: &SmtpConfig,
    to: &str,
    data: &[u8],
) -> Result<()> {
    if let Some(credentials) = &config.credentials {
        if !capabilities.auth_mechanisms.iter().any(|m| m == "PLAIN") {
            return Err(delivery_error("the server does not offer AUTH PLAIN"));
        }
        let token = STANDARD.encode(format!(
            "\0{}\0{}",
            credentials.username, credentials.password
        ));
        conversation
            .command(&format!("AUTH PLAIN {token}"), 235)
            .await?;
    }
    if !data.is_ascii() && !capabilities.has("8BITMIME") {
        return Err(delivery_error(
            "the message is not ASCII and the server does not accept 8-bit data",
        ));
    }
    conversation
        .command(&format!("MAIL FROM:<{}>", config.from), 250)
        .await?;
    conversation
        .command_one_of(&format!("RCPT TO:<{to}>"), &[250, 251])
        .await?;
    conversation.command("DATA", 354).await?;
    conversation.send_raw(data).await?;
    conversation.send_raw(b".\r\n").await?;
    conversation.expect(250).await?;
    // The message is accepted, so a failed QUIT changes nothing for the caller.
    let _ = conversation.command("QUIT", 221).await;
    Ok(())
}

struct Conversation<S> {
    io: BufReader<S>,
}

#[derive(Debug)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conversation<S> {
    fn new(stream: S) -> Self {
        Self {
            io: BufReader::new(stream),
        }
    }

    fn into_inner(self) -> S {
        self.io.into_inner()
    }

    async fn expect(&mut self, code: u16) -> Result<Reply> {
        self.expect_one_of(&[code]).await
    }

    async fn expect_one_of(&mut self, codes: &[u16]) -> Result<Reply> {
        let reply = self.reply().await?;
        if codes.contains(&reply.code) {
            Ok(reply)
        } else {
            Err(delivery_error(&format!("unexpected reply {}", reply.code)))
        }
    }

    async fn command(&mut self, line: &str, code: u16) -> Result<Reply> {
        self.command_one_of(line, &[code]).await
    }

    /// Sends one command line. The line itself is never put in an error, since it
    /// may carry credentials or addresses.
    async fn command_one_of(&mut self, line: &str, codes: &[u16]) -> Result<Reply> {
        self.send_raw(line.as_bytes()).await?;
        self.send_raw(b"\r\n").await?;
        self.expect_one_of(codes).await
    }

    async fn ehlo(&mut self) -> Result<Capabilities> {
        let reply = self.command("EHLO localhost", 250).await?;
        Ok(Capabilities::from_reply(&reply))
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        let stream = self.io.get_mut();
        stream
            .write_all(bytes)
            .await
            .map_err(|error| delivery_error(&format!("write failed ({:?})", error.kind())))?;
        stream
            .flush()
            .await
            .map_err(|error| delivery_error(&format!("write failed ({:?})", error.kind())))
    }

    async fn reply(&mut self) -> Result<Reply> {
        let mut code = None;
        let mut lines = Vec::new();
        loop {
            let line = read_line(&mut self.io).await?;
            let digits = line
                .get(..3)
                .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
                .ok_or_else(|| delivery_error("malformed reply"))?;
            let parsed: u16 = digits
                .parse()
                .map_err(|_| delivery_error("malformed reply"))?;
            if code.is_some_and(|previous| previous != parsed) {
                return Err(delivery_error("reply code changed mid-reply"));
            }
            code = Some(parsed);
            let more = line.as_bytes().get(3) == Some(&b'-');
            lines.push(line.get(4..).unwrap_or("").to_owned());
            if !more {
                break;
            }
            if lines.len() >= MAX_REPLY_LINES {
                return Err(delivery_error("reply has too many lines"));
            }
        }
        Ok(Reply {
            code: code.expect("the loop sets the code before breaking"),
            lines,
        })
    }
}

/// Reads one line without letting a peer that never sends a newline grow memory
/// without bound.
async fn read_line<S: AsyncRead + Unpin>(io: &mut BufReader<S>) -> Result<String> {
    let mut line = Vec::new();
    loop {
        let available = io
            .fill_buf()
            .await
            .map_err(|error| delivery_error(&format!("read failed ({:?})", error.kind())))?;
        if available.is_empty() {
            return Err(delivery_error("the connection closed"));
        }
        let (used, complete) = match available.iter().position(|&byte| byte == b'\n') {
            Some(index) => (index + 1, true),
            None => (available.len(), false),
        };
        line.extend_from_slice(&available[..used]);
        io.consume(used);
        if line.len() > MAX_LINE_BYTES {
            return Err(delivery_error("reply line is too long"));
        }
        if complete {
            break;
        }
    }
    let text = String::from_utf8(line).map_err(|_| delivery_error("reply is not UTF-8"))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

#[derive(Debug, Default)]
struct Capabilities {
    keywords: Vec<String>,
    auth_mechanisms: Vec<String>,
}

impl Capabilities {
    /// Reads the EHLO reply. The first line is the server's greeting, not a
    /// capability.
    fn from_reply(reply: &Reply) -> Self {
        let mut capabilities = Self::default();
        for line in reply.lines.iter().skip(1) {
            let mut words = line.split_ascii_whitespace();
            let Some(keyword) = words.next() else {
                continue;
            };
            let keyword = keyword.to_ascii_uppercase();
            if keyword == "AUTH" {
                capabilities.auth_mechanisms = words.map(str::to_ascii_uppercase).collect();
            }
            capabilities.keywords.push(keyword);
        }
        capabilities
    }

    fn has(&self, keyword: &str) -> bool {
        self.keywords.iter().any(|known| known == keyword)
    }
}

async fn connect_tls(
    host: &str,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| AuthError::InvalidConfiguration("the SMTP host is not a valid name".into()))?;
    tls_connector()?
        .connect(server_name, tcp)
        .await
        .map_err(|error| delivery_error(&format!("TLS handshake failed ({:?})", error.kind())))
}

fn tls_connector() -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| AuthError::InvalidConfiguration(format!("TLS setup: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Builds the RFC 5322 message. Lines that begin with a dot are doubled, and
/// every line ends with CRLF, so the data phase cannot end early.
fn render(from: &str, message: &EmailMessage) -> Result<Vec<u8>> {
    validate_address(from)?;
    validate_header_text("subject", &message.subject)?;
    let mut out = String::new();
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: {}\r\n", message.to));
    out.push_str(&format!("Subject: {}\r\n", message.subject));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    // One trailing newline ends the last line; it does not start an empty one.
    let body = message.text.strip_suffix('\n').unwrap_or(&message.text);
    for line in body.split('\n') {
        let line = line.replace('\r', "");
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(&line);
        out.push_str("\r\n");
    }
    Ok(out.into_bytes())
}

/// Refuses anything that could end a header or start a second SMTP command.
fn validate_address(address: &str) -> Result<()> {
    let valid = address.is_ascii()
        && !address.is_empty()
        && address.len() <= 254
        && address
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'<' && byte != b'>' && byte != b',')
        && address.matches('@').count() == 1
        && address
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty());
    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidRequest(
            "email address is not valid".into(),
        ))
    }
}

fn validate_header_text(name: &str, value: &str) -> Result<()> {
    if value.is_ascii() && !value.contains(['\r', '\n']) {
        Ok(())
    } else {
        Err(AuthError::InvalidRequest(format!(
            "email {name} must be one line of ASCII text"
        )))
    }
}

#[cfg(any(test, feature = "test-utils"))]
fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// A delivery failure, described without addresses or credentials.
fn delivery_error(reason: &str) -> AuthError {
    AuthError::Plugin(format!("email delivery: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn message(subject: &str, text: &str) -> EmailMessage {
        EmailMessage {
            to: "reader@example.com".into(),
            subject: subject.into(),
            text: text.into(),
        }
    }

    #[test]
    fn rendered_messages_dot_stuff_and_use_crlf() {
        let data = render(
            "sender@example.com",
            &message("Hello", "first\n.dot line\r\nlast"),
        )
        .unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("Subject: Hello\r\n"));
        assert!(text.contains("\r\n\r\nfirst\r\n..dot line\r\nlast\r\n"));
        assert!(
            !text.replace("\r\n", "").contains('\n'),
            "every newline is CRLF"
        );
    }

    #[test]
    fn header_injection_is_refused() {
        assert!(render("sender@example.com", &message("Hi\r\nBcc: x@y.z", "body")).is_err());
        assert!(render("sender@example.com", &message("Héllo", "body")).is_err());
        assert!(validate_address("a@b.c\r\nRCPT TO:<evil@example.com>").is_err());
        assert!(validate_address("a@b.c>, <evil@example.com").is_err());
        assert!(validate_address("no-at-sign").is_err());
        assert!(validate_address("reader@example.com").is_ok());
    }

    #[test]
    fn plaintext_is_only_for_loopback_and_never_with_credentials() {
        let base = SmtpConfig {
            host: "mail.example.com".into(),
            port: 25,
            security: SmtpSecurity::Plaintext,
            credentials: None,
            from: "sender@example.com".into(),
        };
        assert!(SmtpEmailSender::new(base.clone()).is_err());
        let local = SmtpConfig {
            host: "127.0.0.1".into(),
            ..base.clone()
        };
        assert!(SmtpEmailSender::new(local.clone()).is_ok());
        let with_credentials = SmtpConfig {
            credentials: Some(SmtpCredentials {
                username: "user".into(),
                password: "secret".into(),
            }),
            ..local
        };
        assert!(SmtpEmailSender::new(with_credentials).is_err());
    }

    #[test]
    fn credentials_are_redacted_in_debug_output() {
        let credentials = SmtpCredentials {
            username: "user".into(),
            password: "hunter2".into(),
        };
        assert!(!format!("{credentials:?}").contains("hunter2"));
    }

    /// A scripted server over an in-memory pipe. It checks each command the
    /// client sends and answers with the next scripted reply.
    async fn scripted(
        script: Vec<(&'static str, &'static str)>,
    ) -> (
        Conversation<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<Vec<String>>,
    ) {
        let (client, server) = duplex(64 * 1024);
        let handle = tokio::spawn(async move {
            let mut server = BufReader::new(server);
            let mut seen = Vec::new();
            server
                .get_mut()
                .write_all(b"220 scripted\r\n")
                .await
                .unwrap();
            for (expected_prefix, reply) in script {
                if expected_prefix == "." {
                    // The message body runs until a line holding only a dot.
                    loop {
                        let line = read_line(&mut server).await.unwrap();
                        if line == "." {
                            break;
                        }
                    }
                    seen.push(".".into());
                    server.get_mut().write_all(reply.as_bytes()).await.unwrap();
                    continue;
                }
                let line = read_line(&mut server).await.unwrap();
                assert!(
                    line.starts_with(expected_prefix),
                    "expected {expected_prefix:?}, got {:?}",
                    line.split(' ').next()
                );
                seen.push(line);
                server.get_mut().write_all(reply.as_bytes()).await.unwrap();
            }
            seen
        });
        (Conversation::new(client), handle)
    }

    #[tokio::test]
    async fn auth_plain_sends_the_expected_token_and_refuses_a_bad_reply() {
        let config = SmtpConfig {
            host: "127.0.0.1".into(),
            port: 0,
            security: SmtpSecurity::Plaintext,
            credentials: Some(SmtpCredentials {
                username: "user".into(),
                password: "pass".into(),
            }),
            from: "sender@example.com".into(),
        };
        let token = STANDARD.encode("\0user\0pass");
        let caps = "250-scripted\r\n250 AUTH PLAIN\r\n";
        let (mut conversation, server) = scripted(vec![
            ("EHLO", caps),
            ("AUTH PLAIN", "235 ok\r\n"),
            ("MAIL FROM", "250 ok\r\n"),
            ("RCPT TO", "250 ok\r\n"),
            ("DATA", "354 go\r\n"),
            (".", "250 queued\r\n"),
            ("QUIT", "221 bye\r\n"),
        ])
        .await;
        conversation.expect(220).await.unwrap();
        let capabilities = conversation.ehlo().await.unwrap();
        let data = render(&config.from, &message("Hi", "body")).unwrap();
        transact(
            &mut conversation,
            &capabilities,
            &config,
            "reader@example.com",
            &data,
        )
        .await
        .unwrap();
        let seen = server.await.unwrap();
        assert_eq!(seen[1], format!("AUTH PLAIN {token}"));

        // A server that rejects the credentials stops delivery at AUTH.
        let (mut conversation, server) =
            scripted(vec![("EHLO", caps), ("AUTH PLAIN", "535 no\r\n")]).await;
        conversation.expect(220).await.unwrap();
        let capabilities = conversation.ehlo().await.unwrap();
        assert!(transact(
            &mut conversation,
            &capabilities,
            &config,
            "reader@example.com",
            &data
        )
        .await
        .is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn read_line_refuses_a_peer_that_never_sends_a_newline() {
        let (client, mut server) = duplex(64 * 1024);
        tokio::spawn(async move {
            let junk = vec![b'x'; MAX_LINE_BYTES * 2];
            let _ = server.write_all(&junk).await;
        });
        let mut reader = BufReader::new(client);
        assert!(read_line(&mut reader).await.is_err());
    }
}
