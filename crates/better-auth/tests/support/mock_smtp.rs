//! An in-process SMTP server for tests. It accepts the commands the client needs,
//! optionally requires AUTH PLAIN, can refuse one recipient, and records every
//! delivery with dot-stuffing removed, so tests see the message the client wrote.

use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

#[derive(Clone, Debug, Default)]
pub struct MockOptions {
    /// When set, MAIL FROM is refused until AUTH PLAIN carries these credentials.
    pub require_auth: Option<(String, String)>,
    /// A recipient the server refuses with 550.
    pub reject_recipient: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub mail_from: String,
    pub rcpt_to: String,
    pub data: String,
}

pub struct MockSmtp {
    pub port: u16,
    deliveries: Arc<Mutex<Vec<Delivery>>>,
}

impl MockSmtp {
    pub async fn start(options: MockOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let store = deliveries.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let options = options.clone();
                let store = store.clone();
                tokio::spawn(async move {
                    let _ = session(stream, options, store).await;
                });
            }
        });
        Self { port, deliveries }
    }

    pub fn deliveries(&self) -> Vec<Delivery> {
        self.deliveries.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct Envelope {
    authenticated: bool,
    mail_from: Option<String>,
    recipients: Vec<String>,
}

async fn session(
    stream: TcpStream,
    options: MockOptions,
    store: Arc<Mutex<Vec<Delivery>>>,
) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut envelope = Envelope {
        authenticated: options.require_auth.is_none(),
        ..Envelope::default()
    };
    write.write_all(b"220 mock.test ESMTP\r\n").await?;
    loop {
        let mut raw = String::new();
        if reader.read_line(&mut raw).await? == 0 {
            return Ok(());
        }
        let line = raw.trim_end_matches(['\r', '\n']).to_owned();
        let upper = line.to_ascii_uppercase();
        let reply: String = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            if options.require_auth.is_some() {
                "250-mock.test\r\n250-8BITMIME\r\n250 AUTH PLAIN\r\n".into()
            } else {
                "250-mock.test\r\n250 8BITMIME\r\n".into()
            }
        } else if upper.starts_with("AUTH PLAIN ") {
            let sent = line["AUTH PLAIN ".len()..].trim();
            let accepted = options.require_auth.as_ref().is_some_and(|(user, pass)| {
                STANDARD
                    .decode(sent)
                    .map(|bytes| bytes == format!("\0{user}\0{pass}").into_bytes())
                    .unwrap_or(false)
            });
            if accepted {
                envelope.authenticated = true;
                "235 authenticated\r\n".into()
            } else {
                "535 authentication failed\r\n".into()
            }
        } else if upper.starts_with("MAIL FROM:") {
            if envelope.authenticated {
                envelope.mail_from = Some(address(&line["MAIL FROM:".len()..]));
                "250 ok\r\n".into()
            } else {
                "530 authentication required\r\n".into()
            }
        } else if upper.starts_with("RCPT TO:") {
            let recipient = address(&line["RCPT TO:".len()..]);
            if options.reject_recipient.as_deref() == Some(recipient.as_str()) {
                "550 no such user\r\n".into()
            } else if envelope.mail_from.is_none() {
                "503 need MAIL first\r\n".into()
            } else {
                envelope.recipients.push(recipient);
                "250 ok\r\n".into()
            }
        } else if upper == "DATA" {
            if envelope.mail_from.is_none() || envelope.recipients.is_empty() {
                "503 need RCPT first\r\n".into()
            } else {
                write.write_all(b"354 end with a dot\r\n").await?;
                let data = read_data(&mut reader).await?;
                let mail_from = envelope.mail_from.take().unwrap_or_default();
                let mut deliveries = store.lock().unwrap();
                for rcpt_to in envelope.recipients.drain(..) {
                    deliveries.push(Delivery {
                        mail_from: mail_from.clone(),
                        rcpt_to,
                        data: data.clone(),
                    });
                }
                "250 queued\r\n".into()
            }
        } else if upper == "RSET" {
            envelope.mail_from = None;
            envelope.recipients.clear();
            "250 ok\r\n".into()
        } else if upper == "NOOP" {
            "250 ok\r\n".into()
        } else if upper == "QUIT" {
            write.write_all(b"221 bye\r\n").await?;
            return Ok(());
        } else {
            "500 unrecognized command\r\n".into()
        };
        write.write_all(reply.as_bytes()).await?;
    }
}

/// Reads the message body up to the lone-dot line and removes dot-stuffing.
async fn read_data(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<String> {
    let mut out = String::new();
    loop {
        let mut raw = String::new();
        if reader.read_line(&mut raw).await? == 0 {
            return Ok(out);
        }
        let line = raw.trim_end_matches(['\r', '\n']);
        if line == "." {
            return Ok(out);
        }
        let line = line
            .strip_prefix('.')
            .filter(|rest| rest.starts_with('.'))
            .unwrap_or(line);
        out.push_str(line);
        out.push_str("\r\n");
    }
}

/// The address inside `<...>`, as the client wrote it.
fn address(argument: &str) -> String {
    argument
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_owned()
}
