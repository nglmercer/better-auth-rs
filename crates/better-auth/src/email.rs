//! Email delivery for verification and password-reset links.
//!
//! The core only knows the [`EmailSender`] trait. Applications plug in a
//! transport (SMTP, an email API, or a queue). [`CapturingEmailSender`] keeps
//! messages in memory for tests and local development.

use async_trait::async_trait;
use better_auth_core::error::Result;
use std::sync::Mutex;

/// One outgoing message. Bodies are plain text: HTML templates are the
/// application's responsibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub text: String,
}

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, message: EmailMessage) -> Result<()>;
}

/// Keeps every message in memory, in send order.
#[derive(Default)]
pub struct CapturingEmailSender {
    messages: Mutex<Vec<EmailMessage>>,
}

impl CapturingEmailSender {
    pub fn messages(&self) -> Vec<EmailMessage> {
        self.messages
            .lock()
            .map(|messages| messages.clone())
            .unwrap_or_default()
    }

    pub fn last(&self) -> Option<EmailMessage> {
        self.messages().pop()
    }
}

#[async_trait]
impl EmailSender for CapturingEmailSender {
    async fn send(&self, message: EmailMessage) -> Result<()> {
        if let Ok(mut messages) = self.messages.lock() {
            messages.push(message);
        }
        Ok(())
    }
}

/// Builds the password-reset message. The link points at `reset_url`, which
/// the application serves and which posts the token to `/reset-password`.
pub fn password_reset_message(to: &str, reset_url: &str) -> EmailMessage {
    EmailMessage {
        to: to.to_owned(),
        subject: "Reset your password".into(),
        text: format!(
            "We received a request to reset your password.\n\n\
             Open this link to choose a new password:\n{reset_url}\n\n\
             If you did not ask for this, you can ignore this message."
        ),
    }
}

/// Builds the email-verification message.
pub fn verification_message(to: &str, verify_url: &str) -> EmailMessage {
    EmailMessage {
        to: to.to_owned(),
        subject: "Verify your email address".into(),
        text: format!(
            "Confirm that this address belongs to you:\n{verify_url}\n\n\
             If you did not create an account, you can ignore this message."
        ),
    }
}

/// Builds the magic-link sign-in message.
pub fn magic_link_message(to: &str, link: &str) -> EmailMessage {
    EmailMessage {
        to: to.to_owned(),
        subject: "Your sign-in link".into(),
        text: format!(
            "Open this link to sign in. It works once and expires in 5 minutes:\n{link}\n\n\
             If you did not ask for it, you can ignore this message."
        ),
    }
}

/// Builds the one-time code message.
/// Builds the message that carries an email-verification code.
pub fn email_verification_code_message(to: &str, code: &str) -> EmailMessage {
    EmailMessage {
        to: to.to_owned(),
        subject: "Verify your email address".into(),
        text: format!(
            "Your verification code is {code}. It works once and expires in 5 minutes.\n\n\
             If you did not ask for it, you can ignore this message."
        ),
    }
}

/// Builds the message that carries a code for changing the account's email address.
/// It goes to the new address, which proves the caller can receive mail there.
pub fn email_change_code_message(to: &str, code: &str) -> EmailMessage {
    EmailMessage {
        to: to.to_owned(),
        subject: "Confirm your new email address".into(),
        text: format!(
            "Your code to use this address is {code}. It works once and expires in 5 minutes.\n\n\
             If you did not ask for it, you can ignore this message."
        ),
    }
}

/// Builds the message that carries a password-reset code.
pub fn password_reset_code_message(to: &str, code: &str) -> EmailMessage {
    EmailMessage {
        to: to.to_owned(),
        subject: "Your password reset code".into(),
        text: format!(
            "Your password reset code is {code}. It works once and expires in 5 minutes.\n\n\
             If you did not ask for it, you can ignore this message. Your password is unchanged."
        ),
    }
}

pub fn email_otp_message(to: &str, code: &str) -> EmailMessage {
    EmailMessage {
        to: to.to_owned(),
        subject: "Your sign-in code".into(),
        text: format!(
            "Your sign-in code is {code}. It works once and expires in 5 minutes.\n\n\
             If you did not ask for it, you can ignore this message."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capturing_sender_keeps_messages_in_order() {
        let sender = CapturingEmailSender::default();
        sender
            .send(password_reset_message(
                "a@example.com",
                "https://app.example/reset?token=1",
            ))
            .await
            .unwrap();
        sender
            .send(verification_message(
                "b@example.com",
                "https://app.example/verify?token=2",
            ))
            .await
            .unwrap();
        let messages = sender.messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].to, "a@example.com");
        assert!(messages[0].text.contains("token=1"));
        assert_eq!(sender.last().unwrap().to, "b@example.com");
    }
}
