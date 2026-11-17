use super::*;

/// A list response as Mailpit v1.20 returns it (fields trimmed).
const LIST: &str = r#"{
    "total": 3, "unread": 1, "count": 2, "messages_count": 2, "start": 0, "tags": [],
    "messages": [{
        "ID": "Qx7aB", "MessageID": "abc@macro", "Read": false,
        "From": {"Name": "Macro", "Address": "noreply@example.com"},
        "To": [{"Name": "", "Address": "new@example.com"}],
        "Cc": [], "Bcc": [], "ReplyTo": [],
        "Subject": "Your sign-in code", "Created": "2026-11-17T03:40:00.123Z",
        "Tags": [], "Size": 1234, "Attachments": 0, "Snippet": "Your code is 123456"
    }, {
        "ID": "Zz9", "From": null, "To": null, "Subject": "", "Created": "2026-11-17T03:41:00Z"
    }]
}"#;

/// Messages map to captured mail with readable senders and recipients, and a
/// search counts only its matches.
#[test]
fn mailpit_listings_read_into_captured_mail() {
    let page: Messages = serde_json::from_str(LIST).unwrap();
    assert_eq!(page.messages_count, 2);
    let first = &page.messages[0];
    assert_eq!(first.id, "Qx7aB");
    assert_eq!(
        first.from.as_ref().map(Address::display).as_deref(),
        Some("Macro <noreply@example.com>")
    );
    assert_eq!(first.snippet, "Your code is 123456");
    let second = &page.messages[1];
    assert!(second.from.is_none() && second.to.is_none());
}

/// A message's bodies and date come through; its snippet is the text on one line.
#[test]
fn mailpit_messages_carry_their_bodies() {
    let message: Message = serde_json::from_str(
        r#"{"ID": "Qx7aB", "From": {"Name": "", "Address": "noreply@example.com"},
            "To": [{"Name": "New", "Address": "new@example.com"}], "Subject": "Code",
            "Date": "2026-11-17T03:40:00Z", "Text": "Your code\n\nis 123456", "HTML": "<p>x</p>"}"#,
    )
    .unwrap();
    assert_eq!(recipients(message.to), ["New <new@example.com>"]);
    assert_eq!(snippet(&message.text), "Your code is 123456");
    assert_eq!(message.html, "<p>x</p>");
}

/// Deleting with a missing or odd id never reaches Mailpit, where an empty
/// id list would delete every message.
#[tokio::test]
async fn deleting_needs_a_real_id() {
    let capture = MailpitCapture::new(Some("http://127.0.0.1:9".parse().unwrap()));
    for id in ["", "../messages", "a b", "x?IDs="] {
        assert!(!capture.delete(id).await.unwrap(), "{id:?}");
    }
}

/// Without a configured capture every call says so instead of failing as an error.
#[tokio::test]
async fn an_unconfigured_capture_is_unavailable() {
    let capture = MailpitCapture::new(None);
    let err = capture.list(&MailQuery::default()).await.unwrap_err();
    assert!(matches!(err, SelfHostError::Unavailable(_)));
}

/// Paths are appended to Mailpit's address, keeping any prefix it is served under.
#[test]
fn urls_keep_the_configured_prefix() {
    let capture = MailpitCapture::new(Some("http://mailpit:8025/mail/".parse().unwrap()));
    let url = capture.url(&["api", "v1", "message", "Qx7aB"]).unwrap();
    assert_eq!(
        url.as_str(),
        "http://mailpit:8025/mail/api/v1/message/Qx7aB"
    );
}
