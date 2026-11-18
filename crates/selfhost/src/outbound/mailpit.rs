//! [`MailCapture`] over Mailpit's HTTP API, reached over the stack's internal
//! network. Mailpit is the capture the self-host stack runs in its
//! `mailcatcher` profile.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;

use crate::domain::model::{CapturedMail, CapturedMessage, MailPage, MailQuery, SelfHostError};
use crate::domain::ports::MailCapture;

/// Mail capture over the Mailpit at `base`; off when `base` is `None`.
pub struct MailpitCapture {
    client: Client,
    base: Option<Url>,
}

impl MailpitCapture {
    /// Creates the adapter; `base` is Mailpit's web address, such as `http://mailpit:8025`.
    pub fn new(base: Option<Url>) -> Self {
        Self {
            client: Client::new(),
            base,
        }
    }

    fn url(&self, segments: &[&str]) -> Result<Url, SelfHostError> {
        let mut url = self.base.clone().ok_or_else(|| {
            SelfHostError::Unavailable("mail capture is not set up on this server".into())
        })?;
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("the mail capture address cannot hold a path"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }
}

/// Mailpit's message ids are database ids; anything else is rejected before
/// it reaches a URL.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn unreachable(error: reqwest::Error) -> SelfHostError {
    tracing::warn!(error = ?error, "mail capture unreachable");
    SelfHostError::Unavailable("the mail capture is not reachable".into())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Address {
    #[serde(default)]
    name: String,
    address: String,
}

impl Address {
    fn display(&self) -> String {
        if self.name.is_empty() {
            self.address.clone()
        } else {
            format!("{} <{}>", self.name, self.address)
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Summary {
    #[serde(rename = "ID")]
    id: String,
    from: Option<Address>,
    #[serde(default)]
    to: Option<Vec<Address>>,
    #[serde(default)]
    subject: String,
    created: DateTime<Utc>,
    #[serde(default)]
    snippet: String,
}

/// The list and search responses; unlike messages, their own keys are lowercase.
#[derive(Deserialize)]
struct Messages {
    /// How many messages match, across all pages.
    messages_count: u32,
    messages: Vec<Summary>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Message {
    #[serde(rename = "ID")]
    id: String,
    from: Option<Address>,
    #[serde(default)]
    to: Option<Vec<Address>>,
    #[serde(default)]
    subject: String,
    date: DateTime<Utc>,
    #[serde(default)]
    text: String,
    #[serde(rename = "HTML", default)]
    html: String,
}

fn recipients(to: Option<Vec<Address>>) -> Vec<String> {
    to.unwrap_or_default()
        .iter()
        .map(Address::display)
        .collect()
}

/// The start of a plain-text body, on one line.
fn snippet(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    line.chars().take(200).collect()
}

#[async_trait]
impl MailCapture for MailpitCapture {
    #[tracing::instrument(name = "selfhost.mail_capture.list", skip_all, fields(start = query.start), err)]
    async fn list(&self, query: &MailQuery) -> Result<MailPage, SelfHostError> {
        let mut url = match &query.search {
            Some(_) => self.url(&["api", "v1", "search"])?,
            None => self.url(&["api", "v1", "messages"])?,
        };
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("start", &query.start.to_string());
            pairs.append_pair("limit", &query.limit.unwrap_or(50).to_string());
            if let Some(search) = &query.search {
                pairs.append_pair("query", search);
            }
        }
        let page: Messages = self
            .client
            .get(url)
            .send()
            .await
            .map_err(unreachable)?
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("listing captured mail: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("reading captured mail: {e}"))?;
        Ok(MailPage {
            total: page.messages_count,
            messages: page
                .messages
                .into_iter()
                .map(|m| CapturedMail {
                    id: m.id,
                    from: m.from.map(|a| a.display()).unwrap_or_default(),
                    to: recipients(m.to),
                    subject: m.subject,
                    created_at: m.created,
                    snippet: m.snippet,
                })
                .collect(),
        })
    }

    #[tracing::instrument(name = "selfhost.mail_capture.get", skip_all, err)]
    async fn get(&self, id: &str) -> Result<Option<CapturedMessage>, SelfHostError> {
        if !valid_id(id) {
            return Ok(None);
        }
        let response = self
            .client
            .get(self.url(&["api", "v1", "message", id])?)
            .send()
            .await
            .map_err(unreachable)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let message: Message = response
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("reading captured message: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("reading captured message: {e}"))?;
        Ok(Some(CapturedMessage {
            mail: CapturedMail {
                id: message.id,
                from: message.from.map(|a| a.display()).unwrap_or_default(),
                to: recipients(message.to),
                subject: message.subject,
                created_at: message.date,
                snippet: snippet(&message.text),
            },
            text: (!message.text.is_empty()).then_some(message.text),
            html: (!message.html.is_empty()).then_some(message.html),
        }))
    }

    #[tracing::instrument(name = "selfhost.mail_capture.delete", skip_all, err)]
    async fn delete(&self, id: &str) -> Result<bool, SelfHostError> {
        // An empty id list makes Mailpit delete everything.
        if !valid_id(id) {
            return Ok(false);
        }
        self.client
            .delete(self.url(&["api", "v1", "messages"])?)
            .json(&serde_json::json!({ "IDs": [id] }))
            .send()
            .await
            .map_err(unreachable)?
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("deleting captured message: {e}"))?;
        Ok(true)
    }

    #[tracing::instrument(name = "selfhost.mail_capture.clear", skip_all, err)]
    async fn clear(&self) -> Result<(), SelfHostError> {
        self.client
            .delete(self.url(&["api", "v1", "messages"])?)
            .send()
            .await
            .map_err(unreachable)?
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("clearing captured mail: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod test;
