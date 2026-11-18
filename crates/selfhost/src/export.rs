//! Downloadable renderings of self-host data.

use std::borrow::Cow;

use crate::domain::model::{AuditEntry, AuditStatus};

#[cfg(test)]
mod test;

/// Prefixes text a spreadsheet would run as a formula with `'`, so user-chosen
/// values (an email, an error message) open as plain text.
fn cell(value: &str) -> Cow<'_, str> {
    if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        Cow::Owned(format!("'{value}"))
    } else {
        Cow::Borrowed(value)
    }
}

/// Renders audit entries as CSV with a header row, in the given order.
pub fn audit_csv(entries: &[AuditEntry]) -> anyhow::Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "id",
        "created_at",
        "actor",
        "action",
        "target",
        "status",
        "error",
        "completed_at",
        "details",
    ])?;
    for entry in entries {
        let (status, error) = match &entry.status {
            AuditStatus::Pending => ("pending", ""),
            AuditStatus::Succeeded => ("succeeded", ""),
            AuditStatus::Failed(error) => ("failed", error.as_str()),
        };
        let completed_at = entry
            .completed_at
            .map(|at| at.to_rfc3339())
            .unwrap_or_default();
        let fields = [
            Cow::Owned(entry.id.to_string()),
            Cow::Owned(entry.created_at.to_rfc3339()),
            cell(entry.entry.actor.as_deref().unwrap_or("system")),
            Cow::Borrowed(entry.entry.action.as_str()),
            cell(entry.entry.target.as_deref().unwrap_or("")),
            Cow::Borrowed(status),
            cell(error),
            Cow::Owned(completed_at),
            Cow::Owned(entry.entry.details.to_string()),
        ];
        writer.write_record(fields.iter().map(|field| field.as_bytes()))?;
    }
    Ok(String::from_utf8(writer.into_inner()?)?)
}
