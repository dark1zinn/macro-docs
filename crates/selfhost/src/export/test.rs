use chrono::{TimeZone, Utc};
use serde_json::json;

use super::*;
use crate::domain::model::{AuditAction, NewAuditEntry};

#[test]
fn csv_quotes_values_and_defuses_formulas() {
    let at = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
    let entries = [
        AuditEntry {
            id: 2,
            created_at: at,
            entry: NewAuditEntry {
                actor: Some("macro|root@example.com".into()),
                action: AuditAction::AllowedEmailAdded,
                target: Some("=HYPERLINK(\"x\")@example.com".into()),
                details: json!({}),
            },
            status: AuditStatus::Failed("refused, \"twice\"".into()),
            completed_at: Some(at),
        },
        AuditEntry {
            id: 1,
            created_at: at,
            entry: NewAuditEntry {
                actor: None,
                action: AuditAction::RootClaimed,
                target: Some("macro|root@example.com".into()),
                details: json!({}),
            },
            status: AuditStatus::Pending,
            completed_at: None,
        },
    ];

    let csv = audit_csv(&entries).unwrap();

    let mut reader = csv::Reader::from_reader(csv.as_bytes());
    let rows: Vec<Vec<String>> = reader
        .records()
        .map(|r| r.unwrap().iter().map(str::to_owned).collect())
        .collect();
    assert_eq!(
        rows[0],
        [
            "2",
            "2026-01-02T03:04:05+00:00",
            "macro|root@example.com",
            "allowed_email_added",
            "'=HYPERLINK(\"x\")@example.com",
            "failed",
            "refused, \"twice\"",
            "2026-01-02T03:04:05+00:00",
            "{}",
        ]
    );
    assert_eq!(rows[1][2], "system");
    assert_eq!(rows[1][5], "pending");
    assert_eq!(rows[1][7], "");
}
