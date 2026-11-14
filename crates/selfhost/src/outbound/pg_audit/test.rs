use serde_json::json;

use super::*;

fn entry(action: AuditAction, target: &str) -> NewAuditEntry {
    NewAuditEntry {
        actor: Some("macro|root@example.com".into()),
        action,
        target: Some(target.into()),
        details: json!({ "email": target }),
    }
}

#[sqlx::test(migrator = "macro_db_migrator::MACRO_DB_MIGRATIONS")]
async fn an_entry_settles_once_and_is_never_deleted(pool: PgPool) {
    let log = PgAuditLog::new(pool.clone());
    let id = log
        .begin(&entry(AuditAction::UserDisabled, "macro|a@example.com"))
        .await
        .unwrap();

    log.finish(id, &AuditStatus::Succeeded).await.unwrap();

    assert!(
        log.finish(id, &AuditStatus::Failed("late".into()))
            .await
            .is_err(),
        "a settled entry must not change outcome"
    );
    let rewrite = sqlx::query!(
        "UPDATE selfhost_audit_log SET target = 'someone else' WHERE id = $1",
        id
    )
    .execute(&pool)
    .await;
    assert!(rewrite.is_err(), "the trigger must refuse edits");
    let delete = sqlx::query!("DELETE FROM selfhost_audit_log WHERE id = $1", id)
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "the trigger must refuse deletes");

    let listed = log.list(&AuditQuery::default()).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, AuditStatus::Succeeded);
    assert_eq!(
        listed[0].entry,
        entry(AuditAction::UserDisabled, "macro|a@example.com")
    );
    assert!(listed[0].completed_at.is_some());
}

#[sqlx::test(migrator = "macro_db_migrator::MACRO_DB_MIGRATIONS")]
async fn a_failed_entry_keeps_its_reason(pool: PgPool) {
    let log = PgAuditLog::new(pool);
    let id = log
        .begin(&entry(AuditAction::AdminRevoked, "macro|a@example.com"))
        .await
        .unwrap();

    log.finish(
        id,
        &AuditStatus::Failed("cannot demote the last active admin".into()),
    )
    .await
    .unwrap();

    let listed = log.list(&AuditQuery::default()).await.unwrap();
    assert_eq!(
        listed[0].status,
        AuditStatus::Failed("cannot demote the last active admin".into())
    );
}

#[sqlx::test(migrator = "macro_db_migrator::MACRO_DB_MIGRATIONS")]
async fn listing_filters_and_pages_newest_first(pool: PgPool) {
    let log = PgAuditLog::new(pool);
    let mut ids = Vec::new();
    for (action, target) in [
        (AuditAction::AllowedEmailAdded, "new_hire@example.com"),
        (AuditAction::AllowedEmailAdded, "newXhire@example.com"),
        (AuditAction::UserDisabled, "macro|New_Hire@example.com"),
        (AuditAction::AllowedEmailRemoved, "other@example.com"),
    ] {
        ids.push(log.begin(&entry(action, target)).await.unwrap());
    }
    let targets = |entries: Vec<AuditEntry>| {
        entries
            .into_iter()
            .map(|e| e.entry.target.unwrap())
            .collect::<Vec<_>>()
    };

    let added = log
        .list(&AuditQuery {
            action: Some(AuditAction::AllowedEmailAdded),
            ..AuditQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(
        targets(added),
        ["newXhire@example.com", "new_hire@example.com"]
    );

    // `_` matches literally and case does not matter.
    let searched = log
        .list(&AuditQuery {
            search: Some("NEW_HIRE".into()),
            ..AuditQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(
        targets(searched),
        ["macro|New_Hire@example.com", "new_hire@example.com"]
    );

    let page = log
        .list(&AuditQuery {
            before: Some(ids[2]),
            limit: Some(1),
            ..AuditQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(targets(page), ["newXhire@example.com"]);
}
