use super::*;

/// Inserts an active root-capable account: a `macro_user` row, the `"User"`
/// profile that references it, and a `super_admin` role on the profile id.
async fn insert_admin(pool: &PgPool, email: &str, macro_user_id: &str) {
    sqlx::query!(
        r#"INSERT INTO macro_user (id, username, email, stripe_customer_id)
           VALUES ($1::text::uuid, $2, $2, $2) ON CONFLICT DO NOTHING"#,
        macro_user_id,
        email
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query!(
        r#"INSERT INTO "User" (id, email, macro_user_id)
           VALUES ($1, $2, $3::text::uuid) ON CONFLICT DO NOTHING"#,
        format!("macro|{email}"),
        email,
        macro_user_id
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query!(
        r#"INSERT INTO "RolesOnUsers" ("userId", "roleId") VALUES ($1, 'super_admin') ON CONFLICT DO NOTHING"#,
        format!("macro|{email}")
    )
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrator = "macro_db_migrator::MACRO_DB_MIGRATIONS")]
async fn concurrent_demotions_of_two_admins_leave_one_admin(pool: PgPool) {
    insert_admin(
        &pool,
        "first@example.com",
        "00000000-0000-4000-8000-000000000001",
    )
    .await;
    insert_admin(
        &pool,
        "second@example.com",
        "00000000-0000-4000-8000-000000000002",
    )
    .await;
    let repo = PgSelfHostRepo::new(pool.clone());

    let (a, b) = tokio::join!(
        repo.revoke_admin_unless_last("macro|first@example.com"),
        repo.revoke_admin_unless_last("macro|second@example.com"),
    );

    let revoked = [a.unwrap(), b.unwrap()].iter().filter(|r| **r).count();
    assert_eq!(revoked, 1, "exactly one demotion must win the race");
    let remaining = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!" FROM "RolesOnUsers" WHERE "roleId" = 'super_admin'"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, 1);
}

#[sqlx::test(migrator = "macro_db_migrator::MACRO_DB_MIGRATIONS")]
async fn disabling_the_only_active_admin_is_refused(pool: PgPool) {
    insert_admin(
        &pool,
        "only@example.com",
        "00000000-0000-4000-8000-000000000003",
    )
    .await;
    let repo = PgSelfHostRepo::new(pool.clone());

    let marked = repo
        .mark_disabled_unless_last_admin("macro|only@example.com", "macro|other@example.com")
        .await
        .unwrap();

    assert!(!marked);
}

const WEEK: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// Two admins inviting the same address at once send one invitation; the
/// other learns when the next one is possible.
#[sqlx::test(migrator = "macro_db_migrator::MACRO_DB_MIGRATIONS")]
async fn concurrent_invitations_to_one_address_claim_once(pool: PgPool) {
    let repo = PgSelfHostRepo::new(pool.clone());
    assert!(
        repo.add_allowed_email("new@example.com", "macro|a@example.com")
            .await
            .unwrap()
    );
    assert!(
        !repo
            .add_allowed_email("new@example.com", "macro|a@example.com")
            .await
            .unwrap()
    );

    let (a, b) = tokio::join!(
        repo.claim_invite("new@example.com", WEEK),
        repo.claim_invite("new@example.com", WEEK),
    );

    let claims = [a.unwrap(), b.unwrap()];
    assert_eq!(
        claims
            .iter()
            .filter(|c| **c == InviteClaim::Claimed(None))
            .count(),
        1,
        "exactly one invitation must win the race: {claims:?}"
    );
    let invited_at = repo.list_allowed_emails().await.unwrap()[0]
        .last_invited_at
        .unwrap();
    assert!(claims.contains(&InviteClaim::TooSoon(
        invited_at + chrono::Duration::from_std(WEEK).unwrap()
    )));
    assert_eq!(
        repo.claim_invite("stranger@example.com", WEEK)
            .await
            .unwrap(),
        InviteClaim::NotAllowed
    );
}

/// Putting back the previous time after a failed send lets the next
/// invitation go out right away.
#[sqlx::test(migrator = "macro_db_migrator::MACRO_DB_MIGRATIONS")]
async fn a_restored_invitation_time_frees_the_address(pool: PgPool) {
    let repo = PgSelfHostRepo::new(pool.clone());
    repo.add_allowed_email("new@example.com", "macro|a@example.com")
        .await
        .unwrap();
    let InviteClaim::Claimed(previous) = repo.claim_invite("new@example.com", WEEK).await.unwrap()
    else {
        panic!("the first invitation must be claimed");
    };

    repo.restore_last_invited("new@example.com", previous)
        .await
        .unwrap();

    assert_eq!(
        repo.claim_invite("new@example.com", WEEK).await.unwrap(),
        InviteClaim::Claimed(None)
    );
}
