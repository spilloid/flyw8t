//! Managing devices from the console: names, notes, tags, sites, retiring, and changes to
//! many devices at once.
//!
//! A device never moves between organizations: its jobs, inventory and audit belong to the
//! organization it was enrolled in. To hand a machine to another organization, retire it and
//! enroll it again with that organization's token.
//!
//! Every change is scoped like a read: a device outside the caller's organizations does not
//! exist for them. A change to many devices names each device explicitly and states how many
//! it expects, so the count confirmed is the count changed.

use crate::audit::Audit;
use crate::auth::{Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::jobs::{self, NewJob};
use crate::queries;
use crate::web::{check_csrf, ctx, html, page, to, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::Response;
use flyw8t_domain::Permission;
use flyw8t_protocol::Action;
use flyw8t_web::model::BulkConfirm;
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

/// The most devices one change may touch.
pub const MAX_BULK: usize = 500;
/// The most tags one device may carry.
const MAX_TAGS: usize = 20;

/// A tag as stored: lowercase letters, digits and `._:-`, starting with a letter or digit, at
/// most 40 characters (the same rule as the database's check).
pub fn clean_tag(raw: &str) -> AppResult<String> {
    let t = raw.trim().to_lowercase();
    let ok = (1..=40).contains(&t.len())
        && t.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:-".contains(&b));
    if ok {
        Ok(t)
    } else {
        Err(AppError::BadRequest(format!(
            "{:?} is not a valid tag: use up to 40 letters, digits, '.', '_', ':' or '-'.",
            raw.trim()
        )))
    }
}

/// Tags typed as one field, separated by commas or spaces. Duplicates collapse.
fn parse_tags(raw: &str) -> AppResult<Vec<String>> {
    let mut tags = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .map(clean_tag)
        .collect::<AppResult<Vec<_>>>()?;
    tags.sort();
    tags.dedup();
    if tags.len() > MAX_TAGS {
        return Err(AppError::BadRequest(format!(
            "A device can carry at most {MAX_TAGS} tags."
        )));
    }
    Ok(tags)
}

/// The device's organization, if the caller can see the device; locked for the change.
async fn scoped_org(tx: &mut PgConnection, p: &Principal, id: Uuid) -> AppResult<Uuid> {
    let (all, orgs) = p.scope();
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM devices WHERE id = $1 AND ($2 OR organization_id = ANY($3)) FOR UPDATE",
    )
    .bind(id)
    .bind(all)
    .bind(&orgs)
    .fetch_optional(&mut *tx)
    .await?;
    row.map(|(o,)| o).ok_or(AppError::NotFound)
}

/// Name, notes, tags and site.
pub async fn edit(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::ManageDevices)?;
        let name = form.get("display_name").unwrap_or("").trim();
        if name.chars().count() > 200 {
            return Err(AppError::BadRequest("Name must be at most 200 characters.".into()));
        }
        let notes = form.get("notes").unwrap_or("").trim().replace('\0', "");
        if notes.chars().count() > 4000 {
            return Err(AppError::BadRequest("Notes must be at most 4000 characters.".into()));
        }
        let tags = parse_tags(form.get("tags").unwrap_or(""))?;
        let site: Option<Uuid> = match form.get("site").unwrap_or("") {
            "" => None,
            s => Some(s.parse().map_err(|_| AppError::BadRequest("Unknown site.".into()))?),
        };

        let mut tx = state.db.begin().await?;
        let org = scoped_org(&mut tx, &p, id).await?;
        if let Some(site) = site {
            let exists: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM sites WHERE id = $1 AND organization_id = $2")
                    .bind(site)
                    .bind(org)
                    .fetch_optional(&mut *tx)
                    .await?;
            if exists.is_none() {
                return Err(AppError::BadRequest(
                    "That site belongs to another organization.".into(),
                ));
            }
        }
        sqlx::query("UPDATE devices SET display_name = $2, notes = $3, site_id = $4 WHERE id = $1")
            .bind(id)
            .bind((!name.is_empty()).then_some(name))
            .bind(&notes)
            .bind(site)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM device_tags WHERE device_id = $1 AND NOT (tag = ANY($2))")
            .bind(id)
            .bind(&tags)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO device_tags (device_id, tag) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(&tags)
        .execute(&mut *tx)
        .await?;
        Audit::user(&p, "device.update")
            .org(org)
            .target("device", id)
            .detail(json!({ "display_name": name, "tags": tags, "site_id": site, "notes_chars": notes.chars().count() }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        to(format!("/devices/{id}?m=device-updated"))
    })
    .await
}

/// Retire one device inside a transaction: revoke its credentials and mark it retired. The
/// caller closes its connection after committing.
async fn retire_one(tx: &mut PgConnection, p: &Principal, id: Uuid) -> AppResult<()> {
    let org = scoped_org(tx, p, id).await?;
    let retired =
        sqlx::query("UPDATE devices SET retired_at = now() WHERE id = $1 AND retired_at IS NULL")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    let revoked = sqlx::query(
        "UPDATE device_credentials SET revoked_at = now(), revoked_reason = $2 WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(format!("retired by {}", p.email))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if retired > 0 {
        Audit::user(p, "device.retire")
            .org(org)
            .target("device", id)
            .detail(json!({ "credentials_revoked": revoked }))
            .record(&mut *tx)
            .await?;
    }
    Ok(())
}

pub async fn retire(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::RetireDevices)?;
        if form.get("confirm") != Some("yes") {
            return Err(AppError::BadRequest("Confirm the retirement first.".into()));
        }
        let mut tx = state.db.begin().await?;
        retire_one(&mut tx, &p, id).await?;
        tx.commit().await?;
        state.registry.kick(id);
        to(format!("/devices/{id}?m=device-retired"))
    })
    .await
}

/// The devices a bulk form names, each one checked against the caller's scope: the ticked
/// `device` fields, or (`all=1`) every `shown` device, exactly the rows the page displayed.
/// (The filter is never re-run here: a device that started matching it since the page was
/// shown must not be changed unseen.)
async fn selected(state: &Shared, p: &Principal, form: &Form) -> AppResult<Vec<Uuid>> {
    let field = if form.get("all") == Some("1") {
        "shown"
    } else {
        "device"
    };
    let mut ids = form
        .all(field)
        .into_iter()
        .map(|d| {
            d.parse()
                .map_err(|_| AppError::BadRequest("Unknown device.".into()))
        })
        .collect::<AppResult<Vec<Uuid>>>()?;
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err(AppError::BadRequest("Select at least one device.".into()));
    }
    if ids.len() > MAX_BULK {
        return Err(AppError::BadRequest(format!(
            "{} devices selected; one change can touch at most {MAX_BULK}. Narrow the filter.",
            ids.len()
        )));
    }
    let (all, orgs) = p.scope();
    let (visible,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM devices WHERE id = ANY($1) AND ($2 OR organization_id = ANY($3))",
    )
    .bind(&ids)
    .bind(all)
    .bind(&orgs)
    .fetch_one(&state.db)
    .await?;
    if visible as usize != ids.len() {
        return Err(AppError::NotFound);
    }
    Ok(ids)
}

/// A confirmed change states how many devices it expects; anything else is refused.
fn confirmed_count(form: &Form, ids: &[Uuid]) -> AppResult<()> {
    if form.get("confirm") != Some("yes") {
        return Err(AppError::BadRequest("Confirm the change first.".into()));
    }
    if form.get("count").and_then(|c| c.parse::<usize>().ok()) != Some(ids.len()) {
        return Err(AppError::BadRequest(
            "The selection changed since you confirmed it. Start again from the device list."
                .into(),
        ));
    }
    Ok(())
}

/// The device list's bulk form: tag changes happen at once; running a diagnostic and
/// retiring go to a confirmation page that names every device first.
pub async fn bulk(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        let op = form.get("op").unwrap_or("");
        match op {
            "tag-add" | "tag-remove" => p.require(Permission::ManageDevices)?,
            "run" => p.require(Permission::RunDiagnostics)?,
            "retire" => p.require(Permission::RetireDevices)?,
            _ => return Err(AppError::BadRequest("Choose what to do with the selection.".into())),
        }
        let ids = selected(&state, &p, &form).await?;
        if op == "tag-add" || op == "tag-remove" {
            let tag = clean_tag(form.get("tag").unwrap_or(""))?;
            let mut tx = state.db.begin().await?;
            // Lock the devices (in one order, so two changes cannot deadlock) before counting
            // their tags: two concurrent additions must not both see room for one more.
            sqlx::query("SELECT id FROM devices WHERE id = ANY($1) ORDER BY id FOR UPDATE")
                .bind(&ids)
                .execute(&mut *tx)
                .await?;
            let changed = if op == "tag-add" {
                let over: Option<(Uuid,)> = sqlx::query_as(
                    "SELECT device_id FROM device_tags WHERE device_id = ANY($1) AND tag <> $2
                      GROUP BY device_id HAVING count(*) >= $3 LIMIT 1",
                )
                .bind(&ids)
                .bind(&tag)
                .bind(MAX_TAGS as i64)
                .fetch_optional(&mut *tx)
                .await?;
                if over.is_some() {
                    return Err(AppError::BadRequest(format!(
                        "A selected device already carries {MAX_TAGS} tags."
                    )));
                }
                sqlx::query(
                    "INSERT INTO device_tags (device_id, tag) SELECT unnest($1::uuid[]), $2 ON CONFLICT DO NOTHING",
                )
                .bind(&ids)
                .bind(&tag)
                .execute(&mut *tx)
                .await?
                .rows_affected()
            } else {
                sqlx::query("DELETE FROM device_tags WHERE device_id = ANY($1) AND tag = $2")
                    .bind(&ids)
                    .bind(&tag)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
            };
            Audit::user(&p, if op == "tag-add" { "device.tag" } else { "device.untag" })
                .detail(json!({ "tag": tag, "devices": ids, "changed": changed }))
                .record(&mut *tx)
                .await?;
            tx.commit().await?;
            let m = if op == "tag-add" { "devices-tagged" } else { "devices-untagged" };
            return to(format!("/devices?tag={tag}&m={m}"));
        }
        let mut devices = Vec::with_capacity(ids.len());
        for id in &ids {
            if let Some(d) = queries::device_summary(&state, &p, *id).await? {
                devices.push(d);
            }
        }
        let op = if op == "run" { "run" } else { "retire" };
        html(flyw8t_web::bulk_confirm_page(
            &ctx(&p, None),
            BulkConfirm { op, devices },
        ))
    })
    .await
}

/// Run one diagnostic on every confirmed device, as one batch. Each job is authorized on its
/// own; devices that cannot run jobs (retired, revoked) are skipped and counted.
pub async fn bulk_run(State(state): State<Shared>, WebUser(p): WebUser, body: Bytes) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::RunDiagnostics)?;
        let ids = selected(&state, &p, &form).await?;
        confirmed_count(&form, &ids)?;
        let name = form.get("action").unwrap_or("");
        let action = Action::from_request(name, |k| form.get(k).map(str::to_string))
            .map_err(|e| AppError::BadRequest(e.to_string()))?;
        action
            .validate()
            .map_err(|e| AppError::BadRequest(e.to_string()))?;
        // All or nothing: every job of the batch, and its audit, commit together; only then
        // is anything offered to a device. A failure leaves no partial batch to retry over.
        let batch = Uuid::new_v4();
        let mut skipped = 0usize;
        let mut queued = Vec::with_capacity(ids.len());
        let mut tx = state.db.begin().await?;
        for id in &ids {
            let job = NewJob {
                device_id: *id,
                action: action.clone(),
                timeout_secs: None,
                idempotency_key: None,
                batch_id: Some(batch),
            };
            match jobs::create_in(&state, &mut tx, &p, job).await {
                Ok(_) => queued.push(*id),
                // Retired or revoked: refused before anything was written.
                Err(AppError::Conflict(_)) => skipped += 1,
                Err(e) => return Err(e),
            }
        }
        if queued.is_empty() {
            return Err(AppError::Conflict(
                "None of the selected devices can run jobs (retired or revoked).".into(),
            ));
        }
        Audit::user(&p, "job.batch")
            .detail(json!({ "batch_id": batch, "action": action.name(), "devices": ids.len(), "skipped": skipped }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        // Committed: the batch exists whatever happens next. A device that cannot be offered
        // its job now gets it from the announcement or the sweeper.
        for id in queued {
            if let Err(e) = jobs::dispatch_pending(&state, id, jobs::Pass::NewWork).await {
                tracing::warn!(device = %id, error = %format!("{e:#}"), "batch dispatch deferred to the sweeper");
            }
        }
        to(format!("/jobs?batch={batch}"))
    })
    .await
}

pub async fn bulk_retire(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::RetireDevices)?;
        let ids = selected(&state, &p, &form).await?;
        confirmed_count(&form, &ids)?;
        let mut tx = state.db.begin().await?;
        for id in &ids {
            retire_one(&mut tx, &p, *id).await?;
        }
        tx.commit().await?;
        for id in &ids {
            state.registry.kick(*id);
        }
        to("/devices?status=retired&m=devices-retired")
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_normalized_and_checked() {
        assert_eq!(clean_tag(" Kiosk ").unwrap(), "kiosk");
        assert_eq!(clean_tag("ring:pilot-1").unwrap(), "ring:pilot-1");
        for bad in ["", "-lead", "has space", "naïve", &"x".repeat(41), "a/b"] {
            assert!(clean_tag(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_tags("finance, Kiosk kiosk,,pilot").unwrap(),
            vec!["finance", "kiosk", "pilot"]
        );
        let many = (0..21)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_tags(&many).is_err());
    }
}
