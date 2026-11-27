//! Network inventory from NetViz's v1 push contract. Collectors have their own
//! credential plane; a collector key cannot authenticate a person or an agent.
use crate::audit::Audit;
use crate::auth::{self, Principal, WebUser};
use crate::error::{AppError, AppResult};
use crate::web::{check_csrf, ctx, html, page, to, Form};
use crate::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Json;
use flyw8t_domain::network::{
    fresh, normalize_fingerprint, web_port, NetworkObservation, NetworkRange, MAX_BATCH,
};
use flyw8t_domain::Permission;
use flyw8t_web::model::{
    NetworkAsset, NetworkCollector, NetworkHistory, NetworkSite, NetworkWorkspace,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use std::collections::HashSet;
use time::OffsetDateTime;
use uuid::Uuid;

const KEY_PREFIX: &str = "fw8n_";
const PAGE_SIZE: i64 = 50;

pub async fn visible_site(
    state: &Shared,
    p: &Principal,
    id: Uuid,
) -> AppResult<(Uuid, NetworkSite)> {
    p.require(Permission::ViewDevices)?;
    let (all, orgs) = p.scope();
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT s.organization_id, s.name, o.name FROM sites s JOIN organizations o ON o.id=s.organization_id
         WHERE s.id=$1 AND ($2 OR s.organization_id=ANY($3))",
    ).bind(id).bind(all).bind(orgs).fetch_optional(&state.db).await?;
    let (org, name, organization) = row.ok_or(AppError::NotFound)?;
    Ok((
        org,
        NetworkSite {
            id,
            name,
            organization,
        },
    ))
}

type CollectorRow = (
    Uuid,
    String,
    Uuid,
    String,
    String,
    String,
    i32,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    Option<String>,
    Option<String>,
);
fn collector_view(r: CollectorRow) -> NetworkCollector {
    NetworkCollector {
        id: r.0,
        name: r.1,
        site: NetworkSite {
            id: r.2,
            name: r.3,
            organization: r.4,
        },
        cidr: r.5,
        interval_secs: r.6,
        heartbeat_at: r.7,
        inventory_at: r.8,
        revoked_at: r.9,
        version: r.10,
        portglass_fingerprint: r.11,
    }
}

async fn collectors(
    state: &Shared,
    p: &Principal,
    site: Option<Uuid>,
    id: Option<Uuid>,
) -> AppResult<Vec<NetworkCollector>> {
    let (all, orgs) = p.scope();
    let rows: Vec<CollectorRow> = sqlx::query_as(
        "SELECT c.id,c.name,s.id,s.name,o.name,c.cidr,c.interval_secs,c.heartbeat_at,c.inventory_at,c.revoked_at,c.version,c.portglass_fingerprint
         FROM network_collectors c JOIN sites s ON s.id=c.site_id JOIN organizations o ON o.id=c.organization_id
         WHERE ($1 OR c.organization_id=ANY($2)) AND ($3::uuid IS NULL OR c.site_id=$3) AND ($4::uuid IS NULL OR c.id=$4)
         ORDER BY c.revoked_at NULLS FIRST, lower(c.name) LIMIT 200",
    ).bind(all).bind(orgs).bind(site).bind(id).fetch_all(&state.db).await?;
    Ok(rows.into_iter().map(collector_view).collect())
}

#[derive(sqlx::FromRow)]
struct AssetRow {
    id: Uuid,
    site_id: Uuid,
    site_name: String,
    organization: String,
    collector_id: Uuid,
    ip: String,
    mac: Option<String>,
    hostname: String,
    vendor: String,
    device_type: String,
    status: String,
    open_ports: Vec<i32>,
    first_seen_at: OffsetDateTime,
    collected_at: OffsetDateTime,
    received_at: OffsetDateTime,
    interval_secs: i32,
    collector_revoked: bool,
}
fn asset_view(r: AssetRow) -> NetworkAsset {
    NetworkAsset {
        id: r.id,
        site: NetworkSite {
            id: r.site_id,
            name: r.site_name,
            organization: r.organization,
        },
        collector_id: r.collector_id,
        ip: r.ip,
        mac: r.mac,
        hostname: r.hostname,
        vendor: r.vendor,
        device_type: r.device_type,
        status: r.status,
        open_ports: r.open_ports,
        first_seen_at: r.first_seen_at,
        collected_at: r.collected_at,
        received_at: r.received_at,
        interval_secs: r.interval_secs,
        collector_revoked: r.collector_revoked,
    }
}
const ASSET_COLUMNS: &str = "a.id,s.id AS site_id,s.name AS site_name,o.name AS organization,a.collector_id,a.ip,a.mac,a.hostname,a.vendor,a.device_type,a.status,a.open_ports,a.first_seen_at,a.collected_at,a.received_at,c.interval_secs,(c.revoked_at IS NOT NULL) AS collector_revoked";
const ASSET_FROM: &str = "network_assets a JOIN network_collectors c ON c.id=a.collector_id JOIN sites s ON s.id=a.site_id JOIN organizations o ON o.id=a.organization_id";

pub async fn asset(state: &Shared, p: &Principal, id: Uuid) -> AppResult<NetworkAsset> {
    p.require(Permission::ViewDevices)?;
    let (all, orgs) = p.scope();
    let row: Option<AssetRow> = sqlx::query_as(&format!("SELECT {ASSET_COLUMNS} FROM {ASSET_FROM} WHERE a.id=$1 AND ($2 OR a.organization_id=ANY($3))"))
        .bind(id).bind(all).bind(orgs).fetch_optional(&state.db).await?;
    Ok(asset_view(row.ok_or(AppError::NotFound)?))
}

#[derive(Default, Deserialize)]
pub struct NetworkQuery {
    #[serde(default, deserialize_with = "optional_site")]
    site: Option<Uuid>,
    q: Option<String>,
    page: Option<u32>,
}

fn optional_site<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Uuid>, D::Error> {
    let value = String::deserialize(d)?;
    if value.is_empty() {
        Ok(None)
    } else {
        value.parse().map(Some).map_err(serde::de::Error::custom)
    }
}

pub async fn workspace(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Query(q): Query<NetworkQuery>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewDevices)?;
        if let Some(site) = q.site { visible_site(&state, &p, site).await?; }
        let term = q.q.unwrap_or_default().trim().chars().take(200).collect::<String>();
        let page_number = q.page.unwrap_or(1).clamp(1, 10000);
        let (all, orgs) = p.scope();
        let site_rows: Vec<(Uuid, String, String)> = sqlx::query_as("SELECT s.id,s.name,o.name FROM sites s JOIN organizations o ON o.id=s.organization_id WHERE ($1 OR s.organization_id=ANY($2)) ORDER BY lower(o.name),lower(s.name)")
            .bind(all).bind(&orgs).fetch_all(&state.db).await?;
        let condition = "($1 OR a.organization_id=ANY($2)) AND ($3::uuid IS NULL OR a.site_id=$3) AND ($4='' OR concat_ws(' ',a.ip,a.mac,a.hostname,a.vendor,a.device_type) ILIKE $5)";
        let pattern = format!("%{}%", crate::queries::like_escape(&term));
        let (total,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM network_assets a WHERE {condition}"))
            .bind(all).bind(&orgs).bind(q.site).bind(&term).bind(&pattern).fetch_one(&state.db).await?;
        let rows: Vec<AssetRow> = sqlx::query_as(&format!("SELECT {ASSET_COLUMNS} FROM {ASSET_FROM} WHERE {condition} ORDER BY lower(o.name),lower(s.name),lower(a.hostname),a.ip,a.id LIMIT $6 OFFSET $7"))
            .bind(all).bind(&orgs).bind(q.site).bind(&term).bind(&pattern).bind(PAGE_SIZE).bind(i64::from(page_number-1)*PAGE_SIZE).fetch_all(&state.db).await?;
        html(flyw8t_web::network_page(&ctx(&p,None), NetworkWorkspace {
            sites:site_rows.into_iter().map(|(id,name,organization)| NetworkSite{id,name,organization}).collect(),
            selected_site:q.site, query:term, page:page_number, total, assets:rows.into_iter().map(asset_view).collect(), collectors:collectors(&state,&p,q.site,None).await?,
        }))
    }).await
}

pub async fn detail(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
) -> Response {
    page(&p, async {
        let a=asset(&state,&p,id).await?;
        let c=collectors(&state,&p,None,Some(a.collector_id)).await?.pop().ok_or(AppError::NotFound)?;
        let (all, orgs)=p.scope();
        let rows:Vec<(OffsetDateTime,OffsetDateTime,String,serde_json::Value)>=sqlx::query_as(
            "SELECT h.collected_at,h.received_at,c.name,h.observation FROM network_observations h JOIN network_assets a ON a.id=h.asset_id JOIN network_collectors c ON c.id=h.collector_id
             WHERE a.id=$1 AND ($2 OR a.organization_id=ANY($3)) ORDER BY h.collected_at DESC,h.id DESC LIMIT 30"
        ).bind(id).bind(all).bind(orgs).fetch_all(&state.db).await?;
        let history=rows.into_iter().map(|(collected_at,received_at,collector,o)|NetworkHistory{collected_at,received_at,collector,observation:serde_json::to_string_pretty(&o).unwrap_or_default()}).collect();
        html(flyw8t_web::network_asset_page(&ctx(&p,None),a,c,history))
    }).await
}

pub async fn register(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(site): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let f=Form::parse(&body); check_csrf(&p,&f)?;
        p.require(Permission::ManageEnrollment)?;
        let (org,_)=visible_site(&state,&p,site).await?;
        let name=f.get("name").unwrap_or("").trim();
        if name.is_empty() || name.len()>120 || name.chars().any(char::is_control) { return Err(AppError::BadRequest("Give the collector a name of 1–120 bytes.".into())); }
        let range=NetworkRange::parse(f.get("cidr").unwrap_or("")).map_err(|e|AppError::BadRequest(e.into()))?;
        let interval:i32=f.get("interval_secs").unwrap_or("60").parse().map_err(|_|AppError::BadRequest("Enter a polling interval in seconds.".into()))?;
        if !(30..=3600).contains(&interval) { return Err(AppError::BadRequest("The interval must be 30–3600 seconds.".into())); }
        let fingerprint=normalize_fingerprint(f.get("portglass_fingerprint").unwrap_or("")).map_err(|e|AppError::BadRequest(e.into()))?;
        let key=format!("{KEY_PREFIX}{}",auth::random_secret(32));
        let mut tx=state.db.begin().await?;
        auth::recheck_actor(&mut tx, &p, Some(org), false).await?;
        let (id,):(Uuid,)=sqlx::query_as("INSERT INTO network_collectors(organization_id,site_id,name,cidr,interval_secs,token_hash,created_by,portglass_fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id")
            .bind(org).bind(site).bind(name).bind(range.canonical()).bind(interval).bind(auth::digest(&key)).bind(p.user_id).bind(fingerprint).fetch_one(&mut *tx).await?;
        Audit::user(&p,"network.collector_registered").org(org).target("network_collector",id).detail(json!({"site_id":site,"cidr":range.canonical()})).record(&mut *tx).await?;
        tx.commit().await?;
        let config=json!({"version":1,"cidr":range.canonical(),"anchordesk_url":state.config.public_url,"probe_key":key,"interval":format!("{interval}s")});
        html(flyw8t_web::network_collector_created(&ctx(&p,None),id,&serde_json::to_string_pretty(&config).unwrap()))
    }).await
}

pub async fn collector_page(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
) -> Response {
    page(&p, async {
        p.require(Permission::ViewDevices)?;
        let c = collectors(&state, &p, None, Some(id))
            .await?
            .pop()
            .ok_or(AppError::NotFound)?;
        html(flyw8t_web::network_collector_page(&ctx(&p, None), c))
    })
    .await
}

pub async fn configure_access(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p,async {
        let f=Form::parse(&body);check_csrf(&p,&f)?;p.require(Permission::ManageEnrollment)?;
        let fingerprint=normalize_fingerprint(f.get("portglass_fingerprint").unwrap_or("")).map_err(|e|AppError::BadRequest(e.into()))?;
        let (all,orgs)=p.scope();let mut tx=state.db.begin().await?;
        let row:Option<(Uuid,)>=sqlx::query_as("UPDATE network_collectors SET portglass_fingerprint=$1 WHERE id=$2 AND revoked_at IS NULL AND ($3 OR organization_id=ANY($4)) RETURNING organization_id")
            .bind(fingerprint).bind(id).bind(all).bind(orgs).fetch_optional(&mut *tx).await?;
        let (org,)=row.ok_or(AppError::NotFound)?;
        Audit::user(&p,"network.access_configured").org(org).target("network_collector",id).record(&mut *tx).await?;
        tx.commit().await?;to(format!("/network/collectors/{id}"))
    }).await
}

pub async fn revoke(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p,async {
        let f=Form::parse(&body);check_csrf(&p,&f)?;p.require(Permission::ManageEnrollment)?;
        let (all,orgs)=p.scope();let mut tx=state.db.begin().await?;
        let row:Option<(Uuid,)>=sqlx::query_as("UPDATE network_collectors SET revoked_at=coalesce(revoked_at,now()) WHERE id=$1 AND ($2 OR organization_id=ANY($3)) RETURNING organization_id")
            .bind(id).bind(all).bind(orgs).fetch_optional(&mut *tx).await?;
        let (org,)=row.ok_or(AppError::NotFound)?;
        Audit::user(&p,"network.collector_revoked").org(org).target("network_collector",id).record(&mut *tx).await?;
        tx.commit().await?;to(format!("/network/collectors/{id}"))
    }).await
}

/// One try at a collector key. Wrong keys from one address are budgeted (30 in five minutes), so guessing keys
/// cannot keep taking database connections. The place is taken before the lookup and given back unless the key was
/// refused: a good key, a database error and a request that goes away all leave the budget as it was.
struct KeyAttempt<'a> {
    state: &'a Shared,
    place: Option<crate::ratelimit::Reservation>,
}

impl<'a> KeyAttempt<'a> {
    fn take(state: &'a Shared, ip: &str) -> AppResult<Self> {
        let place = state
            .limiter
            .reserve(
                &format!("collector-key:{ip}"),
                30,
                std::time::Duration::from_secs(300),
            )
            .ok_or(AppError::RateLimited)?;
        Ok(Self {
            state,
            place: Some(place),
        })
    }

    /// The key was refused: the place stays taken.
    fn refused(mut self) {
        self.place = None;
    }
}

impl Drop for KeyAttempt<'_> {
    fn drop(&mut self) {
        if let Some(place) = self.place.take() {
            self.state.limiter.refund(place);
        }
    }
}

/// `authenticate`, counted against the address's budget of wrong keys.
async fn authenticate_counted(
    state: &Shared,
    ip: &str,
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
) -> AppResult<(Uuid, Uuid, Uuid, NetworkRange)> {
    let attempt = KeyAttempt::take(state, ip)?;
    let result = authenticate(tx, headers).await;
    if matches!(result, Err(AppError::Unauthorized)) {
        attempt.refused();
    }
    result
}

/// Lock the credential until the write commits: revocation returning means no
/// request authenticated with this key can commit afterwards.
async fn authenticate(
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
) -> AppResult<(Uuid, Uuid, Uuid, NetworkRange)> {
    let key = headers
        .get("x-probe-key")
        .and_then(|v| v.to_str().ok())
        .filter(|k| k.starts_with(KEY_PREFIX) && k.len() < 128)
        .ok_or(AppError::Unauthorized)?;
    let row:Option<(Uuid,Uuid,Uuid,String)>=sqlx::query_as("SELECT id,organization_id,site_id,cidr FROM network_collectors WHERE token_hash=$1 AND revoked_at IS NULL FOR UPDATE")
        .bind(auth::digest(key)).fetch_optional(&mut **tx).await?;
    let (id, org, site, cidr) = row.ok_or(AppError::Unauthorized)?;
    let range = NetworkRange::parse(&cidr).map_err(|e| anyhow::anyhow!(e))?;
    Ok((id, org, site, range))
}

#[derive(Deserialize)]
pub struct DeviceBatch {
    devices: Vec<NetworkObservation>,
}

pub async fn ingest(
    State(state): State<Shared>,
    crate::client_ip::ClientIp(ip): crate::client_ip::ClientIp,
    headers: HeaderMap,
    Json(mut batch): Json<DeviceBatch>,
) -> AppResult<Json<serde_json::Value>> {
    if batch.devices.len() > MAX_BATCH {
        return Err(AppError::BadRequest(format!(
            "A batch may contain at most {MAX_BATCH} devices."
        )));
    }
    let mut tx = state.db.begin().await?;
    let (collector, org, site, range) =
        authenticate_counted(&state, &ip, &mut tx, &headers).await?;
    let now = OffsetDateTime::now_utc();
    let mut keys = HashSet::new();
    let mut addresses = HashSet::new();
    let mut observations = Vec::with_capacity(batch.devices.len());
    for o in &mut batch.devices {
        let key = o
            .normalize(range, now)
            .map_err(|e| AppError::BadRequest(e.into()))?;
        if !keys.insert(key.clone()) || !addresses.insert(o.ip.clone()) {
            return Err(AppError::BadRequest(
                "A batch contains duplicate device identities or addresses.".into(),
            ));
        }
        observations.push((key, o));
    }
    // Serialize cross-collector identity promotion within this site, never globally.
    sqlx::query("SELECT id FROM sites WHERE id=$1 FOR UPDATE")
        .bind(site)
        .execute(&mut *tx)
        .await?;
    let (mut created, mut updated) = (0, 0);
    for (key, o) in observations {
        let mut existing: Option<(Uuid, OffsetDateTime)> = sqlx::query_as(
            "SELECT id,collected_at FROM network_assets WHERE site_id=$1 AND identity_key=$2",
        )
        .bind(site)
        .bind(&key)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.is_none() && !o.mac.is_empty() {
            existing=sqlx::query_as("SELECT id,collected_at FROM network_assets WHERE site_id=$1 AND identity_key=$2 AND mac IS NULL")
                .bind(site).bind(format!("ip:{}",o.ip)).fetch_optional(&mut *tx).await?;
        }
        let (id, is_new) = match existing {
            Some((id, at)) => {
                if at >= o.collected_at {
                    updated += 1;
                    continue;
                }
                (id, false)
            }
            None if o.status != "up" => continue,
            None => (Uuid::new_v4(), true),
        };
        let ports = o
            .open_ports
            .iter()
            .map(|&v| i32::from(v))
            .collect::<Vec<_>>();
        sqlx::query("INSERT INTO network_assets(id,organization_id,site_id,collector_id,identity_key,ip,mac,hostname,vendor,device_type,status,open_ports,collected_at,received_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now()) ON CONFLICT(id) DO UPDATE SET collector_id=excluded.collector_id,identity_key=excluded.identity_key,ip=excluded.ip,mac=excluded.mac,hostname=excluded.hostname,vendor=excluded.vendor,device_type=excluded.device_type,status=excluded.status,open_ports=excluded.open_ports,collected_at=excluded.collected_at,received_at=now()")
            .bind(id).bind(org).bind(site).bind(collector).bind(&key).bind(&o.ip).bind((!o.mac.is_empty()).then_some(&o.mac)).bind(&o.hostname).bind(&o.vendor).bind(&o.device_type).bind(&o.status).bind(ports).bind(o.collected_at).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO network_observations(asset_id,collector_id,collected_at,observation) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(id).bind(collector).bind(o.collected_at).bind(serde_json::to_value(&o).map_err(anyhow::Error::from)?).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM network_observations WHERE asset_id=$1 AND id NOT IN (SELECT id FROM network_observations WHERE asset_id=$1 ORDER BY collected_at DESC,id DESC LIMIT 100)")
            .bind(id).execute(&mut *tx).await?;
        if is_new {
            created += 1;
        } else {
            updated += 1;
        }
    }
    sqlx::query("UPDATE network_collectors SET inventory_at=now() WHERE id=$1")
        .bind(collector)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"received":batch.devices.len(),"created":created,"updated":updated,"errors":[]}),
    ))
}

#[derive(Deserialize)]
pub struct Heartbeat {
    cidr: String,
    #[serde(default)]
    version: String,
}
pub async fn heartbeat(
    State(state): State<Shared>,
    crate::client_ip::ClientIp(ip): crate::client_ip::ClientIp,
    headers: HeaderMap,
    Json(h): Json<Heartbeat>,
) -> AppResult<Json<serde_json::Value>> {
    let mut tx = state.db.begin().await?;
    let (id, _, _, range) = authenticate_counted(&state, &ip, &mut tx, &headers).await?;
    let reported = NetworkRange::parse(&h.cidr).map_err(|e| AppError::BadRequest(e.into()))?;
    if reported.canonical() != range.canonical() {
        return Err(AppError::BadRequest(
            "The reported range differs from this collector's registered range.".into(),
        ));
    }
    if h.version.len() > 80 || h.version.chars().any(char::is_control) {
        return Err(AppError::BadRequest("Invalid collector version.".into()));
    }
    sqlx::query("UPDATE network_collectors SET heartbeat_at=now(),version=$2 WHERE id=$1")
        .bind(id)
        .bind(h.version)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"ok"})))
}

pub async fn open_interface(
    State(state): State<Shared>,
    WebUser(p): WebUser,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Response {
    page(&p, async {
        let form = Form::parse(&body);
        check_csrf(&p, &form)?;
        p.require(Permission::RunDiagnostics)?;
        p.require(Permission::ViewDevices)?;

        let (all, orgs) = p.scope();
        let mut tx = state.db.begin().await?;
        let (org, site, collector): (Uuid, Uuid, Uuid) = sqlx::query_as(
            "SELECT organization_id, site_id, collector_id FROM network_assets
             WHERE id=$1 AND ($2 OR organization_id=ANY($3))",
        )
        .bind(id)
        .bind(all)
        .bind(orgs)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;

        let invalid_port = || AppError::BadRequest("Choose a discovered web port.".into());
        let port = form
            .get("port")
            .and_then(|port| port.parse::<u16>().ok())
            .filter(|port| web_port(*port))
            .ok_or_else(invalid_port)?;
        auth::recheck_actor(&mut tx, &p, Some(org), false).await?;

        let stale = || AppError::Conflict(
            "A recent reachable observation from an active collector is required. Refresh inventory before opening this address.".into(),
        );
        // Ingest locks its collector before the site. Use the same order and reread
        // the asset under the site lock in case another collector updated it.
        let fingerprint: Option<String> = sqlx::query_scalar(
            "SELECT portglass_fingerprint FROM network_collectors
             WHERE id=$1 AND site_id=$2 AND organization_id=$3 AND revoked_at IS NULL FOR SHARE",
        )
        .bind(collector)
        .bind(site)
        .bind(org)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(stale)?;
        sqlx::query("SELECT id FROM sites WHERE id=$1 FOR SHARE")
            .bind(site)
            .execute(&mut *tx)
            .await?;
        let asset: AssetRow = sqlx::query_as(&format!(
            "SELECT {ASSET_COLUMNS} FROM {ASSET_FROM}
             WHERE a.id=$1 AND a.site_id=$2 AND a.organization_id=$3 AND a.collector_id=$4",
        ))
        .bind(id)
        .bind(site)
        .bind(org)
        .bind(collector)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(stale)?;
        let a = asset_view(asset);
        if !a.open_ports.contains(&i32::from(port)) {
            return Err(invalid_port());
        }
        if a.status != "up" || !fresh(a.collected_at, OffsetDateTime::now_utc(), a.interval_secs) {
            return Err(stale());
        }
        let fingerprint = fingerprint.ok_or_else(|| {
            AppError::BadRequest("Configure this collector's PortGlass probe fingerprint first.".into())
        })?;
        let conflict: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM network_assets
             WHERE site_id=$1 AND ip=$2 AND id<>$3 AND status='up' AND collected_at >= $4)",
        )
        .bind(site)
        .bind(&a.ip)
        .bind(id)
        .bind(a.collected_at)
        .fetch_one(&mut *tx)
        .await?;
        if conflict {
            return Err(AppError::Conflict("This address was reported for another asset. Refresh inventory and confirm the device before opening it.".into()));
        }
        let target = format!("{}:{port}", a.ip);
        let scheme = if matches!(port, 443 | 8443) { "https" } else { "http" };
        let uri = format!("portglass://connect?fingerprint={fingerprint}&target={target}&scheme={scheme}");
        Audit::user(&p, "network.access_requested")
            .org(org)
            .target("network_asset", id)
            .detail(json!({"collector_id":collector,"target":target,"probe_fingerprint":fingerprint,"outcome":"handoff_only"}))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        html(flyw8t_web::network_launch_page(&ctx(&p, None), a, &uri, &target))
    })
    .await
}
