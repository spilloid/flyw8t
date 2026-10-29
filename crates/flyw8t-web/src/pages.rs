use crate::fmt;
use crate::model::*;
use flyw8t_domain::finding::{freshness, Freshness};
use flyw8t_domain::job::{outcome, ExecState, Tone, ALL_STATES};
use flyw8t_protocol::CATALOG;
use leptos::prelude::*;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Overview,
    Devices,
    Organizations,
    Jobs,
    Audit,
    Admin,
}

fn render(view: impl IntoView + 'static) -> String {
    let owner = Owner::new();
    let html = owner.with(|| view.to_html());
    format!("<!doctype html>{html}")
}

fn head(title: String, refresh: Option<u32>) -> impl IntoView {
    view! {
        <head>
            <meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width, initial-scale=1"/>
            <meta name="color-scheme" content="light dark"/>
            {refresh.map(|s| view! { <meta http-equiv="refresh" content=s.to_string()/> })}
            <title>{title}</title>
            <link rel="icon" href="/static/icon.svg" type="image/svg+xml"/>
            <link rel="stylesheet" href="/static/app.css"/>
        </head>
    }
}

/// The authenticated page frame: header, navigation, flash, content.
fn shell(
    title: &str,
    ctx: &PageCtx,
    active: Nav,
    refresh: Option<u32>,
    body: impl IntoView + 'static,
) -> String {
    let mut items = vec![
        (Nav::Overview, "/", "Overview"),
        (Nav::Devices, "/devices", "Devices"),
        (Nav::Organizations, "/organizations", "Organizations"),
        (Nav::Jobs, "/jobs", "Jobs"),
    ];
    if ctx.is_admin {
        items.push((Nav::Audit, "/audit", "Audit"));
        items.push((Nav::Admin, "/admin", "Administration"));
    }
    let nav = items
        .into_iter()
        .map(|(n, href, label)| {
            let current = (n == active).then_some("page");
            view! { <a href=href aria-current=current>{label}</a> }
        })
        .collect_view();
    let flash = ctx.flash.clone().map(|f| {
        let class = if f.ok { "flash ok" } else { "flash bad" };
        view! { <div class=class role="status">{f.message}</div> }
    });
    let user = format!("{} · {}", ctx.user_name, ctx.role);
    let csrf = ctx.csrf.clone();
    render(view! {
        <html lang="en">
            {head(format!("{title} · flyw8t"), refresh)}
            <body>
                <header class="top">
                    <a class="brand" href="/">"flyw8t"</a>
                    <nav aria-label="Main">{nav}</nav>
                    <form class="logout" method="post" action="/logout">
                        <input type="hidden" name="csrf" value=csrf/>
                        <span class="who">{user}</span>
                        <button type="submit" class="link">"Sign out"</button>
                    </form>
                </header>
                <main>
                    {flash}
                    {body}
                </main>
            </body>
        </html>
    })
}

fn badge(tone: Tone, label: &str) -> impl IntoView {
    let class = match tone {
        Tone::Succeeded => "badge good",
        Tone::Failed => "badge bad",
        Tone::Unknown => "badge unknown",
        Tone::InProgress => "badge busy",
        Tone::Neutral => "badge neutral",
    };
    view! { <span class=class>{label.to_string()}</span> }
}

fn connection_badge(c: &Connection, now: OffsetDateTime) -> impl IntoView {
    match c {
        Connection::Connected { since } => {
            let title = format!("Live connection since {}", fmt::timestamp(*since));
            view! { <span class="badge good" title=title>"Connected · live"</span> }.into_any()
        }
        Connection::Disconnected { last_seen: Some(t) } => {
            let title = format!("Last authenticated message {}", fmt::timestamp(*t));
            let label = format!("Offline · seen {}", fmt::ago(now, *t));
            view! { <span class="badge neutral" title=title>{label}</span> }.into_any()
        }
        Connection::Disconnected { last_seen: None } | Connection::NeverConnected => {
            view! { <span class="badge neutral">"Never connected"</span> }.into_any()
        }
    }
}

fn time_cell(now: OffsetDateTime, t: OffsetDateTime) -> impl IntoView {
    view! { <time datetime=fmt::iso(t) title=fmt::timestamp(t)>{fmt::ago(now, t)}</time> }
}

fn opt_time(now: OffsetDateTime, t: Option<OffsetDateTime>) -> impl IntoView {
    match t {
        Some(t) => time_cell(now, t).into_any(),
        None => view! { <span class="muted">"—"</span> }.into_any(),
    }
}

fn job_table(rows: Vec<JobRow>, now: OffsetDateTime, show_device: bool) -> impl IntoView {
    if rows.is_empty() {
        return view! { <p class="empty">"No jobs yet."</p> }.into_any();
    }
    let body = rows
        .into_iter()
        .map(|j| {
            let o = outcome(j.state, j.verification);
            let href = format!("/jobs/{}", j.id);
            let device = show_device.then(|| {
                let dhref = format!("/devices/{}", j.device_id);
                view! { <td data-label="Device"><a href=dhref>{j.hostname.clone()}</a></td> }
            });
            view! {
                <tr>
                    <td data-label="Job"><a href=href class="mono">{fmt::short_id(j.id)}</a></td>
                    {device}
                    <td data-label="Action"><span class="mono">{j.action.clone()}</span>" "<span class="muted">{j.params.clone()}</span></td>
                    <td data-label="Outcome">{badge(o.tone, o.label)}</td>
                    <td data-label="Requested">{time_cell(now, j.created_at)}" · "{j.requested_by.clone()}</td>
                </tr>
            }
        })
        .collect_view();
    let device_head = show_device.then(|| view! { <th scope="col">"Device"</th> });
    view! {
        <table class="list">
            <thead><tr><th scope="col">"Job"</th>{device_head}<th scope="col">"Action"</th><th scope="col">"Outcome"</th><th scope="col">"Requested"</th></tr></thead>
            <tbody>{body}</tbody>
        </table>
    }
    .into_any()
}

// ---------------------------------------------------------------------------------------

pub fn login_page(error: Option<String>, no_admin: bool, csrf_ok_hint: Option<String>) -> String {
    let note = no_admin.then(|| {
        view! {
            <p class="flash bad">
                "No administrator account exists yet. Set FLYW8T_BOOTSTRAP_ADMIN_EMAIL and FLYW8T_BOOTSTRAP_ADMIN_PASSWORD and restart the server."
            </p>
        }
    });
    let err = error.map(|e| view! { <p class="flash bad" role="alert">{e}</p> });
    let hint = csrf_ok_hint.map(|h| view! { <p class="muted">{h}</p> });
    render(view! {
        <html lang="en">
            {head("Sign in · flyw8t".into(), None)}
            <body class="login">
                <main class="card narrow">
                    <h1>"flyw8t"</h1>
                    <p class="muted">"Lightweight agents. Heavyweight control."</p>
                    {note}
                    {err}
                    <form method="post" action="/login" class="stack">
                        <label>"Email"<input type="email" name="email" autocomplete="username" required=true autofocus=true/></label>
                        <label>"Password"<input type="password" name="password" autocomplete="current-password" required=true/></label>
                        <button type="submit">"Sign in"</button>
                    </form>
                    {hint}
                </main>
            </body>
        </html>
    })
}

pub fn overview_page(ctx: &PageCtx, o: Overview) -> String {
    let now = ctx.now;
    let attention = (!o.attention.is_empty()).then(|| {
        let rows = o.attention.clone();
        view! {
            <section>
                <h2>"Needs attention"</h2>
                <p class="muted">"Jobs whose outcome could not be proven, or that failed, in the last 24 hours."</p>
                {job_table(rows, now, true)}
            </section>
        }
    });
    let body = view! {
        <h1>"Overview"</h1>
        <div class="tiles">
            <a class="tile" href="/devices?connection=connected"><span class="num">{o.devices_connected}</span>" of "{o.devices_total}" devices connected now"</a>
            <a class="tile" href="/jobs?state=running"><span class="num">{o.jobs_in_flight}</span>" queued or running"</a>
            <a class="tile" href="/jobs?state=completed"><span class="num">{o.jobs_succeeded_24h}</span>" verified successes (24 h)"</a>
            <a class="tile bad" href="/jobs?state=failed"><span class="num">{o.jobs_failed_24h}</span>" failed (24 h)"</a>
            <a class="tile unknown" href="/jobs?state=outcome_unknown"><span class="num">{o.jobs_unknown}</span>" outcome unknown"</a>
        </div>
        {attention}
        <section>
            <h2>"Recent jobs"</h2>
            {job_table(o.recent, now, true)}
        </section>
    };
    shell("Overview", ctx, Nav::Overview, Some(30), body)
}

pub fn devices_page(
    ctx: &PageCtx,
    rows: Vec<DeviceRow>,
    filter: DeviceFilter,
    orgs: Vec<OrgRef>,
) -> String {
    let now = ctx.now;
    let org_options = orgs
        .into_iter()
        .map(|o| {
            let selected = filter.organization == Some(o.id);
            view! { <option value=o.id.to_string() selected=selected>{o.name}</option> }
        })
        .collect_view();
    let conn_options = [
        ("", "Any connection"),
        ("connected", "Connected now"),
        ("offline", "Not connected"),
    ]
    .into_iter()
    .map(|(v, l)| {
        let selected = filter.connection == v;
        view! { <option value=v selected=selected>{l}</option> }
    })
    .collect_view();
    let count = rows.len();
    let table = if rows.is_empty() {
        view! { <p class="empty">"No devices match. Enroll one from an organization's page."</p> }
            .into_any()
    } else {
        let body = rows
            .into_iter()
            .map(|d| {
                let href = format!("/devices/{}", d.id);
                let retired = d.retired.then(|| view! { " " <span class="badge neutral">"retired"</span> });
                view! {
                    <tr>
                        <td data-label="Device"><a href=href><strong>{d.hostname.clone()}</strong></a>{retired}</td>
                        <td data-label="Organization">{d.organization.name.clone()}{d.site.clone().map(|s| format!(" / {s}"))}</td>
                        <td data-label="Connection">{connection_badge(&d.connection, now)}</td>
                        <td data-label="OS">{d.os.clone().unwrap_or_else(|| "—".into())}</td>
                        <td data-label="Agent" class="mono">{d.agent_version.clone().unwrap_or_else(|| "—".into())}</td>
                    </tr>
                }
            })
            .collect_view();
        view! {
            <table class="list">
                <thead><tr><th scope="col">"Device"</th><th scope="col">"Organization"</th><th scope="col">"Connection"</th><th scope="col">"OS"</th><th scope="col">"Agent"</th></tr></thead>
                <tbody>{body}</tbody>
            </table>
        }
        .into_any()
    };
    let body = view! {
        <h1>"Devices"</h1>
        <form method="get" action="/devices" class="filters" role="search">
            <input type="search" name="q" value=filter.q.clone() placeholder="Search hostname" aria-label="Search hostname" accesskey="s" autofocus=true/>
            <select name="org" aria-label="Organization"><option value="">"All organizations"</option>{org_options}</select>
            <select name="connection" aria-label="Connection">{conn_options}</select>
            <button type="submit">"Filter"</button>
        </form>
        <p class="muted">{format!("{count} device(s). Connection state is live; everything else is the last report the device sent.")}</p>
        {table}
    };
    shell("Devices", ctx, Nav::Devices, None, body)
}

fn inventory_section(inv: Option<InventoryView>, now: OffsetDateTime) -> impl IntoView {
    let Some(inv) = inv else {
        return view! {
            <section class="card">
                <h2>"Inventory"</h2>
                <p class="empty">"The device has not reported inventory yet."</p>
            </section>
        }
        .into_any();
    };
    let r = inv.report;
    let fresh = freshness(r.collected_at, now, Duration::hours(7), Duration::days(2));
    let fresh_badge = match fresh {
        Freshness::Fresh => view! { <span class="badge good">"Fresh"</span> }.into_any(),
        Freshness::Aging => view! { <span class="badge neutral">"Aging"</span> }.into_any(),
        Freshness::Stale => view! { <span class="badge bad">"Stale"</span> }.into_any(),
    };
    let os = [r.os.long_version.clone(), r.os.name.clone()]
        .into_iter()
        .flatten()
        .next()
        .unwrap_or_else(|| r.os.family.clone());
    let disks = r
        .disks
        .iter()
        .map(|d| {
            let used = d.total_bytes.saturating_sub(d.available_bytes);
            let pct = (used.saturating_mul(100))
                .checked_div(d.total_bytes)
                .unwrap_or(0);
            let label = format!(
                "{} ({}) — {} free of {} ({pct}% used)",
                d.mount_point,
                d.file_system,
                fmt::bytes(d.available_bytes),
                fmt::bytes(d.total_bytes)
            );
            view! { <li>{label}</li> }
        })
        .collect_view();
    let nics = r
        .network
        .iter()
        .filter(|n| !n.addresses.is_empty())
        .map(|n| {
            let label = format!(
                "{}: {}{}",
                n.name,
                n.addresses.join(", "),
                n.mac
                    .as_ref()
                    .map(|m| format!(" · {m}"))
                    .unwrap_or_default()
            );
            view! { <li>{label}</li> }
        })
        .collect_view();
    let provenance = format!(
        "Reported by the device, collected {} ({}), received {} via {}. Cached, not live.",
        fmt::timestamp(r.collected_at),
        fmt::ago(now, r.collected_at),
        fmt::timestamp(inv.received_at),
        if inv.source == "job" {
            "a system.info job"
        } else {
            "periodic inventory"
        },
    );
    view! {
        <section class="card">
            <h2>"Inventory " {fresh_badge}</h2>
            <p class="muted">{provenance}</p>
            <dl class="facts">
                <dt>"Hostname"</dt><dd>{r.hostname.clone()}</dd>
                <dt>"Operating system"</dt><dd>{os}" · "{r.os.arch.clone()}</dd>
                <dt>"Kernel"</dt><dd>{r.os.kernel_version.clone().unwrap_or_else(|| "—".into())}</dd>
                <dt>"CPU"</dt><dd>{r.hardware.cpu_model.clone().unwrap_or_else(|| "unknown".into())}{format!(" · {} logical cores", r.hardware.cpu_logical_cores)}</dd>
                <dt>"Memory"</dt><dd>{format!("{} total, {} available", fmt::bytes(r.hardware.memory_total_bytes), fmt::bytes(r.hardware.memory_available_bytes))}</dd>
                <dt>"Uptime"</dt><dd>{format!("{} (at collection)", fmt::duration_secs(r.uptime_secs))}</dd>
                <dt>"Disks"</dt><dd><ul class="plain">{disks}</ul></dd>
                <dt>"Network"</dt><dd><ul class="plain">{nics}</ul></dd>
            </dl>
        </section>
    }
    .into_any()
}

fn run_forms(
    ctx: &PageCtx,
    device_id: uuid::Uuid,
    connected: bool,
    retired: bool,
) -> impl IntoView {
    if !ctx.can_run {
        return view! { <p class="muted">"Your role cannot run diagnostics."</p> }.into_any();
    }
    if retired {
        return view! { <p class="muted">"This device is retired; it cannot run jobs."</p> }
            .into_any();
    }
    let action_url = format!("/devices/{device_id}/jobs");
    let note = if connected {
        "The device is connected; jobs are sent immediately."
    } else {
        "The device is not connected. Jobs queue until it connects or their 15-minute delivery window passes."
    };
    let forms = CATALOG
        .iter()
        .map(|a| {
            let params = a
                .params
                .iter()
                .map(|p| match *p {
                    "target" => view! { <label>"Host or IP"<input type="text" name="target" required=true maxlength="253" placeholder="8.8.8.8" pattern="[A-Za-z0-9.:\\-]+"/></label> }.into_any(),
                    "limit" => view! { <label>"How many"<input type="number" name="limit" value="15" min="1" max="50"/></label> }.into_any(),
                    _ => ().into_any(),
                })
                .collect_view();
            view! {
                <form method="post" action=action_url.clone() class="action">
                    <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                    <input type="hidden" name="action" value=a.name/>
                    <div>
                        <strong>{a.title}</strong>" "<span class="mono muted">{a.name}</span>
                        <p class="muted">{a.description}</p>
                    </div>
                    {params}
                    <button type="submit">"Run"</button>
                </form>
            }
        })
        .collect_view();
    view! {
        <p class="muted">{note}" Read-only diagnostics only."</p>
        <div class="actions">{forms}</div>
    }
    .into_any()
}

pub fn device_page(ctx: &PageCtx, d: DeviceDetail) -> String {
    let now = ctx.now;
    let connected = matches!(d.row.connection, Connection::Connected { .. });
    let conn_detail = match &d.row.connection {
        Connection::Connected { since } => format!(
            "Live authenticated connection since {} ({}).",
            fmt::timestamp(*since),
            fmt::ago(now, *since)
        ),
        Connection::Disconnected { last_seen: Some(t) } => format!(
            "Not connected. Last authenticated message {} ({}).",
            fmt::timestamp(*t),
            fmt::ago(now, *t)
        ),
        _ => "Enrolled but has never connected.".into(),
    };
    let credential = match d.credential.clone() {
        Some(c) if c.revoked_at.is_some() => format!(
            "Credential {} revoked {}.",
            c.fingerprint,
            fmt::timestamp(c.revoked_at.unwrap())
        ),
        Some(c) => format!(
            "Ed25519 key {} registered {}.",
            c.fingerprint,
            fmt::timestamp(c.created_at)
        ),
        None => "No credential on record.".into(),
    };
    let revoke = (ctx.is_admin && d.credential.as_ref().is_some_and(|c| c.revoked_at.is_none())).then(|| {
        let url = format!("/devices/{}/revoke", d.row.id);
        view! {
            <form method="post" action=url class="danger">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label class="inline"><input type="checkbox" name="confirm" value="yes" required=true/>" I understand this disconnects the device permanently; it must be re-enrolled."</label>
                <button type="submit" class="bad">"Revoke device credential"</button>
            </form>
        }
    });
    let title = d.row.hostname.clone();
    let org_line = format!(
        "{}{}",
        d.row.organization.name,
        d.row
            .site
            .clone()
            .map(|s| format!(" / {s}"))
            .unwrap_or_default()
    );
    let body = view! {
        <p class="crumbs"><a href="/devices">"Devices"</a>" / "</p>
        <h1>{d.row.hostname.clone()}" "{connection_badge(&d.row.connection, now)}</h1>
        <div class="grid">
            <section class="card">
                <h2>"Identity"</h2>
                <dl class="facts">
                    <dt>"Organization"</dt><dd>{org_line}</dd>
                    <dt>"Connection"</dt><dd>{conn_detail}</dd>
                    <dt>"Enrolled"</dt><dd>{fmt::timestamp(d.enrolled_at)}</dd>
                    <dt>"Agent"</dt><dd class="mono">{d.row.agent_version.clone().unwrap_or_else(|| "—".into())}</dd>
                    <dt>"Credential"</dt><dd>{credential}</dd>
                    <dt>"Remote access"</dt><dd>{d.remote_access.clone()}</dd>
                    <dt>"Device ID"</dt><dd class="mono">{d.row.id.to_string()}</dd>
                </dl>
                {revoke}
            </section>
            {inventory_section(d.inventory.clone(), now)}
        </div>
        <section class="card">
            <h2>"Run a diagnostic"</h2>
            {run_forms(ctx, d.row.id, connected, d.row.retired)}
        </section>
        <section>
            <h2>"Job history"</h2>
            {job_table(d.recent_jobs.clone(), now, false)}
        </section>
    };
    shell(&title, ctx, Nav::Devices, None, body)
}

pub fn jobs_page(ctx: &PageCtx, rows: Vec<JobRow>, state: Option<ExecState>) -> String {
    let now = ctx.now;
    let options = ALL_STATES
        .into_iter()
        .map(|s| {
            let selected = state == Some(s);
            view! { <option value=s.as_str() selected=selected>{s.as_str().replace('_', " ")}</option> }
        })
        .collect_view();
    let body = view! {
        <h1>"Jobs"</h1>
        <form method="get" action="/jobs" class="filters">
            <select name="state" aria-label="Execution state"><option value="">"Any state"</option>{options}</select>
            <button type="submit">"Filter"</button>
        </form>
        {job_table(rows, now, true)}
    };
    shell("Jobs", ctx, Nav::Jobs, None, body)
}

fn stream_block(label: &'static str, s: Option<StreamView>) -> impl IntoView {
    s.filter(|s| !s.data.is_empty() || s.truncated).map(|s| {
        let trunc = s.truncated.then(
            || view! { <p class="muted">"Truncated: the device kept the first 256 KiB."</p> },
        );
        view! {
            <h3>{label}</h3>
            {trunc}
            <pre class="output">{s.data}</pre>
        }
    })
}

pub fn job_page(ctx: &PageCtx, j: JobDetail, can_cancel: bool) -> String {
    let now = ctx.now;
    let o = outcome(j.row.state, j.row.verification);
    let in_progress = !j.row.state.is_terminal() && j.row.state != ExecState::OutcomeUnknown;
    let refresh = in_progress.then_some(2);
    let cancel = (can_cancel && in_progress && j.cancel_requested_at.is_none()).then(|| {
        let url = format!("/jobs/{}/cancel", j.row.id);
        let note = if j.row.state.is_pre_dispatch() {
            "Not sent yet: cancelling guarantees it will not run."
        } else {
            "Already sent: the device will be asked to stop. It may finish first; the result will say which."
        };
        view! {
            <form method="post" action=url class="inline-form">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <button type="submit" class="bad">"Cancel job"</button>
                <span class="muted">{note}</span>
            </form>
        }
    });
    let cancel_note = j.cancel_requested_at.map(|t| {
        view! { <p class="flash bad">{format!("Cancellation requested {}. Waiting for the device to confirm.", fmt::timestamp(t))}</p> }
    });
    let notes = [
        j.state_note.clone(),
        j.verification_note.clone(),
        j.error.clone(),
    ]
    .into_iter()
    .flatten()
    .map(|n| view! { <li>{n}</li> })
    .collect_view();
    let result = j.result.clone().map(|r| {
        let pretty = serde_json::to_string_pretty(&r).unwrap_or_default();
        view! { <h3>"Structured result"</h3><pre class="output">{pretty}</pre> }
    });
    let exit = j
        .exit_code
        .map(|c| view! { <dt>"Exit code"</dt><dd class="mono">{c}</dd> });
    let events = j
        .events
        .iter()
        .map(|e| {
            let transition = match (&e.from_state, &e.to_state) {
                (Some(f), Some(t)) => format!("{f} → {t}"),
                (None, Some(t)) => format!("→ {t}"),
                _ => String::new(),
            };
            let detail = if e.detail.as_object().is_some_and(|o| o.is_empty()) { String::new() } else { e.detail.to_string() };
            view! {
                <li>
                    <time datetime=fmt::iso(e.at)>{fmt::timestamp(e.at)}</time>
                    " "<strong>{e.kind.clone()}</strong>" "<span class="mono">{transition}</span>
                    " "<span class="muted">{format!("by {}", e.actor)}</span>
                    {(!detail.is_empty()).then(|| view! { <div class="mono small">{detail.clone()}</div> })}
                </li>
            }
        })
        .collect_view();
    let device_href = format!("/devices/{}", j.row.device_id);
    let title = format!("Job {}", fmt::short_id(j.row.id));
    let body = view! {
        <p class="crumbs"><a href="/jobs">"Jobs"</a>" / "</p>
        <h1>{title.clone()}" "{badge(o.tone, o.label)}</h1>
        <p class="lead">{o.explanation}</p>
        {cancel_note}
        {cancel}
        <div class="grid">
            <section class="card">
                <h2>"Request"</h2>
                <dl class="facts">
                    <dt>"Device"</dt><dd><a href=device_href>{j.row.hostname.clone()}</a>{format!(" · {}", j.row.organization.name)}</dd>
                    <dt>"Action"</dt><dd><span class="mono">{j.row.action.clone()}</span>" "<span class="muted">{j.row.params.clone()}</span></dd>
                    <dt>"Requested by"</dt><dd>{format!("{} via {}", j.row.requested_by, j.request_channel)}</dd>
                    <dt>"Created"</dt><dd>{fmt::timestamp(j.row.created_at)}</dd>
                    <dt>"Time limit"</dt><dd>{format!("{} s on the device", j.timeout_secs)}</dd>
                    <dt>"Deliver by"</dt><dd>{fmt::timestamp(j.deliver_by)}</dd>
                    <dt>"Deliveries"</dt><dd>{j.dispatch_count}</dd>
                    <dt>"Success means"</dt><dd>{j.success_contract.clone()}</dd>
                </dl>
            </section>
            <section class="card">
                <h2>"Outcome"</h2>
                <dl class="facts">
                    <dt>"Execution"</dt><dd class="mono">{j.row.state.as_str()}</dd>
                    <dt>"Verification"</dt><dd class="mono">{j.row.verification.as_str()}</dd>
                    <dt>"Device accepted"</dt><dd>{opt_time(now, j.acknowledged_at)}</dd>
                    <dt>"Started (device clock)"</dt><dd>{j.started_at.map(fmt::timestamp).unwrap_or_else(|| "—".into())}</dd>
                    <dt>"Finished (device clock)"</dt><dd>{j.finished_at.map(fmt::timestamp).unwrap_or_else(|| "—".into())}</dd>
                    {exit}
                </dl>
                <ul class="notes">{notes}</ul>
            </section>
        </div>
        <section class="card">
            <h2>"Output"</h2>
            {stream_block("Standard output", j.stdout.clone())}
            {stream_block("Standard error", j.stderr.clone())}
            {result}
            {(j.stdout.is_none() && j.stderr.is_none() && j.result.is_none()).then(|| view! { <p class="empty">"No output received."</p> })}
        </section>
        <section class="card">
            <h2>"Lifecycle"</h2>
            <p class="muted">"Append-only. Every transition and every report the device sent, including duplicates."</p>
            <ol class="timeline">{events}</ol>
        </section>
    };
    shell(&title, ctx, Nav::Jobs, refresh, body)
}

pub fn organizations_page(ctx: &PageCtx, orgs: Vec<OrgSummary>) -> String {
    let create = ctx.is_admin.then(|| {
        view! {
            <form method="post" action="/organizations" class="inline-form card">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"New organization"<input type="text" name="name" required=true maxlength="200"/></label>
                <button type="submit">"Create"</button>
            </form>
        }
    });
    let list = if orgs.is_empty() {
        view! { <p class="empty">"No organizations yet."</p> }.into_any()
    } else {
        let rows = orgs
            .into_iter()
            .map(|o| {
                let href = format!("/organizations/{}", o.id);
                let sites = o.sites.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(", ");
                view! {
                    <tr>
                        <td data-label="Organization"><a href=href><strong>{o.name}</strong></a></td>
                        <td data-label="Sites">{sites}</td>
                        <td data-label="Devices">{o.device_count}</td>
                    </tr>
                }
            })
            .collect_view();
        view! {
            <table class="list">
                <thead><tr><th scope="col">"Organization"</th><th scope="col">"Sites"</th><th scope="col">"Devices"</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        }
        .into_any()
    };
    let body = view! {
        <h1>"Organizations"</h1>
        {create}
        {list}
    };
    shell("Organizations", ctx, Nav::Organizations, None, body)
}

fn revealed_box(r: RevealedSecret) -> impl IntoView {
    view! {
        <section class="card reveal" role="alert">
            <h2>{r.label}</h2>
            <p><strong>"Copy it now. It is shown once and only its hash is stored."</strong></p>
            <pre class="output secret">{r.secret}</pre>
            <p class="muted">{r.hint}</p>
        </section>
    }
}

pub fn organization_page(
    ctx: &PageCtx,
    org: OrgSummary,
    tokens: Vec<EnrollmentTokenView>,
    revealed: Option<RevealedSecret>,
) -> String {
    let now = ctx.now;
    let id = org.id;
    let add_site = ctx.is_admin.then(|| {
        let url = format!("/organizations/{id}/sites");
        view! {
            <form method="post" action=url class="inline-form">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"Add site"<input type="text" name="name" required=true maxlength="200"/></label>
                <button type="submit">"Add"</button>
            </form>
        }
    });
    let enroll_form = ctx.can_enroll.then(|| {
        let url = format!("/organizations/{id}/enrollment-tokens");
        let site_opts = org
            .sites
            .iter()
            .map(|s| view! { <option value=s.id.to_string()>{s.name.clone()}</option> })
            .collect_view();
        view! {
            <form method="post" action=url class="inline-form">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"Site"<select name="site"><option value="">"(none)"</option>{site_opts}</select></label>
                <label>"Valid for"<select name="ttl_minutes">
                    <option value="15">"15 minutes"</option>
                    <option value="60" selected=true>"1 hour"</option>
                    <option value="480">"8 hours"</option>
                    <option value="1440">"24 hours"</option>
                </select></label>
                <label>"Devices"<input type="number" name="max_uses" value="1" min="1" max="100"/></label>
                <button type="submit">"Create enrollment token"</button>
            </form>
        }
    });
    let token_rows = tokens
        .into_iter()
        .map(|t| {
            let status = if t.revoked {
                "revoked".to_string()
            } else if t.expires_at <= now {
                "expired".to_string()
            } else if t.uses >= t.max_uses {
                "used up".to_string()
            } else {
                format!("active, expires {}", fmt::ago(now, t.expires_at).replace(" ago", "").replace("in the future (clock skew)", "soon"))
            };
            let revoke = (!t.revoked && t.expires_at > now && t.uses < t.max_uses && ctx.can_enroll).then(|| {
                let url = format!("/organizations/{id}/enrollment-tokens/{}/revoke", t.id);
                view! {
                    <form method="post" action=url class="inline-form">
                        <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                        <button type="submit" class="link">"Revoke"</button>
                    </form>
                }
            });
            view! {
                <tr>
                    <td data-label="Created">{time_cell(now, t.created_at)}" · "{t.created_by.clone()}</td>
                    <td data-label="Site">{t.site.clone().unwrap_or_else(|| "—".into())}</td>
                    <td data-label="Uses">{format!("{} / {}", t.uses, t.max_uses)}</td>
                    <td data-label="Status">{status}{revoke}</td>
                </tr>
            }
        })
        .collect_view();
    let sites = org
        .sites
        .iter()
        .map(|s| view! { <li>{s.name.clone()}</li> })
        .collect_view();
    let devices_href = format!("/devices?org={id}");
    let body = view! {
        <p class="crumbs"><a href="/organizations">"Organizations"</a>" / "</p>
        <h1>{org.name.clone()}</h1>
        {revealed.map(revealed_box)}
        <div class="grid">
            <section class="card">
                <h2>"Sites"</h2>
                <ul class="plain">{sites}</ul>
                {add_site}
                <p><a href=devices_href>{format!("{} device(s) →", org.device_count)}</a></p>
            </section>
            <section class="card">
                <h2>"Enroll a device"</h2>
                <p class="muted">"Enrollment tokens are short-lived and single-purpose. The device's organization comes from the token, never from the device."</p>
                {enroll_form}
            </section>
        </div>
        <section>
            <h2>"Enrollment tokens"</h2>
            <table class="list">
                <thead><tr><th scope="col">"Created"</th><th scope="col">"Site"</th><th scope="col">"Uses"</th><th scope="col">"Status"</th></tr></thead>
                <tbody>{token_rows}</tbody>
            </table>
        </section>
    };
    shell(&org.name, ctx, Nav::Organizations, None, body)
}

pub fn audit_page(ctx: &PageCtx, rows: Vec<AuditRow>) -> String {
    let now = ctx.now;
    let body_rows = rows
        .into_iter()
        .map(|a| {
            let class = match a.outcome.as_str() {
                "success" => "badge good",
                "denied" => "badge bad",
                _ => "badge unknown",
            };
            let target = match (&a.target_type, a.target_id) {
                (Some(t), Some(id)) => format!("{t} {}", fmt::short_id(id)),
                (Some(t), None) => t.clone(),
                _ => String::new(),
            };
            let detail = if a.detail.as_object().is_some_and(|o| o.is_empty()) { String::new() } else { a.detail.to_string() };
            view! {
                <tr>
                    <td data-label="When">{time_cell(now, a.at)}</td>
                    <td data-label="Actor">{a.actor_label.clone()}<span class="muted">{format!(" via {}", a.channel)}</span></td>
                    <td data-label="Action" class="mono">{a.action.clone()}</td>
                    <td data-label="Target" class="mono">{target}</td>
                    <td data-label="Result"><span class=class>{a.outcome.clone()}</span></td>
                    <td data-label="Detail" class="mono small">{a.organization.clone().map(|o| format!("[{o}] "))}{detail}</td>
                </tr>
            }
        })
        .collect_view();
    let body = view! {
        <h1>"Audit"</h1>
        <p class="muted">"Append-only; the database rejects updates and deletes on this table. Newest 200 shown."</p>
        <table class="list">
            <thead><tr><th scope="col">"When"</th><th scope="col">"Actor"</th><th scope="col">"Action"</th><th scope="col">"Target"</th><th scope="col">"Result"</th><th scope="col">"Detail"</th></tr></thead>
            <tbody>{body_rows}</tbody>
        </table>
    };
    shell("Audit", ctx, Nav::Audit, None, body)
}

pub fn admin_page(
    ctx: &PageCtx,
    users: Vec<UserRow>,
    tokens: Vec<ApiTokenRow>,
    orgs: Vec<OrgRef>,
    revealed: Option<RevealedSecret>,
) -> String {
    let now = ctx.now;
    let user_rows = users
        .into_iter()
        .map(|u| {
            view! {
                <tr>
                    <td data-label="User">{u.display_name.clone()}<div class="muted">{u.email.clone()}</div></td>
                    <td data-label="Role">{u.role.clone()}{u.disabled.then_some(" (disabled)")}</td>
                    <td data-label="Organizations">{if u.role == "admin" { "all".to_string() } else { u.organizations.join(", ") }}</td>
                </tr>
            }
        })
        .collect_view();
    let org_checks = orgs
        .iter()
        .map(|o| view! { <label class="inline"><input type="checkbox" name="org" value=o.id.to_string()/>{o.name.clone()}</label> })
        .collect_view();
    let token_rows = tokens
        .into_iter()
        .map(|t| {
            let revoke = (!t.revoked).then(|| {
                let url = format!("/admin/tokens/{}/revoke", t.id);
                view! {
                    <form method="post" action=url class="inline-form">
                        <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                        <button type="submit" class="link">"Revoke"</button>
                    </form>
                }
            });
            view! {
                <tr>
                    <td data-label="Token">{t.name.clone()}<div class="mono muted">{format!("fw8_{}…", t.prefix)}</div></td>
                    <td data-label="Owner">{t.owner.clone()}</td>
                    <td data-label="Scopes" class="mono">{t.scopes.join(" ")}</td>
                    <td data-label="Last used">{opt_time(now, t.last_used_at)}</td>
                    <td data-label="Status">{if t.revoked { "revoked" } else { "active" }}{revoke}</td>
                </tr>
            }
        })
        .collect_view();
    let body = view! {
        <h1>"Administration"</h1>
        {revealed.map(revealed_box)}
        <section>
            <h2>"Users"</h2>
            <table class="list">
                <thead><tr><th scope="col">"User"</th><th scope="col">"Role"</th><th scope="col">"Organizations"</th></tr></thead>
                <tbody>{user_rows}</tbody>
            </table>
            <form method="post" action="/admin/users" class="card stack">
                <h3>"Add user"</h3>
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"Email"<input type="email" name="email" required=true/></label>
                <label>"Name"<input type="text" name="display_name" required=true maxlength="200"/></label>
                <label>"Initial password (12+ characters)"<input type="password" name="password" required=true minlength="12" autocomplete="new-password"/></label>
                <label>"Role"<select name="role">
                    <option value="technician">"Technician — view and run diagnostics in assigned organizations"</option>
                    <option value="readonly">"Read-only — view assigned organizations"</option>
                    <option value="admin">"Administrator — everything, every organization"</option>
                </select></label>
                <fieldset><legend>"Organizations (ignored for administrators)"</legend>{org_checks}</fieldset>
                <button type="submit">"Create user"</button>
            </form>
        </section>
        <section>
            <h2>"API tokens"</h2>
            <p class="muted">"For integrations such as AnchorDesk. A token acts as the user who created it, never with more access than that user; its scopes can only narrow it."</p>
            <table class="list">
                <thead><tr><th scope="col">"Token"</th><th scope="col">"Owner"</th><th scope="col">"Scopes"</th><th scope="col">"Last used"</th><th scope="col">"Status"</th></tr></thead>
                <tbody>{token_rows}</tbody>
            </table>
            <form method="post" action="/admin/tokens" class="inline-form card">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"Name"<input type="text" name="name" required=true maxlength="100" placeholder="AnchorDesk"/></label>
                <label class="inline"><input type="checkbox" name="scope" value="read" checked=true/>" read"</label>
                <label class="inline"><input type="checkbox" name="scope" value="jobs:run"/>" jobs:run"</label>
                <label>"Expires in"<select name="ttl_days">
                    <option value="30">"30 days"</option>
                    <option value="90" selected=true>"90 days"</option>
                    <option value="365">"1 year"</option>
                </select></label>
                <button type="submit">"Create token"</button>
            </form>
        </section>
    };
    shell("Administration", ctx, Nav::Admin, None, body)
}

pub fn error_page(ctx: Option<&PageCtx>, status: u16, message: &str) -> String {
    let title = match status {
        403 => "Not allowed",
        404 => "Not found",
        400 | 422 => "Request rejected",
        409 => "Conflict",
        429 => "Slow down",
        _ => "Something went wrong",
    };
    let msg = message.to_string();
    match ctx {
        Some(ctx) => shell(
            title,
            ctx,
            Nav::Overview,
            None,
            view! { <h1>{title}</h1><p class="lead">{msg}</p><p><a href="/">"Back to overview"</a></p> },
        ),
        None => render(view! {
            <html lang="en">
                {head(format!("{title} · flyw8t"), None)}
                <body class="login"><main class="card narrow"><h1>{title}</h1><p>{msg}</p><p><a href="/login">"Sign in"</a></p></main></body>
            </html>
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flyw8t_domain::job::Verification;
    use uuid::Uuid;

    fn ctx() -> PageCtx {
        PageCtx {
            user_name: "Ada <script>".into(),
            role: "admin",
            csrf: "tok\"en".into(),
            now: OffsetDateTime::UNIX_EPOCH + Duration::days(1),
            can_run: true,
            is_admin: true,
            can_enroll: true,
            flash: None,
        }
    }

    fn job(state: ExecState, v: Verification) -> JobRow {
        JobRow {
            id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            hostname: "<img src=x>".into(),
            organization: OrgRef {
                id: Uuid::from_u128(3),
                name: "Org".into(),
            },
            action: "net.ping".into(),
            params: "target=1.1.1.1".into(),
            state,
            verification: v,
            requested_by: "ada@example.com".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            terminal_at: None,
        }
    }

    #[test]
    fn pages_escape_untrusted_text() {
        let html = jobs_page(
            &ctx(),
            vec![job(ExecState::Queued, Verification::Pending)],
            None,
        );
        assert!(
            !html.contains("<img src=x>"),
            "device-reported hostname must be escaped"
        );
        assert!(!html.contains("Ada <script>"));
        assert!(html.contains("&lt;img src=x&gt;"));
        assert!(html.starts_with("<!doctype html>"));
    }

    #[test]
    fn only_verified_completion_shows_succeeded() {
        let html = jobs_page(
            &ctx(),
            vec![job(ExecState::Completed, Verification::Failed)],
            None,
        );
        assert!(html.contains("Verification failed"));
        assert!(!html.contains(">Succeeded<"));
        let html = jobs_page(
            &ctx(),
            vec![job(ExecState::Dispatched, Verification::Pending)],
            None,
        );
        assert!(html.contains(">Sent<"));
    }

    #[test]
    fn readonly_users_get_no_admin_navigation() {
        let mut c = ctx();
        c.is_admin = false;
        let html = jobs_page(&c, vec![], None);
        assert!(!html.contains("href=\"/admin\""));
        assert!(!html.contains("href=\"/audit\""));
    }
}
