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
    Network,
    Organizations,
    Jobs,
    Scripts,
    Support,
    Audit,
    Admin,
    /// The signed-in user's own settings; reached from the name in the header.
    Account,
}

/// Text for inside a `<textarea>`. Leptos writes a textarea's children without escaping them, so this escapes `&` and
/// `<` itself (enough inside a textarea; the browser decodes them back), so the text can never close the element and
/// become markup. HTML also drops one newline right after the opening tag, so one is added for it to drop.
fn textarea_text(s: &str) -> String {
    format!("\n{}", s.replace('&', "&amp;").replace('<', "&lt;"))
}

fn render(view: impl IntoView + 'static) -> String {
    let owner = Owner::new();
    let html = owner.with(|| view.to_html());
    format!("<!doctype html>{html}")
}

fn head(title: String, refresh: Option<u32>, script: Option<&'static str>) -> impl IntoView {
    view! {
        <head>
            <meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width, initial-scale=1"/>
            <meta name="color-scheme" content="light dark"/>
            {refresh.map(|s| view! { <meta http-equiv="refresh" content=s.to_string()/> })}
            <title>{title}</title>
            <link rel="icon" href="/static/icon.svg" type="image/svg+xml"/>
            <link rel="manifest" href="/manifest.webmanifest"/>
            <link rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png"/>
            <meta name="theme-color" content="#2456c7"/>
            <meta name="mobile-web-app-capable" content="yes"/>
            <meta name="apple-mobile-web-app-title" content="flyw8t"/>
            <link rel="stylesheet" href="/static/app.css"/>
            {script.map(|src| view! { <script src=src defer=true></script> })}
        </head>
    }
}

pub(crate) fn shell(
    title: &str,
    ctx: &PageCtx,
    active: Nav,
    refresh: Option<u32>,
    body: impl IntoView + 'static,
) -> String {
    shell_with(title, ctx, active, refresh, None, body)
}

/// The authenticated page frame: header, navigation, flash, content. `script` loads a page script: the attended-support
/// one (ADR-0010) or the script editor's (ADR-0014), the only two in the console.
fn shell_with(
    title: &str,
    ctx: &PageCtx,
    active: Nav,
    refresh: Option<u32>,
    script: Option<&'static str>,
    body: impl IntoView + 'static,
) -> String {
    // Grouped by what a technician is doing. The labels show only where the navigation is a column.
    let mut work = vec![(Nav::Jobs, "/jobs", "Jobs")];
    if ctx.can_view_scripts {
        work.push((Nav::Scripts, "/scripts", "Scripts"));
    }
    if ctx.can_support {
        work.push((Nav::Support, "/support", "Support"));
    }
    let mut groups = vec![
        (
            "Fleet",
            vec![
                (Nav::Overview, "/", "Overview"),
                (Nav::Devices, "/devices", "Devices"),
                (Nav::Network, "/network", "Network"),
                (Nav::Organizations, "/organizations", "Organizations"),
            ],
        ),
        ("Work", work),
    ];
    if ctx.is_admin {
        groups.push((
            "Control",
            vec![
                (Nav::Audit, "/audit", "Audit"),
                (Nav::Admin, "/admin", "Administration"),
            ],
        ));
    }
    let family = (!ctx.family.is_empty()).then(|| {
        let links = ctx
            .family
            .iter()
            .map(|l| view! { <a href=l.url.clone() rel="noopener noreferrer" class="family">{l.label.clone()}</a> })
            .collect_view();
        view! { <div class="navgroup"><span class="navlabel">"Products"</span>{links}</div> }
    });
    let nav = groups
        .into_iter()
        .map(|(group, items)| {
            let links = items
                .into_iter()
                .map(|(n, href, label)| {
                    let current = (n == active).then_some("page");
                    view! { <a href=href aria-current=current>{label}</a> }
                })
                .collect_view();
            view! { <div class="navgroup"><span class="navlabel">{group}</span>{links}</div> }
        })
        .collect_view();
    let version = format!("flyw8t {} · pre-release", ctx.version);
    let flash = ctx.flash.clone().map(|f| {
        let class = if f.ok { "flash ok" } else { "flash bad" };
        view! { <div class=class role="status">{f.message}</div> }
    });
    let user = format!("{} · {}", ctx.user_name, ctx.role);
    let csrf = ctx.csrf.clone();
    render(view! {
        <html lang="en">
            {head(format!("{title} · flyw8t"), refresh, script)}
            <body class="app">
                <a class="skip" href="#main">"Skip to content"</a>
                <header class="top">
                    <a class="brand" href="/"><img src="/static/icon.svg" alt="" width="24" height="24"/>"flyw8t"</a>
                    <nav aria-label="Main">{nav}{family}</nav>
                    <form class="logout" method="post" action="/logout">
                        <input type="hidden" name="csrf" value=csrf/>
                        <a class="who" href="/account" title="Your account and two-step verification">{user}</a>
                        <button type="submit" class="link">"Sign out"</button>
                    </form>
                    <p class="ver">{version}</p>
                </header>
                <main id="main">
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

pub(crate) fn time_cell(now: OffsetDateTime, t: OffsetDateTime) -> impl IntoView {
    view! { <time datetime=fmt::iso(t) title=fmt::timestamp(t)>{fmt::ago(now, t)}</time> }
}

fn opt_time(now: OffsetDateTime, t: Option<OffsetDateTime>) -> impl IntoView {
    match t {
        Some(t) => time_cell(now, t).into_any(),
        None => view! { <span class="muted">"—"</span> }.into_any(),
    }
}

/// A share in use, with its bar. Green below 75%, amber to 90%, red above.
fn usage(percent: u8, label: String, detail: String) -> impl IntoView {
    view! {
        <div class="usage">
            <span class="fig">{format!("{percent}%")}</span>
            <meter min="0" max="100" low="75" high="90" optimum="0" value=percent.to_string() aria-label=label></meter>
            <span class="muted small">{detail}</span>
        </div>
    }
}

/// Percent-encodes a query-string value.
pub(crate) fn query_value(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The device list with these filters, in `sort` order.
fn devices_href(f: &DeviceFilter, sort: &str) -> String {
    let mut q = Vec::new();
    if !f.q.is_empty() {
        q.push(format!("q={}", query_value(&f.q)));
    }
    if let Some(o) = f.organization {
        q.push(format!("org={o}"));
    }
    for (k, v) in [
        ("tag", &f.tag),
        ("connection", &f.connection),
        ("status", &f.status),
    ] {
        if !v.is_empty() {
            q.push(format!("{k}={}", query_value(v)));
        }
    }
    if f.attention {
        q.push("attention=1".into());
    }
    if !sort.is_empty() {
        q.push(format!("sort={sort}"));
    }
    if q.is_empty() {
        "/devices".into()
    } else {
        format!("/devices?{}", q.join("&"))
    }
}

fn concern_badge(c: &Concern) -> impl IntoView {
    let (class, label) = match c {
        Concern::NeverConnected => ("badge neutral", "Never connected".to_string()),
        Concern::LongOffline { days } => ("badge unknown", format!("Offline {days} d")),
        Concern::DiskNearlyFull {
            mount_point,
            used_percent,
        } => ("badge bad", format!("{mount_point} {used_percent}% full")),
        Concern::StaleInventory { days } => ("badge unknown", format!("Inventory {days} d old")),
        Concern::NoInventory { days } => {
            ("badge unknown", format!("Connected {days} d, no inventory"))
        }
    };
    view! { <li><span class=class>{label}</span></li> }
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

/// The sign-in page. `login_token` is the value of the sign-in cookie set with it (login CSRF).
pub fn login_page(error: Option<String>, no_admin: bool, login_token: &str, oidc: bool) -> String {
    let note = no_admin.then(|| {
        view! {
            <p class="flash bad">
                "No administrator account exists yet. Set FLYW8T_BOOTSTRAP_ADMIN_EMAIL and FLYW8T_BOOTSTRAP_ADMIN_PASSWORD and restart the server."
            </p>
        }
    });
    let err = error.map(|e| view! { <p class="flash bad" role="alert">{e}</p> });
    let login_token = login_token.to_string();
    render(view! {
        <html lang="en">
            {head("Sign in · flyw8t".into(), None, None)}
            <body class="login">
                <main class="card narrow">
                    <h1>"flyw8t"</h1>
                    <p class="muted">"Lightweight agents. Heavyweight control."</p>
                    {note}
                    {err}
                    <form method="post" action="/login" class="stack">
                        <input type="hidden" name="login_csrf" value=login_token/>
                        <label>"Email"<input type="email" name="email" autocomplete="username" required=true autofocus=true/></label>
                        <label>"Password"<input type="password" name="password" autocomplete="current-password" required=true/></label>
                        <button type="submit">"Sign in"</button>
                    </form>
                    {oidc.then(|| view! { <p><a href="/login/oidc">"Sign in with your organization"</a></p> })}
                    <p><a href="/login/passkey">"Sign in with a passkey"</a></p>
                </main>
            </body>
        </html>
    })
}

/// Signing in with a passkey. `login_token` is the sign-in cookie's value; the ceremony form carries it as its CSRF token.
pub fn passkey_sign_in_page(ceremony: WebAuthnCeremony, login_token: &str) -> String {
    render(view! {
        <html lang="en">
            {head("Sign in with a passkey · flyw8t".into(), None, Some("/static/passkey.js"))}
            <body class="login">
                <main class="card narrow">
                    <h1>"flyw8t"</h1>
                    <p class="muted">"Your browser or security key shows the passkeys it holds for this console. Choose yours, then unlock it."</p>
                    {ceremony_form(ceremony, login_token.to_string(), (), "Sign in with a passkey")}
                    <p class="muted">"A security key added only for confirmations, without a passkey stored on it, cannot be offered here: sign in with your password."</p>
                    <p><a href="/login">"Sign in with your password instead"</a></p>
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
    // First run: until a device is enrolled, say what to do next instead of showing an empty console.
    let setup = (o.devices_total == 0).then(|| {
        if !ctx.can_enroll {
            return view! { <p class="empty">"No devices are enrolled in your organizations yet. An administrator or technician enrolls them."</p> }.into_any();
        }
        let have_org = !o.organizations.is_empty();
        let org_step = if have_org {
            view! { <li class="done"><strong>"Create an organization"</strong><p class="muted">"Done. Every device belongs to one."</p></li> }.into_any()
        } else if ctx.is_admin {
            view! { <li><strong><a href="/organizations">"Create an organization"</a></strong><p class="muted">"Every device belongs to one: a customer, or your own company."</p></li> }.into_any()
        } else {
            view! { <li><strong>"Ask an administrator to create an organization and assign you to it"</strong></li> }.into_any()
        };
        let token_step = match o.organizations.first() {
            Some(org) => {
                let href = format!("/organizations/{}", org.id);
                view! { <li><strong><a href=href>"Create an enrollment token"</a></strong><p class="muted">"On the organization's page. The token is shown once, with the commands to run."</p></li> }.into_any()
            }
            None => view! { <li><strong>"Create an enrollment token"</strong><p class="muted">"On the organization's page. The token is shown once, with the commands to run."</p></li> }.into_any(),
        };
        view! {
            <section class="card">
                <h2>"Enroll your first device"</h2>
                <ol class="setup">
                    {org_step}
                    {token_step}
                    <li><strong>"Run the agent on the device"</strong><p class="muted">"In an elevated PowerShell on the Windows device, run the commands shown with the token. The device appears under Devices as soon as it connects."</p></li>
                </ol>
            </section>
        }
        .into_any()
    });
    let device_attention = (o.devices_total > 0).then(|| {
        let total = o.device_attention_total;
        let partial = o.devices_truncated.then(|| view! { <p class="muted small">{format!("The fleet is larger than these figures cover: only the first {DEVICE_SCAN_LIMIT} devices by name were examined.")}</p> });
        let content = if o.device_attention.is_empty() && o.devices_truncated {
            // Not an all-clear: part of the fleet was not looked at.
            view! { <p class="empty">"No concerns among the devices examined. The rest of the fleet was not examined."</p> }.into_any()
        } else if o.device_attention.is_empty() {
            view! { <p class="empty">"Nothing to report: every device has been heard from within a week, none reports a nearly full disk, and every connected device has sent inventory lately."</p> }.into_any()
        } else {
            let rows = o
                .device_attention
                .iter()
                .map(|a| {
                    let href = format!("/devices/{}", a.device.id);
                    let reasons = a.concerns.iter().map(concern_badge).collect_view();
                    let reported = match &a.device.health {
                        Some(h) => time_cell(now, h.collected_at).into_any(),
                        None => view! { <span class="muted">"no inventory"</span> }.into_any(),
                    };
                    view! {
                        <tr>
                            <td data-label="Device"><a href=href><strong>{a.device.name().to_string()}</strong></a><div class="muted small">{a.device.organization.name.clone()}</div></td>
                            <td data-label="Why"><ul class="reasons">{reasons}</ul></td>
                            <td data-label="Inventory from">{reported}</td>
                        </tr>
                    }
                })
                .collect_view();
            let more = (total > o.device_attention.len() as i64).then(|| {
                view! { <p><a href="/devices?attention=1">{format!("All {total} devices needing attention →")}</a></p> }
            });
            view! {
                <table class="list">
                    <thead><tr><th scope="col">"Device"</th><th scope="col">"Why"</th><th scope="col">"Inventory from"</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
                {more}
            }
            .into_any()
        };
        // Out of every active device, not only those on the versions listed.
        let known = o.devices_total;
        let versions = o
            .agent_versions
            .iter()
            .map(|(v, n)| {
                let label = v.clone().unwrap_or_else(|| "not reported".into());
                let aria = format!("{n} of {known} devices on {label}");
                view! {
                    <li>
                        <span class="mono">{label}</span>
                        <meter min="0" max=known.to_string() value=n.to_string() aria-label=aria></meter>
                        <span class="fig">{*n}</span>
                    </li>
                }
            })
            .collect_view();
        view! {
            <div class="grid">
                <section class="card">
                    <h2>"Devices needing attention"</h2>
                    <p class="muted">{format!("Not heard from for {OFFLINE_ATTENTION_DAYS} days or more, never connected, a fixed disk at {DISK_NEARLY_FULL_PERCENT}% or more, or connected with no inventory received for {STALE_INVENTORY_DAYS} days. Disk figures are what each device last reported, not live.")}</p>
                    {partial}
                    {content}
                </section>
                <section class="card">
                    <h2>"Agent versions"</h2>
                    <p class="muted">{format!("What each active device reported when it last connected, however long ago that was. This server is {}.", ctx.version)}</p>
                    <ul class="bars">{versions}</ul>
                </section>
            </div>
        }
    });
    let attention_class = if o.device_attention_total > 0 {
        "tile unknown"
    } else {
        "tile"
    };
    let body = view! {
        <h1>"Overview"</h1>
        {setup}
        <div class="tiles">
            <a class="tile" href="/devices?connection=connected"><span class="num">{o.devices_connected}</span>" of "{o.devices_total}" devices connected now"</a>
            <a class=attention_class href="/devices?attention=1"><span class="num">{o.device_attention_total}</span>" devices need attention"</a>
            <a class="tile" href="/jobs?state=running"><span class="num">{o.jobs_in_flight}</span>" queued or running"</a>
            <a class="tile" href="/jobs?state=completed"><span class="num">{o.jobs_succeeded_24h}</span>" verified successes (24 h)"</a>
            <a class="tile bad" href="/jobs?state=failed"><span class="num">{o.jobs_failed_24h}</span>" failed (24 h)"</a>
            <a class="tile unknown" href="/jobs?state=outcome_unknown"><span class="num">{o.jobs_unknown}</span>" outcome unknown"</a>
        </div>
        {device_attention}
        {attention}
        <section>
            <h2>"Recent jobs"</h2>
            {job_table(o.recent, now, true)}
        </section>
    };
    shell("Overview", ctx, Nav::Overview, Some(30), body)
}

fn tag_chips(tags: &[String]) -> impl IntoView {
    tags.iter()
        .map(|t| {
            let href = format!("/devices?tag={t}");
            view! { " " <a class="tag" href=href>{t.clone()}</a> }
        })
        .collect_view()
}

pub fn devices_page(
    ctx: &PageCtx,
    rows: Vec<DeviceRow>,
    filter: DeviceFilter,
    orgs: Vec<OrgRef>,
    tags: Vec<String>,
) -> String {
    let now = ctx.now;
    let org_options = orgs
        .into_iter()
        .map(|o| {
            let selected = filter.organization == Some(o.id);
            view! { <option value=o.id.to_string() selected=selected>{o.name}</option> }
        })
        .collect_view();
    // Also in the column headings, which a narrow screen does not show.
    let sort_options = [
        ("", "By name"),
        ("seen", "Longest silent first"),
        ("disk", "Fullest disk first"),
    ]
    .into_iter()
    .map(|(v, l)| {
        let selected = filter.sort == v;
        view! { <option value=v selected=selected>{l}</option> }
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
    let tag_options = tags
        .into_iter()
        .map(|t| {
            let selected = filter.tag == t;
            view! { <option value=t.clone() selected=selected>{t.clone()}</option> }
        })
        .collect_view();
    let status_options = [
        ("", "Active"),
        ("retired", "Retired"),
        ("all", "Active and retired"),
    ]
    .into_iter()
    .map(|(v, l)| {
        let selected = filter.status == v;
        view! { <option value=v selected=selected>{l}</option> }
    })
    .collect_view();
    let count = rows.len();
    // Selecting devices is offered only to someone who can do something with them.
    let pick = ctx.can_manage_devices || ctx.can_run || ctx.can_retire;
    let shown: Vec<String> = rows.iter().map(|d| d.id.to_string()).collect();
    let table = if rows.is_empty() {
        view! { <p class="empty">"No devices match. Enroll one from an organization's page."</p> }
            .into_any()
    } else {
        let body = rows
            .into_iter()
            .map(|d| {
                let href = format!("/devices/{}", d.id);
                let retired = d.retired.then(|| view! { " " <span class="badge neutral">"retired"</span> });
                let host = d.display_name.is_some().then(|| view! { <div class="muted small mono">{d.hostname.clone()}</div> });
                let label = format!("Select {}", d.name());
                let check = pick.then(|| view! {
                    <td class="pick"><input type="checkbox" name="device" value=d.id.to_string() aria-label=label/></td>
                });
                let dash = || view! { <span class="muted">"—"</span> }.into_any();
                let disk = match d.health.as_ref().and_then(|h| h.fullest_disk.as_ref()) {
                    Some(k) => usage(
                        k.used_percent(),
                        format!("{} used", k.mount_point),
                        format!("{} · {} free", k.mount_point, fmt::bytes(k.available_bytes)),
                    )
                    .into_any(),
                    None => dash(),
                };
                let memory = match &d.health {
                    Some(h) if h.memory_total_bytes > 0 => usage(
                        h.memory_used_percent(),
                        "Memory used".into(),
                        format!("{} free of {}", fmt::bytes(h.memory_available_bytes), fmt::bytes(h.memory_total_bytes)),
                    )
                    .into_any(),
                    _ => dash(),
                };
                // Device-reported figures always say how old they are.
                let reported = d.health.as_ref().map(|h| {
                    view! { <div class="muted small">"reported "{time_cell(now, h.collected_at)}</div> }
                });
                view! {
                    <tr>
                        {check}
                        <td data-label="Device"><a href=href><strong>{d.name().to_string()}</strong></a>{retired}{host}{tag_chips(&d.tags)}</td>
                        <td data-label="Organization">{d.organization.name.clone()}{d.site.clone().map(|s| format!(" / {s}"))}</td>
                        <td data-label="Connection">{connection_badge(&d.connection, now)}</td>
                        <td data-label="Fullest disk">{disk}</td>
                        <td data-label="Memory">{memory}</td>
                        <td data-label="System">{d.os.clone().unwrap_or_else(|| "—".into())}<div class="muted small mono">{d.agent_version.clone().map(|v| format!("agent {v}")).unwrap_or_else(|| "agent —".into())}</div>{reported}</td>
                    </tr>
                }
            })
            .collect_view();
        let pick_head = pick
            .then(|| view! { <th scope="col" class="pick"><span class="sr">"Select"</span></th> });
        // The three orders, as links in the headings they sort by.
        let sorted = |sort: &'static str, dir: &'static str| (filter.sort == sort).then_some(dir);
        let table = view! {
            <table class="list">
                <thead><tr>
                    {pick_head}
                    <th scope="col" aria-sort=sorted("", "ascending")><a href=devices_href(&filter, "") title="Sort by name">"Device"</a></th>
                    <th scope="col">"Organization"</th>
                    <th scope="col" aria-sort=sorted("seen", "ascending")><a href=devices_href(&filter, "seen") title="Longest silent first">"Connection"</a></th>
                    <th scope="col" aria-sort=sorted("disk", "descending")><a href=devices_href(&filter, "disk") title="Fullest first">"Fullest disk"</a></th>
                    <th scope="col">"Memory"</th>
                    <th scope="col">"System"</th>
                </tr></thead>
                <tbody>{body}</tbody>
            </table>
        };
        if pick {
            let tag_ops = ctx.can_manage_devices.then(|| view! {
                <label>"Tag"<input type="text" name="tag" maxlength="40" placeholder="kiosk" pattern="[A-Za-z0-9][A-Za-z0-9._:\\-]*"/></label>
                <button type="submit" name="op" value="tag-add" class="secondary">"Add tag"</button>
                <button type="submit" name="op" value="tag-remove" class="link">"Remove tag"</button>
            });
            let run = ctx.can_run.then(|| view! { <button type="submit" name="op" value="run" class="secondary">"Run a diagnostic…"</button> });
            let retire = ctx.can_retire.then(|| view! { <button type="submit" name="op" value="retire" class="bad">"Retire…"</button> });
            let all_label = format!("All {count} shown");
            view! {
                <form method="post" action="/devices/bulk" class="bulk">
                    <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                    // "All shown" means exactly these rows, not the filter run again later.
                    {shown.into_iter().map(|id| view! { <input type="hidden" name="shown" value=id/> }).collect_view()}
                    <div class="bulkbar" role="group" aria-label="Selected devices">
                        <label class="inline"><input type="checkbox" name="all" value="1"/>{all_label}</label>
                        <span class="muted small">"or tick devices below, then:"</span>
                        {tag_ops}
                        {run}
                        {retire}
                    </div>
                    {table}
                </form>
            }
            .into_any()
        } else {
            table.into_any()
        }
    };
    let body = view! {
        <h1>"Devices"</h1>
        <form method="get" action="/devices" class="filters" role="search">
            <input type="search" name="q" value=filter.q.clone() placeholder="Search name, hostname or tag" aria-label="Search name, hostname or tag" accesskey="s" autofocus=true/>
            <select name="org" aria-label="Organization"><option value="">"All organizations"</option>{org_options}</select>
            <select name="tag" aria-label="Tag"><option value="">"Any tag"</option>{tag_options}</select>
            <select name="connection" aria-label="Connection">{conn_options}</select>
            <select name="status" aria-label="Status">{status_options}</select>
            <label class="inline"><input type="checkbox" name="attention" value="1" checked=filter.attention/>"Needs attention"</label>
            <select name="sort" aria-label="Order">{sort_options}</select>
            <button type="submit">"Filter"</button>
        </form>
        <p class="muted">{format!("{count} device(s). Connection state is live; disk, memory and system are what each device last reported, with its age.")}{(count >= DEVICE_PAGE_LIMIT).then(|| format!(" Only the first {DEVICE_PAGE_LIMIT} are shown: narrow the filters to see the rest."))}</p>
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
            let name = format!("{} ({})", d.mount_point, d.file_system);
            let figures = format!(
                "{} free of {} ({pct}% used)",
                fmt::bytes(d.available_bytes),
                fmt::bytes(d.total_bytes)
            );
            let aria = format!("{} used", d.mount_point);
            view! {
                <li>
                    <span>{name}</span>
                    <meter min="0" max="100" low="75" high="90" optimum="0" value=pct.to_string() aria-label=aria></meter>
                    <span>{figures}</span>
                </li>
            }
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
                <dt>"Disks"</dt><dd><ul class="plain disks">{disks}</ul></dd>
                <dt>"Network"</dt><dd><ul class="plain">{nics}</ul></dd>
            </dl>
        </section>
    }
    .into_any()
}

/// One form per catalog action, posting to `url` with `hidden` fields added.
fn action_forms(
    ctx: &PageCtx,
    url: String,
    hidden: Vec<(&'static str, String)>,
    button: &'static str,
) -> impl IntoView {
    CATALOG
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
            let hidden = hidden
                .iter()
                .map(|(k, v)| view! { <input type="hidden" name=*k value=v.clone()/> })
                .collect_view();
            view! {
                <form method="post" action=url.clone() class="action">
                    <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                    <input type="hidden" name="action" value=a.name/>
                    {hidden}
                    <div>
                        <strong>{a.title}</strong>" "<span class="mono muted">{a.name}</span>
                        <p class="muted">{a.description}</p>
                    </div>
                    {params}
                    <button type="submit">{button}</button>
                </form>
            }
        })
        .collect_view()
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
    let note = if connected {
        "The device is connected; jobs are sent immediately."
    } else {
        "The device is not connected. Jobs queue until it connects or their 15-minute delivery window passes."
    };
    view! {
        <p class="muted">{note}" Read-only diagnostics only."</p>
        <div class="actions">{action_forms(ctx, format!("/devices/{device_id}/jobs"), vec![], "Run")}</div>
    }
    .into_any()
}

/// Name, tags, site and notes.
fn manage_section(ctx: &PageCtx, d: &DeviceDetail) -> impl IntoView {
    if !ctx.can_manage_devices {
        return ().into_any();
    }
    let id = d.row.id;
    let edit = ctx.can_manage_devices.then(|| {
        let site_options = d
            .sites
            .iter()
            .map(|s| {
                let selected = d.site_id == Some(s.id);
                view! { <option value=s.id.to_string() selected=selected>{s.name.clone()}</option> }
            })
            .collect_view();
        view! {
            <form method="post" action=format!("/devices/{id}/edit") class="stack">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <div class="cols">
                    <label>"Name (blank shows the hostname)"<input type="text" name="display_name" maxlength="200" value=d.row.display_name.clone().unwrap_or_default() placeholder=d.row.hostname.clone()/></label>
                    <label>"Site"<select name="site"><option value="">"No site"</option>{site_options}</select></label>
                </div>
                <label>"Tags, separated by commas"<input type="text" name="tags" maxlength="900" value=d.row.tags.join(", ") placeholder="finance, kiosk"/></label>
                <label>"Notes"<textarea name="notes" rows="3" maxlength="4000">{textarea_text(&d.notes)}</textarea></label>
                <button type="submit">"Save"</button>
            </form>
        }
    });
    view! {
        <section class="card">
            <h2>"Manage"</h2>
            {edit}
        </section>
    }
    .into_any()
}

/// The device's last report at a glance: disks, memory, uptime and how old the report is.
fn glance_section(d: &DeviceDetail, now: OffsetDateTime) -> Option<impl IntoView> {
    let inv = d.inventory.as_ref()?;
    let r = &inv.report;
    let memory = (r.hardware.memory_total_bytes > 0).then(|| {
        let pct = used_percent(
            r.hardware.memory_total_bytes,
            r.hardware.memory_available_bytes,
        );
        view! {
            <div class="stat">
                <span class="k">"Memory"</span>
                <span class="v">{format!("{pct}% used")}</span>
                <meter min="0" max="100" low="75" high="90" optimum="0" value=pct.to_string() aria-label="Memory used"></meter>
                <span class="muted small">{format!("{} free of {}", fmt::bytes(r.hardware.memory_available_bytes), fmt::bytes(r.hardware.memory_total_bytes))}</span>
            </div>
        }
    });
    let disks = r
        .disks
        .iter()
        .filter(|k| !k.removable && k.total_bytes > 0)
        .take(4)
        .map(|k| {
            let pct = used_percent(k.total_bytes, k.available_bytes);
            let aria = format!("{} used", k.mount_point);
            view! {
                <div class="stat">
                    <span class="k">{format!("Disk {}", k.mount_point)}</span>
                    <span class="v">{format!("{pct}% used")}</span>
                    <meter min="0" max="100" low="75" high="90" optimum="0" value=pct.to_string() aria-label=aria></meter>
                    <span class="muted small">{format!("{} free of {}", fmt::bytes(k.available_bytes), fmt::bytes(k.total_bytes))}</span>
                </div>
            }
        })
        .collect_view();
    let os = [r.os.long_version.clone(), r.os.name.clone()]
        .into_iter()
        .flatten()
        .next()
        .unwrap_or_else(|| r.os.family.clone());
    Some(view! {
        <section class="card">
            <div class="stats">
                <div class="stat"><span class="k">"System"</span><span class="v">{os}</span><span class="muted small">{r.os.arch.clone()}</span></div>
                {disks}
                {memory}
                <div class="stat"><span class="k">"Uptime"</span><span class="v">{fmt::duration_secs(r.uptime_secs)}</span><span class="muted small">"when reported"</span></div>
            </div>
            <p class="muted small">"Reported by the device "{time_cell(now, r.collected_at)}". Not live: run System information for current figures."</p>
        </section>
    })
}

pub fn bulk_confirm_page(ctx: &PageCtx, c: BulkConfirm) -> String {
    let now = ctx.now;
    let count = c.devices.len();
    let mut hidden: Vec<(&'static str, String)> = c
        .devices
        .iter()
        .map(|d| ("device", d.id.to_string()))
        .collect();
    hidden.push(("count", count.to_string()));
    hidden.push(("confirm", "yes".into()));
    let rows = c
        .devices
        .iter()
        .map(|d| {
            let href = format!("/devices/{}", d.id);
            let retired = d
                .retired
                .then(|| view! { " " <span class="badge neutral">"retired"</span> });
            view! {
                <tr>
                    <td data-label="Device"><a href=href>{d.name().to_string()}</a>{retired}</td>
                    <td data-label="Organization">{d.organization.name.clone()}</td>
                    <td data-label="Connection">{connection_badge(&d.connection, now)}</td>
                </tr>
            }
        })
        .collect_view();
    let (title, lead, action) = if c.op == "run" {
        let skipped = c.devices.iter().filter(|d| d.retired).count();
        let lead = if skipped > 0 {
            format!("Choose a diagnostic to run on these {count} devices. {skipped} retired device(s) will be skipped.")
        } else {
            format!("Choose a diagnostic to run on these {count} devices. Each gets its own job; the results are grouped as one batch.")
        };
        (
            format!("Run on {count} devices"),
            lead,
            view! { <div class="actions">{action_forms(ctx, "/devices/bulk/run".into(), hidden, "Run on all")}</div> }.into_any(),
        )
    } else {
        let fields = hidden
            .iter()
            .map(|(k, v)| view! { <input type="hidden" name=*k value=v.clone()/> })
            .collect_view();
        (
            format!("Retire {count} devices"),
            "Retiring revokes each device's credential, closes its connection and hides it from the active list. History stays. Jobs not yet delivered expire; a job already running ends with an unknown outcome. This cannot be undone: a retired device must be enrolled again.".to_string(),
            view! {
                <form method="post" action="/devices/bulk/retire" class="danger">
                    <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                    {fields}
                    <button type="submit" class="bad">{format!("Retire all {count}")}</button>
                </form>
            }
            .into_any(),
        )
    };
    let body = view! {
        <p class="crumbs"><a href="/devices">"Devices"</a>" / "</p>
        <h1>{title.clone()}</h1>
        <p class="lead">{lead}</p>
        {action}
        <section>
            <h2>"Devices"</h2>
            <table class="list">
                <thead><tr><th scope="col">"Device"</th><th scope="col">"Organization"</th><th scope="col">"Connection"</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </section>
    };
    shell(&title, ctx, Nav::Devices, None, body)
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
    let revoke = (ctx.can_retire && !d.row.retired && d.credential.as_ref().is_some_and(|c| c.revoked_at.is_none())).then(|| {
        let url = format!("/devices/{}/revoke", d.row.id);
        view! {
            <form method="post" action=url class="danger">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label class="inline"><input type="checkbox" name="confirm" value="yes" required=true/>" I understand this disconnects the device permanently; it must be re-enrolled."</label>
                <button type="submit" class="bad">"Revoke device credential"</button>
            </form>
        }
    });
    let retire = (ctx.can_retire && !d.row.retired).then(|| {
        view! {
            <form method="post" action=format!("/devices/{}/retire", d.row.id) class="danger">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label class="inline"><input type="checkbox" name="confirm" value="yes" required=true/>" Retire this device: revoke its credential, close its connection and hide it from the active list. Its history stays with this organization. Jobs not yet delivered expire; a job already running ends with an unknown outcome. To manage it again, or under another organization, enroll it again."</label>
                <button type="submit" class="bad">"Retire device"</button>
            </form>
        }
    });
    // Both end the device's access for good, so they sit together, closed until asked for.
    let danger = (revoke.is_some() || retire.is_some()).then(|| {
        view! {
            <details class="card dangerzone">
                <summary>"Revoke or retire this device"</summary>
                {revoke}
                {retire}
            </details>
        }
    });
    let glance = glance_section(&d, now);
    let title = d.row.name().to_string();
    let manage = manage_section(ctx, &d);
    let tags = tag_chips(&d.row.tags);
    let notes = (!d.notes.is_empty())
        .then(|| view! { <dt>"Notes"</dt><dd class="notes">{d.notes.clone()}</dd> });
    let retired_note = d.row.retired.then(|| view! { <p class="flash bad">"This device is retired. Its credential is revoked; it cannot connect or run jobs."</p> });
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
        <h1>{title.clone()}" "{connection_badge(&d.row.connection, now)}</h1>
        {retired_note}
        <p>{tags}</p>
        {glance}
        <div class="grid">
            <section class="card">
                <h2>"Identity"</h2>
                <dl class="facts">
                    <dt>"Hostname"</dt><dd class="mono">{d.row.hostname.clone()}</dd>
                    <dt>"Organization"</dt><dd>{org_line}</dd>
                    <dt>"Connection"</dt><dd>{conn_detail}</dd>
                    <dt>"Enrolled"</dt><dd>{fmt::timestamp(d.enrolled_at)}</dd>
                    <dt>"Agent"</dt><dd class="mono">{d.row.agent_version.clone().unwrap_or_else(|| "—".into())}</dd>
                    <dt>"Credential"</dt><dd>{credential}</dd>
                    <dt>"Remote access"</dt><dd>{d.remote_access.clone()}</dd>
                    <dt>"Device ID"</dt><dd class="mono">{d.row.id.to_string()}</dd>
                    {notes}
                </dl>
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
        {manage}
        {fields_card(ctx, &d.fields, "device", d.row.id)}
        {danger}
    };
    shell(&title, ctx, Nav::Devices, None, body)
}

/// What the jobs list is narrowed to, and which page of it this is.
#[derive(Debug, Clone, Default)]
pub struct JobsView {
    pub state: Option<ExecState>,
    /// A catalog action's name, or empty.
    pub action: String,
    pub batch: Option<BatchSummary>,
    /// From 1.
    pub page: u32,
    /// Older jobs exist beyond this page.
    pub more: bool,
}

/// Jobs to a page.
pub const JOBS_PAGE_SIZE: i64 = 100;

fn jobs_href(v: &JobsView, page: u32) -> String {
    let mut parts = vec![format!("page={page}")];
    if let Some(s) = v.state {
        parts.push(format!("state={}", s.as_str()));
    }
    if !v.action.is_empty() {
        parts.push(format!("action={}", query_value(&v.action)));
    }
    if let Some(b) = &v.batch {
        parts.push(format!("batch={}", b.id));
    }
    format!("/jobs?{}", parts.join("&"))
}

pub fn jobs_page(ctx: &PageCtx, rows: Vec<JobRow>, v: JobsView) -> String {
    let now = ctx.now;
    let state = v.state;
    let previous = (v.page > 1)
        .then(|| view! { <a class="button secondary" href=jobs_href(&v, v.page - 1)>"Newer"</a> });
    let next = v
        .more
        .then(|| view! { <a class="button secondary" href=jobs_href(&v, v.page + 1)>"Older"</a> });
    let paging = (v.page > 1 || v.more).then(|| view! {
        <div class="pagination">{previous}<span class="small muted">{format!("Page {}", v.page)}</span>{next}</div>
    });
    let action_options = flyw8t_protocol::catalog::CATALOG
        .iter()
        .map(|a| view! { <option value=a.name selected={v.action == a.name}>{a.name}</option> })
        .collect_view();
    let batch = v.batch.clone();
    let options = ALL_STATES
        .into_iter()
        .map(|s| {
            let selected = state == Some(s);
            view! { <option value=s.as_str() selected=selected>{s.as_str().replace('_', " ")}</option> }
        })
        .collect_view();
    let refresh = batch.as_ref().filter(|b| b.in_progress > 0).map(|_| 5);
    let title = match &batch {
        Some(b) => format!("Batch {}", fmt::short_id(b.id)),
        None => "Jobs".into(),
    };
    let summary = batch.as_ref().map(|b| {
        view! {
            <p class="crumbs"><a href="/jobs">"Jobs"</a>" / "</p>
            <div class="tiles">
                <div class="tile"><span class="num">{b.total}</span>" jobs"</div>
                <div class="tile"><span class="num">{b.succeeded}</span>" succeeded"</div>
                <div class="tile bad"><span class="num">{b.failed}</span>" failed"</div>
                <div class="tile unknown"><span class="num">{b.unknown}</span>" outcome unknown"</div>
                <div class="tile"><span class="num">{b.in_progress}</span>" in progress"</div>
            </div>
        }
    });
    let batch_field = batch
        .as_ref()
        .map(|b| view! { <input type="hidden" name="batch" value=b.id.to_string()/> });
    let body = view! {
        <h1>{title.clone()}</h1>
        {summary}
        <form method="get" action="/jobs" class="filters">
            {batch_field}
            <select name="state" aria-label="Execution state"><option value="">"Any state"</option>{options}</select>
            <select name="action" aria-label="Action"><option value="">"Any action"</option>{action_options}</select>
            <button type="submit">"Filter"</button>
        </form>
        {job_table(rows, now, true)}
        {paging}
    };
    shell(&title, ctx, Nav::Jobs, refresh, body)
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

pub(crate) fn revealed_box(r: RevealedSecret) -> impl IntoView {
    let commands = r.commands.map(|c| {
        view! {
            <h3>"On the Windows device"</h3>
            <p class="muted">"In an elevated PowerShell, in the folder holding "<span class="mono">"flyw8t-agent.exe"</span>" (from the "<a href="https://github.com/spilloid/flyw8t/releases" rel="noreferrer">"release downloads"</a>"; check it against SHA256SUMS). The token is already in the first command:"</p>
            <pre class="output secret cmd">{c}</pre>
            <p class="muted">"The first command registers the device and stores its key, the second installs the service, and the third prints the server and device ID the agent holds. Whether it is connected shows on the device's page here."</p>
        }
    });
    view! {
        <section class="card reveal" role="alert">
            <h2>{r.label}</h2>
            <p><strong>"Copy it now. It is shown once and only its hash is stored."</strong></p>
            <pre class="output secret">{r.secret}</pre>
            <p class="muted">{r.hint}</p>
            {commands}
        </section>
    }
}

/// The input for one field's value: a list for choices and yes/no, a password box for secrets, text otherwise.
fn field_input(kind: &str, choices: &[String], current: Option<&str>) -> AnyView {
    match kind {
        "boolean" => {
            let sel = |v: &str| current == Some(v);
            view! {
                <select name="value" aria-label="Value">
                    <option value="">"(clear)"</option>
                    <option value="true" selected=sel("true")>"Yes"</option>
                    <option value="false" selected=sel("false")>"No"</option>
                </select>
            }
            .into_any()
        }
        "choice" => {
            let opts = choices
                .iter()
                .map(|c| {
                    let selected = current == Some(c.as_str());
                    view! { <option value=c.clone() selected=selected>{c.clone()}</option> }
                })
                .collect_view();
            view! { <select name="value" aria-label="Value"><option value="">"(clear)"</option>{opts}</select> }.into_any()
        }
        "secret" => view! {
            <input type="password" name="value" maxlength="1000" autocomplete="off" placeholder="New secret (blank clears)" aria-label="Value"/>
        }
        .into_any(),
        "number" => view! {
            <input type="text" inputmode="decimal" name="value" maxlength="40" value=current.unwrap_or("").to_string() aria-label="Value"/>
        }
        .into_any(),
        _ => view! {
            <input type="text" name="value" maxlength="1000" value=current.unwrap_or("").to_string() aria-label="Value"/>
        }
        .into_any(),
    }
}

fn source_label(source: &str) -> &'static str {
    match source {
        "device" => "set on this device",
        "site" => "from the site",
        "organization" => "from the organization",
        "global" => "global",
        "default" => "default",
        _ => "not set",
    }
}

/// Custom fields as they apply to an organization (`scope = "organization"`), a site (`"site"`) or a device
/// (`"device"`).
pub fn fields_card(
    ctx: &PageCtx,
    fields: &[ResolvedField],
    scope: &'static str,
    target: uuid::Uuid,
) -> AnyView {
    if fields.is_empty() {
        return ().into_any();
    }
    let rows = fields
        .iter()
        .map(|f| {
            let value = match &f.value {
                Some(v) => view! { <span class=if v.secret { "mono" } else { "" }>{v.display.clone()}</span> }.into_any(),
                None => view! { <span class="muted">"—"</span> }.into_any(),
            };
            let missing = f.missing.then(|| view! { " " <span class="badge bad">"required"</span> });
            let source = format!("{} ", source_label(f.source));
            let history = f.settable_here.then(|| {
                let href = format!("/fields/{}/history?scope={scope}&target={target}", f.id);
                view! { <a href=href class="small">"history"</a> }
            });
            let edit = (f.settable_here && f.can_edit).then(|| {
                let url = format!("/fields/{}/value", f.id);
                let own = if f.kind == "secret" { None } else { f.own.as_ref().map(|v| v.display.clone()) };
                view! {
                    <form method="post" action=url class="inline-form">
                        <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                        <input type="hidden" name="scope" value=scope/>
                        <input type="hidden" name="target" value=target.to_string()/>
                        {field_input(&f.kind, &f.choices, own.as_deref())}
                        <button type="submit">"Set"</button>
                    </form>
                }
            });
            view! {
                <tr>
                    <td data-label="Field"><strong>{f.label.clone()}</strong>{missing}<div class="muted small mono">{f.key.clone()}</div></td>
                    <td data-label="Value">{value}<div class="muted small">{source}{history}</div></td>
                    <td data-label="Set here">{edit}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <section>
            <h2>"Custom fields"</h2>
            <p class="muted">"Device values override the site's, which override the organization's, which override global values and defaults. Secret values are never shown again once set."</p>
            <table class="list">
                <thead><tr><th scope="col">"Field"</th><th scope="col">"Value"</th><th scope="col">"Set here"</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </section>
    }
    .into_any()
}

pub fn fields_page(
    ctx: &PageCtx,
    defs: Vec<FieldDefView>,
    missing: Vec<MissingRequired>,
    secrets_enabled: bool,
) -> String {
    let none = defs.is_empty();
    let rows = defs
        .iter()
        .map(|d| {
            let archived = d.archived.then(|| view! { " " <span class="badge neutral">"archived"</span> });
            let req = d.required_at.as_deref().map(|r| format!("required for every {r}")).unwrap_or_default();
            let tech = if d.technician_can_edit { "technicians may edit" } else { "admins only" };
            let global = d.scopes.iter().any(|s| s == "global").then(|| {
                let current = d.global.as_ref().map(|v| v.display.clone());
                let shown = current.clone().unwrap_or_else(|| "—".into());
                let edit = (!d.archived).then(|| {
                    let url = format!("/fields/{}/value", d.id);
                    let own = if d.kind == "secret" { None } else { current.clone() };
                    view! {
                        <form method="post" action=url class="inline-form">
                            <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                            <input type="hidden" name="scope" value="global"/>
                            {field_input(&d.kind, &d.choices, own.as_deref())}
                            <button type="submit">"Set"</button>
                        </form>
                    }
                });
                let history = format!("/fields/{}/history?scope=global", d.id);
                view! { <div>{shown}" "<a href=history class="small">"history"</a></div>{edit} }
            });
            let archive = (!d.archived).then(|| {
                let url = format!("/admin/fields/{}/archive", d.id);
                view! {
                    <form method="post" action=url>
                        <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                        <button type="submit" class="link">"Archive"</button>
                    </form>
                }
            });
            let choices = (!d.choices.is_empty()).then(|| format!(" · {}", d.choices.join(", ")));
            let default = d.default_value.clone().map(|v| format!(" · default {v}"));
            view! {
                <tr>
                    <td data-label="Field"><strong>{d.label.clone()}</strong>{archived}<div class="mono small">{d.key.clone()}</div></td>
                    <td data-label="Kind">{d.kind.clone()}{choices}{default}<div class="muted small">{d.scopes.join(", ")}" · "{tech}" "{req}</div></td>
                    <td data-label="Global value">{global}</td>
                    <td data-label="">{archive}</td>
                </tr>
            }
        })
        .collect_view();
    let missing_view = (!missing.is_empty()).then(|| {
        let items = missing
            .into_iter()
            .map(|m| {
                let base = if m.level == "organization" { "/organizations" } else { "/devices" };
                let links = m
                    .targets
                    .iter()
                    .map(|(id, name)| {
                        let href = format!("{base}/{id}");
                        view! { <a href=href>{name.clone()}</a>" " }
                    })
                    .collect_view();
                let more = (m.total > m.targets.len()).then(|| format!(" and {} more", m.total - m.targets.len()));
                view! {
                    <li><strong>{m.label.clone()}</strong>{format!(" — {} {}(s) missing: ", m.total, m.level)}{links}{more}</li>
                }
            })
            .collect_view();
        view! {
            <section class="card">
                <h2>"Required values missing"</h2>
                <ul class="plain">{items}</ul>
            </section>
        }
    });
    let no_key = (!secrets_enabled).then(|| {
        view! { <p class="flash bad">"Secret fields can be defined, but no secret value can be stored until FLYW8T_FIELD_KEY is set on the server."</p> }
    });
    let scope_boxes = [("global", "Global"), ("organization", "Organization"), ("site", "Site"), ("device", "Device")]
        .into_iter()
        .map(|(v, l)| view! { <label class="inline"><input type="checkbox" name="scope" value=v/>{l}</label> })
        .collect_view();
    let body = view! {
        <h1>"Administration"</h1>
        {admin_tabs("/admin/fields")}
        <h2>"Custom fields"</h2>
        <p class="lead">"Values scripts will read: set globally, per organization, per site or per device. The most specific value wins. Every change is kept."</p>
        {no_key}
        {missing_view}
        {none.then(|| view! { <p class="empty">"No fields yet. Define one below."</p> })}
        <section hidden=none>
            <table class="list">
                <thead><tr><th scope="col">"Field"</th><th scope="col">"Kind"</th><th scope="col">"Global value"</th><th scope="col"><span class="sr">"Archive"</span></th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </section>
        <section class="card">
            <h2>"Define a field"</h2>
            <form method="post" action="/admin/fields" class="stack">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"Key (scripts use it)"<input type="text" name="key" required=true maxlength="40" pattern="[a-z][a-z0-9_]*" placeholder="backup_share"/></label>
                <label>"Label"<input type="text" name="label" required=true maxlength="100" placeholder="Backup share"/></label>
                <label>"Kind"<select name="kind">
                    <option value="text">"Text"</option>
                    <option value="number">"Number"</option>
                    <option value="boolean">"Yes / no"</option>
                    <option value="choice">"Choice"</option>
                    <option value="secret">"Secret"</option>
                </select></label>
                <label>"Choices (for a choice field, separated by commas)"<input type="text" name="choices" maxlength="2000"/></label>
                <fieldset><legend>"May be set"</legend>{scope_boxes}</fieldset>
                <label>"Required"<select name="required_at">
                    <option value="">"No"</option>
                    <option value="organization">"Every organization must set its own"</option>
                    <option value="device">"Every device must have a value (inherited counts)"</option>
                </select></label>
                <label>"Default (not for secrets)"<input type="text" name="default_value" maxlength="1000"/></label>
                <label class="inline"><input type="checkbox" name="technician_can_edit" value="yes"/>" Technicians may set organization and device values"</label>
                <button type="submit">"Define"</button>
            </form>
        </section>
    };
    shell("Custom fields", ctx, Nav::Admin, None, body)
}

pub fn field_history_page(
    ctx: &PageCtx,
    label: &str,
    key: &str,
    scope: &str,
    back: &str,
    rows: Vec<FieldHistoryRow>,
) -> String {
    let body_rows = rows
        .into_iter()
        .map(|r| {
            let value = match r.display {
                Some(v) => view! { <span>{v}</span> }.into_any(),
                None => view! { <span class="muted">"cleared"</span> }.into_any(),
            };
            view! {
                <tr>
                    <td data-label="When"><time datetime=fmt::iso(r.set_at)>{fmt::timestamp(r.set_at)}</time></td>
                    <td data-label="Value">{value}</td>
                    <td data-label="By">{r.set_by}</td>
                </tr>
            }
        })
        .collect_view();
    let title = format!("{label}: history");
    let body = view! {
        <p class="crumbs"><a href=back.to_string()>"Back"</a>" / "</p>
        <h1>{title.clone()}</h1>
        <p class="muted">{format!("{key}, {scope} value. Newest first. Secret values are never shown.")}</p>
        <table class="list">
            <thead><tr><th scope="col">"When"</th><th scope="col">"Value"</th><th scope="col">"By"</th></tr></thead>
            <tbody>{body_rows}</tbody>
        </table>
    };
    shell(&title, ctx, Nav::Admin, None, body)
}

pub fn organization_page(
    ctx: &PageCtx,
    org: OrgSummary,
    tokens: Vec<EnrollmentTokenView>,
    revealed: Option<RevealedSecret>,
    fields: Vec<ResolvedField>,
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
        .map(|s| {
            let href = format!("/sites/{}", s.id);
            view! { <li><a href=href>{s.name.clone()}</a></li> }
        })
        .collect_view();
    let devices_href = format!("/devices?org={id}");
    let rename = ctx.is_admin.then(|| {
        let url = format!("/organizations/{id}/rename");
        view! {
            <details class="card">
                <summary>"Rename this organization"</summary>
                <form method="post" action=url class="inline-form">
                    <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                    <label>"Name"<input type="text" name="name" required=true maxlength="200" value=org.name.clone()/></label>
                    <button type="submit">"Rename"</button>
                </form>
                <p class="hint">"Devices, history and the audit trail keep their link to it; only the name shown changes."</p>
            </details>
        }
    });
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
        {fields_card(ctx, &fields, "organization", id)}
        {rename}
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

pub fn site_page(ctx: &PageCtx, site: SitePage, fields: Vec<ResolvedField>) -> String {
    let org_href = format!("/organizations/{}", site.organization.id);
    let none = site.devices.is_empty();
    let rename = ctx.is_admin.then(|| {
        let url = format!("/sites/{}/rename", site.id);
        view! {
            <details class="card">
                <summary>"Rename this site"</summary>
                <form method="post" action=url class="inline-form">
                    <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                    <label>"Name"<input type="text" name="name" required=true maxlength="200" value=site.name.clone()/></label>
                    <button type="submit">"Rename"</button>
                </form>
            </details>
        }
    });
    let devices = site
        .devices
        .iter()
        .map(|d| {
            let href = format!("/devices/{}", d.id);
            view! { <li><a href=href>{d.name.clone()}</a></li> }
        })
        .collect_view();
    let body = view! {
        <p class="crumbs"><a href="/organizations">"Organizations"</a>" / "<a href=org_href>{site.organization.name.clone()}</a>" / "</p>
        <h1>{site.name.clone()}</h1>
        <a class="tile network-site-link" href=format!("/network?site={}",site.id)>
            <strong>"Network operations"</strong>
            <span>{format!("{} assets · {} collectors",site.network_assets,site.network_collectors)}</span>
            <span class="small">"Inventory, discovery history and device access →"</span>
        </a>
        <section class="card">
            <h2>"Devices"</h2>
            {none.then(|| view! { <p class="empty">"No devices in this site."</p> })}
            <ul class="plain">{devices}</ul>
        </section>
        {fields_card(ctx, &fields, "site", site.id)}
        {rename}
    };
    shell(&site.name, ctx, Nav::Organizations, None, body)
}

/// The administration pages, as tabs.
fn admin_tabs(active: &'static str) -> impl IntoView {
    let tabs = [
        ("/admin", "Users and API tokens"),
        ("/admin/fields", "Custom fields"),
    ]
    .into_iter()
    .map(|(href, label)| {
        let current = (href == active).then_some("page");
        view! { <a href=href aria-current=current>{label}</a> }
    })
    .collect_view();
    view! { <nav class="tabs" aria-label="Administration">{tabs}</nav> }
}

pub fn admin_page(
    ctx: &PageCtx,
    users: Vec<UserRow>,
    tokens: Vec<ApiTokenRow>,
    orgs: Vec<OrgRef>,
    revealed: Option<RevealedSecret>,
    oidc: bool,
) -> String {
    let now = ctx.now;
    let user_rows = users
        .into_iter()
        .map(|u| {
            view! {
                <tr>
                    <td data-label="User"><a href=format!("/admin/users/{}", u.id)>{u.display_name.clone()}</a><div class="muted">{u.email.clone()}</div></td>
                    <td data-label="Role">{u.role.clone()}{u.disabled.then(|| view! { " "<span class="badge bad">"Disabled"</span> })}</td>
                    <td data-label="Organizations">{if u.role == "admin" { "all".to_string() } else { u.organizations.join(", ") }}</td>
                    <td data-label="Two-step">{mfa_cell(&u, &ctx.csrf)}</td>
                    <td data-label="Sessions">{sessions_cell(&u, &ctx.csrf)}</td>
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
            {oidc.then(||view!{<p><a href="/admin/directory">"Directory sign-in and provisioning"</a></p>})}
        {admin_tabs("/admin")}
        {revealed.map(revealed_box)}
        <section>
            <h2>"Users"</h2>
            <table class="list">
                <thead><tr><th scope="col">"User"</th><th scope="col">"Role"</th><th scope="col">"Organizations"</th><th scope="col">"Two-step"</th><th scope="col">"Sessions"</th></tr></thead>
                <tbody>{user_rows}</tbody>
            </table>
            <details class="card">
            <summary>"Add a user"</summary>
            <form method="post" action="/admin/users" class="stack">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <div class="cols">
                    <label>"Email"<input type="email" name="email" required=true/></label>
                    <label>"Name"<input type="text" name="display_name" required=true maxlength="200"/></label>
                </div>
                <label>"Initial password (12+ characters)"<input type="password" name="password" required=true minlength="12" autocomplete="new-password"/></label>
                <label>"Role"<select name="role">
                    <option value="technician">"Technician — view and run diagnostics in assigned organizations"</option>
                    <option value="readonly">"Read-only — view assigned organizations"</option>
                    <option value="admin">"Administrator — everything, every organization"</option>
                </select></label>
                <fieldset><legend>"Organizations (ignored for administrators)"</legend>{org_checks}</fieldset>
                <button type="submit">"Create user"</button>
            </form>
            </details>
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
                <label class="inline"><input type="checkbox" name="scope" value="support:screenshot"/>" Attended screenshots (participant permission required)"</label>
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
                {head(format!("{title} · flyw8t"), None, None)}
                <body class="login"><main class="card narrow"><h1>{title}</h1><p>{msg}</p><p><a href="/login">"Sign in"</a></p></main></body>
            </html>
        }),
    }
}

// ---------------------------------------------------------------------------------------
// Attended support

fn support_badge_class(state: &str) -> &'static str {
    match state {
        "connected" => "badge good",
        "connecting" | "waiting" | "authorizing" | "created" => "badge busy",
        "connection_failed" => "badge bad",
        _ => "badge neutral",
    }
}

fn support_state_badge(state: &str, label: &str) -> impl IntoView {
    view! { <span class=support_badge_class(state)>{label.to_string()}</span> }
}

pub fn support_list_page(
    ctx: &PageCtx,
    sessions: Vec<SupportSessionView>,
    orgs: Vec<OrgRef>,
    invite: Option<SupportInvite>,
) -> String {
    let now = ctx.now;
    let invite = invite.map(|i| {
        let href = format!("/support/{}", i.session_id);
        view! {
            <section class="card reveal" role="alert">
                <h2>"Invitation ready"</h2>
                <p>"Read this code to the person you are helping, or send them the link. It works once, in one browser, for "{i.minutes}" minutes."</p>
                <p class="code-big">{i.code}</p>
                <p class="muted">"They go to "<span class="mono">{i.entry_url}</span>" and type the code, or open:"</p>
                <pre class="output secret">{i.link}</pre>
                <p><a class="button" href=href>"Open the session"</a></p>
            </section>
        }
    });
    let rows = if sessions.is_empty() {
        view! { <p class="empty">"No support sessions yet."</p> }.into_any()
    } else {
        let body = sessions
            .into_iter()
            .map(|s| {
                let href = format!("/support/{}", s.id);
                view! {
                    <tr>
                        <td data-label="Session"><a href=href class="mono">{fmt::short_id(s.id)}</a></td>
                        <td data-label="For">{s.note.clone().unwrap_or_else(|| "—".into())}<div class="muted">{s.organization.clone()}</div></td>
                        <td data-label="State">{support_state_badge(s.state, s.state_label)}</td>
                        <td data-label="Created">{time_cell(now, s.created_at)}" · "{s.created_by.clone()}</td>
                    </tr>
                }
            })
            .collect_view();
        view! {
            <table class="list">
                <thead><tr><th scope="col">"Session"</th><th scope="col">"For"</th><th scope="col">"State"</th><th scope="col">"Created"</th></tr></thead>
                <tbody>{body}</tbody>
            </table>
        }
        .into_any()
    };
    let control_choice = ctx.can_control.then(|| view! {
        <label class="inline"><input type="radio" name="capability" value="control"/>" View and control (needs the helper)"</label>
    });
    let no_orgs = orgs.is_empty().then(|| view! { <p class="flash bad">"You are not assigned to any organization, so you cannot start a session. Ask an administrator."</p> });
    let org_options = orgs
        .into_iter()
        .map(|o| view! { <option value=o.id.to_string()>{o.name}</option> })
        .collect_view();
    let body = view! {
        <h1>"Support"</h1>
        {no_orgs}
        {invite}
        <section class="card">
            <h2>"Start an attended session"</h2>
            <p>"The person you are helping opens a link in their browser and chooses a tab, a window, or their screen to show you. With "<strong>"view"</strong>" you can see it and nothing more. With "<strong>"control"</strong>" they also run the flyw8t helper and allow it there, and you can use their mouse and keyboard. Nothing is installed, and the session ends when either of you ends it."</p>
            <form method="post" action="/support" class="inline-form">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"Organization"<select name="organization" required=true>{org_options}</select></label>
                <label>"Who are you helping? (optional)"<input type="text" name="note" maxlength="200" placeholder="Front desk, printer issue"/></label>
                <fieldset class="inline"><legend>"Request"</legend>
                    <label class="inline"><input type="radio" name="capability" value="view" checked=true/>" View screen"</label>
                    {control_choice}
                </fieldset>
                <button type="submit">"Create invitation"</button>
            </form>
        </section>
        <section>
            <h2>"Recent sessions"</h2>
            {rows}
        </section>
    };
    shell("Support", ctx, Nav::Support, None, body)
}

pub fn support_session_page(ctx: &PageCtx, s: SupportSessionView, ice_servers: &str) -> String {
    let title = format!("Support session {}", fmt::short_id(s.id));
    let end_url = format!("/support/{}/end", s.id);
    let live = !s.terminal;
    let end_form = live.then(|| {
        view! {
            <form method="post" action=end_url class="inline-form">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <button type="submit" class="bad" id="end-live">"End session"</button>
                <span class="muted">"Ending is immediate and the invitation can never be used again."</span>
            </form>
        }
    });
    let ended = s.ended_at.map(|t| {
        view! { <p class="muted">{format!("Ended {} — {}", fmt::timestamp(t), s.end_reason.clone().unwrap_or_default())}</p> }
    });
    let caps = s
        .capabilities
        .join(", ")
        .replace("view_screen", "view screen")
        .replace("control_input", "keyboard and mouse (through the helper)");
    let control = if s.capabilities.iter().any(|c| c == "control_input") {
        "1"
    } else {
        "0"
    };
    // Only the technician who created the session receives its signaling. Anyone else allowed
    // to see it (an administrator) gets its state and an End button, and no script.
    let observer = s.observer.then(|| view! {
        <p class="flash">{format!("Only {} can view this session. You can end it.", s.created_by)}</p>
    });
    let script = live && !s.observer;
    let (state, label) = if script && s.state == "connected" {
        ("checking", "Checking connection…")
    } else {
        (s.state, s.state_label)
    };
    let data_state = if s.terminal { "ended" } else { state };
    let body = view! {
        <p class="crumbs"><a href="/support">"Support"</a>" / "</p>
        <h1>{title.clone()}" "<span id="state-badge" class=support_badge_class(state)>{label}</span></h1>
        <div id="support" data-role="technician" data-session=s.id.to_string() data-control=control data-csrf=ctx.csrf.clone() data-ice=ice_servers.to_string() data-state=data_state>
            <p class="lead" id="state" aria-live="polite">{label}</p>
            <p class="muted" id="peer" aria-live="polite" hidden=true></p>
            <p class="flash bad" id="error" aria-live="assertive"></p>
            {observer}
            {ended}
            <dl class="facts card">
                <dt>"Organization"</dt><dd>{s.organization.clone()}</dd>
                <dt>"Technician"</dt><dd>{s.created_by.clone()}</dd>
                <dt>"For"</dt><dd>{s.note.clone().unwrap_or_else(|| "—".into())}</dd>
                <dt>"Granted"</dt><dd>{caps}</dd>
                <dt>"Invitation valid until"</dt><dd>{fmt::timestamp(s.invite_expires_at)}</dd>
            </dl>
            <div id="sas-box" class="card sas" hidden=true>
                <strong>"Security code: "</strong><span id="sas" class="mono"></span>
                <p class="muted">"Ask them to read the code on their screen. If it is different, end the session: someone may be in the middle."</p>
            </div>
            <section id="viewer" class="card" hidden=true>
                <h2>"Their shared screen"</h2>
                <video id="remote" autoplay=true muted=true playsinline=true></video>
                <p id="screenshot-status" class="muted" role="status" hidden=true></p>
                <details id="connection-details">
                    <summary>"Connection details"</summary>
                    <dl class="facts">
                        <dt>"Route"</dt><dd id="connection-route">"Unavailable"</dd>
                        <dt>"Session ID"</dt><dd class="mono">{s.id.to_string()}</dd>
                    </dl>
                </details>
            </section>
            {end_form}
            <noscript><p class="flash bad">"Viewing a shared screen needs JavaScript."</p></noscript>
        </div>
    };
    shell_with(
        &title,
        ctx,
        Nav::Support,
        None,
        script.then_some("/static/support.js"),
        body,
    )
}

/// The participant's pages: no account, no navigation.
fn participant_shell(title: &str, script: bool, body: impl IntoView + 'static) -> String {
    render(view! {
        <html lang="en">
            {head(format!("{title} · flyw8t"), None, script.then_some("/static/support.js"))}
            <body class="login">
                <main class="card narrow">{body}</main>
            </body>
        </html>
    })
}

pub fn support_entry_page(error: Option<String>) -> String {
    let err = error.map(|e| view! { <p class="flash bad" role="alert">{e}</p> });
    participant_shell(
        "Get help",
        false,
        view! {
            <h1>"Get help from your technician"</h1>
            <p>"Enter the 9-digit code your technician gave you. You will see who is asking and what they are asking for before anything is shared."</p>
            {err}
            <form method="post" action="/s" class="stack">
                <label>"Code"<input type="text" name="code" inputmode="numeric" autocomplete="off" maxlength="15" required=true autofocus=true placeholder="123 456 789"/></label>
                <button type="submit">"Continue"</button>
            </form>
        },
    )
}

/// Opening an invitation link does not spend it: the person confirms first, so a link that
/// is merely previewed or prefetched stays usable, and nothing binds a browser without a click.
pub fn support_link_page(invite: &str) -> String {
    let action = format!("/s/{invite}");
    participant_shell(
        "Get help",
        false,
        view! {
            <h1>"Get help from your technician"</h1>
            <p>"You were sent a link to share your screen with a technician. Continue to see who is asking and what they are asking for. Nothing is shared until you choose to."</p>
            <form method="post" action=action class="stack">
                <button type="submit">"Continue"</button>
            </form>
            <p class="muted">"The link works once, in one browser."</p>
        },
    )
}

pub fn support_consent_page(v: SupportConsentView, ice_servers: &str) -> String {
    let caps = v
        .capabilities
        .into_iter()
        .map(|c| view! { <li>{c}</li> })
        .collect_view();
    // A control request says so in the heading: it is not a screen-sharing request.
    let heading = if v.control {
        format!("{} wants to see and control your screen", v.technician_name)
    } else {
        format!("{} wants to see your screen", v.technician_name)
    };
    let who = format!(
        "Requested by {} ({}), as known to {}.",
        v.technician_name, v.technician_email, v.server_host
    );
    let deciding = v.state == "authorizing";
    let live_heading = format!("Support with {}", v.technician_name);
    let page_heading = if deciding {
        heading
    } else {
        live_heading.clone()
    };
    let awaiting = v.state == "awaiting_helper";
    let allow_label = if v.control {
        "Allow, and get the flyw8t helper"
    } else {
        "Allow, and choose what to share"
    };
    let cannot = if v.control {
        view! {
            <ul>
                <li>"Do anything before you also allow it in the helper\u{2019}s own window."</li>
                <li>"Reach administrator (UAC) prompts or the sign-in screen."</li>
                <li>"Keep access after you press Stop, end the session, or close the helper."</li>
            </ul>
        }
        .into_any()
    } else {
        view! {
            <ul>
                <li>"Move your mouse, type, or click anything."</li>
                <li>"See anything you do not choose in the next step."</li>
                <li>"Keep access after you end the session or close this page."</li>
            </ul>
        }
        .into_any()
    };
    let control = if v.control { "1" } else { "0" };
    let (state, label) = if v.state == "connected" {
        ("checking", "Checking connection…")
    } else {
        (v.state, v.state_label)
    };
    participant_shell(
        if v.control {
            "Remote control request"
        } else {
            "Screen sharing request"
        },
        true,
        view! {
            <div id="support" data-role="participant" data-session=v.session_id.to_string() data-ice=ice_servers.to_string() data-state=state data-control=control>
                <h1 id="participant-heading" data-live=live_heading>{page_heading}</h1>
                <p>{who}</p>
                // Live status and the way out come first, so ending is always one tap away.
                <div class="live">
                    <p class="lead" id="state" aria-live="polite">{label}</p>
                    <p class="muted" id="peer" aria-live="polite" hidden=true></p>
                    <p class="flash bad" id="error" aria-live="assertive"></p>
                    <button type="button" id="end" class="bad" hidden=true>"Stop sharing and end the session"</button>
                    <section id="screenshot-panel" aria-labelledby="screenshot-title" hidden=true>
                        <h2 id="screenshot-title" aria-live="polite">"Allow screenshots?"</h2>
                        <p class="screenshot-client">"AI client · "<strong id="screenshot-recipient"></strong></p>
                        <p id="screenshot-description"></p>
                        <div class="screenshot-actions">
                            <button type="button" id="screenshot-allow">"Allow screenshots"</button>
                            <button type="button" id="screenshot-decline" class="secondary">"Decline"</button>
                            <button type="button" id="screenshot-revoke" class="secondary" hidden=true>"Turn off screenshots"</button>
                        </div>
                    </section>
                    <div id="sas-box" class="sas" hidden=true>
                        <strong>"Security code: "</strong><span id="sas" class="mono"></span>
                        <p class="muted">"Your technician should read you the same code. If it is different, end the session."</p>
                    </div>
                    <div id="helper-box" class="card" hidden=!awaiting>
                        <p><strong>"Next: run the flyw8t helper."</strong>" It opens a window that asks you once more, shows who is asking and a security code, and has a Stop button. It installs nothing."</p>
                        // The link carries no secret (the token is minted by the download), so it is
                        // here from the start: a reloaded page can still get the helper.
                        <p><a id="helper-link" class="button" href="/s/helper/download">"Download the helper"</a></p>
                        <p class="muted" id="helper-note">"The download works for two minutes. If it expires, decline and ask for a new session."</p>
                        <button type="button" id="cancel-helper" class="bad">"Cancel"</button>
                    </div>
                </div>
                <div id="screen-permissions" hidden=!deciding>
                    <h2>"If you allow, they can"</h2>
                    <ul>{caps}</ul>
                    <h2>"They cannot"</h2>
                    {cannot}
                </div>
                <div id="decide" class="stack" hidden=!deciding>
                    <button type="button" id="allow">{allow_label}</button>
                    <button type="button" id="decline" class="bad">"Decline"</button>
                </div>
                <noscript><p class="flash bad">"This page needs JavaScript in this browser."</p></noscript>
            </div>
        },
    )
}

// ---------------------------------------------------------------------------------------
// Two-step verification

/// A QR code as one SVG path built from the module matrix: markup, not a script or an image
/// resource, so it passes the console's `default-src 'none'` policy.
fn qr_svg(data: &str) -> impl IntoView {
    let Ok(code) = qrcode::QrCode::new(data.as_bytes()) else {
        return view! { <p class="muted">"QR code unavailable; enter the key by hand."</p> }
            .into_any();
    };
    let width = code.width();
    let quiet = 4;
    let mut d = String::new();
    for (i, c) in code.to_colors().into_iter().enumerate() {
        if c == qrcode::Color::Dark {
            d.push_str(&format!(
                "M{} {}h1v1h-1z",
                i % width + quiet,
                i / width + quiet
            ));
        }
    }
    let size = width + 2 * quiet;
    let view_box = format!("0 0 {size} {size}");
    view! {
        <svg class="qr" viewBox=view_box role="img" aria-label="QR code for your authenticator app" shape-rendering="crispEdges">
            <rect width="100%" height="100%" fill="#fff"/>
            <path d=d fill="#000"/>
        </svg>
    }
    .into_any()
}

/// A standalone card page, like sign-in, for steps before the console is reachable.
fn card_page(title: &str, body: impl IntoView + 'static) -> String {
    render(view! {
        <html lang="en">
            {head(format!("{title} · flyw8t"), None, None)}
            <body class="login">
                <main class="card narrow">{body}</main>
            </body>
        </html>
    })
}

/// The second sign-in step: a code from the authenticator app, or a recovery code.
pub fn mfa_challenge_page(csrf: String, error: Option<String>) -> String {
    let err = error.map(|e| view! { <p class="flash bad" role="alert">{e}</p> });
    card_page(
        "Two-step verification",
        view! {
            <h1>"Two-step verification"</h1>
            <p class="muted">"Enter the 6-digit code from your authenticator app."</p>
            {err}
            <form method="post" action="/login/mfa" class="stack">
                <input type="hidden" name="csrf" value=csrf/>
                <label>"Code"<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required=true autofocus=true maxlength="24" spellcheck="false"/></label>
                <button type="submit">"Verify"</button>
            </form>
            <p class="muted">"Lost your device? Enter one of your recovery codes in the same box instead. Each works once."</p>
            <p><a href="/login">"Sign in as someone else"</a></p>
        },
    )
}

pub fn mfa_setup_page(v: MfaSetupView) -> String {
    let intro = if v.forced {
        "This server requires two-step verification. Set it up now to continue."
    } else {
        "Add a second step to signing in."
    };
    let err = v
        .error
        .map(|e| view! { <p class="flash bad" role="alert">{e}</p> });
    let cancel = (!v.forced).then(|| view! { <p><a href="/account">"Cancel"</a></p> });
    card_page(
        "Set up two-step verification",
        view! {
            <h1>"Set up two-step verification"</h1>
            <p class="muted">{intro}</p>
            {err}
            <ol class="steps">
                <li>"Scan this with an authenticator app (for example Aegis, 2FAS, Google Authenticator or a password manager)."</li>
            </ol>
            {qr_svg(&v.otpauth_uri)}
            <p class="muted">"Can't scan? Enter this key for "<strong>{v.email}</strong>" (time-based, 6 digits, 30 seconds):"</p>
            <pre class="output secret" id="totp-key">{v.secret}</pre>
            <ol class="steps" start="2">
                <li>"Enter the code the app shows to confirm it works."</li>
            </ol>
            <form method="post" action="/account/mfa" class="stack">
                <input type="hidden" name="csrf" value=v.csrf/>
                <label>"Code"<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required=true autofocus=true maxlength="12" spellcheck="false"/></label>
                <button type="submit">"Turn on"</button>
            </form>
            {cancel}
        },
    )
}

/// Shown once, straight after the codes are made. Only their hashes are stored.
pub fn recovery_codes_page(codes: Vec<String>, continue_href: &str) -> String {
    let list = codes.join("\n");
    let href = continue_href.to_string();
    card_page(
        "Recovery codes",
        view! {
            <h1>"Save your recovery codes"</h1>
            <section class="reveal" role="alert">
                <p><strong>"These are shown once."</strong>" Each one signs you in a single time if you lose your authenticator. Keep them somewhere safe, apart from your password."</p>
                <pre class="output secret" id="recovery-codes">{list}</pre>
            </section>
            <p><a class="button" href=href>"I've saved them, continue"</a></p>
        },
    )
}

pub fn account_page(ctx: &PageCtx, a: AccountView) -> String {
    let now = ctx.now;
    let csrf = ctx.csrf.clone();
    let mfa = match a.mfa_enabled_at {
        Some(at) => {
            let disable = (!a.require_mfa).then(|| {
                view! {
                    <form method="post" action="/account/mfa/disable" class="inline-form card">
                        <input type="hidden" name="csrf" value=csrf.clone()/>
                        <label>"Current code"<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required=true maxlength="12"/></label>
                        <button type="submit" class="bad">"Turn off two-step verification"</button>
                    </form>
                }
            });
            let required = a.require_mfa.then(|| view! {
                <p class="muted">"This server requires two-step verification, so it cannot be turned off here. If you lose your authenticator and your recovery codes, an administrator can reset it."</p>
            });
            view! {
                <p><span class="badge good">"On"</span>" since "{time_cell(now, at)}". "{format!("{} unused recovery codes.", a.recovery_remaining)}</p>
                <form method="post" action="/account/mfa/recovery-codes" class="inline-form card">
                    <input type="hidden" name="csrf" value=csrf.clone()/>
                    <label>"Current code"<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required=true maxlength="12"/></label>
                    <button type="submit">"Replace recovery codes"</button>
                </form>
                {disable}
                {required}
            }
            .into_any()
        }
        None => view! {
            <p><span class="badge bad">"Off"</span>" Anyone with your password can sign in as you."</p>
            <p><a class="button" href="/account/mfa">"Set up two-step verification"</a></p>
        }
        .into_any(),
    };
    let sudo = a.sudo_until.map(|t| {
        view! {
            <p><span class="badge good">"Sudo mode"</span>" until "{fmt::timestamp(t)}"."</p>
        }
    });
    let passkey_rows = a
        .passkeys
        .into_iter()
        .map(|k| {
            let url = format!("/account/passkeys/{}/remove", k.id);
            let used = match k.last_used_at {
                Some(t) => time_cell(now, t).into_any(),
                None => view! { <span class="muted">"never"</span> }.into_any(),
            };
            view! {
                <tr>
                    <td data-label="Name">{k.name}</td>
                    <td data-label="Added">{time_cell(now, k.created_at)}</td>
                    <td data-label="Last used">{used}</td>
                    <td>
                        <form method="post" action=url class="inline-form">
                            <input type="hidden" name="csrf" value=csrf.clone()/>
                            <button type="submit" class="link">"Remove"</button>
                        </form>
                    </td>
                </tr>
            }
        })
        .collect::<Vec<_>>();
    let passkeys = if passkey_rows.is_empty() {
        view! {
            <p><span class="badge neutral">"None"</span>" Changes that widen what can run (custom field definitions, users, API tokens) need one."</p>
            <p><a class="button" href="/account/passkeys/new">"Add a passkey"</a></p>
        }
        .into_any()
    } else {
        view! {
            <table class="list">
                <thead><tr><th>"Name"</th><th>"Added"</th><th>"Last used"</th><th></th></tr></thead>
                <tbody>{passkey_rows}</tbody>
            </table>
            {sudo}
            <p><a href="/account/passkeys/new">"Add another"</a>" · "<a href="/sudo?next=/account">"Confirm now (sudo mode)"</a></p>
        }
        .into_any()
    };
    let others = a.sessions.iter().filter(|s| !s.current).count();
    let session_rows = a
        .sessions
        .into_iter()
        .map(|s| {
            let url = format!("/account/sessions/{}/revoke", s.id);
            let label = if s.current { "Sign out" } else { "Sign out that session" };
            let state = match (s.current, s.partial) {
                (true, _) => view! { <span class="badge good">"This browser"</span> }.into_any(),
                (false, true) => view! { <span class="badge bad" title="The password was accepted and the second step has not been finished. If this was not you, change your password.">"Password only"</span> }.into_any(),
                (false, false) => view! { <span class="badge neutral">"Signed in"</span> }.into_any(),
            };
            view! {
                <tr>
                    <td data-label="Browser" title=s.user_agent.clone()>{browser_summary(&s.user_agent)}" "{state}</td>
                    <td data-label="Address" class="mono">{s.client_ip}</td>
                    <td data-label="Signed in">{time_cell(now, s.created_at)}</td>
                    <td data-label="Last active">{time_cell(now, s.last_seen_at)}</td>
                    <td>
                        <form method="post" action=url class="inline-form">
                            <input type="hidden" name="csrf" value=csrf.clone()/>
                            <button type="submit" class="link">{label}</button>
                        </form>
                    </td>
                </tr>
            }
        })
        .collect::<Vec<_>>();
    let revoke_others = (others > 0).then(|| {
        view! {
            <form method="post" action="/account/sessions/revoke-others" class="inline-form">
                <input type="hidden" name="csrf" value=csrf.clone()/>
                <button type="submit" class="bad">"Sign out everywhere else"</button>
            </form>
        }
    });
    let password = (!a.directory)
        .then(|| crate::admin::password_card(ctx, a.password_temporary, a.password_changed_at));
    let mfa = if a.directory {
        view!{<p>"Sign-in and MFA are managed by your organization. Your local passkey confirms sudo mode."</p>}.into_any()
    } else {
        mfa
    };
    let body = view! {
        <h1>"Your account"</h1>
        <dl class="facts">
            <dt>"Name"</dt><dd>{a.display_name}</dd>
            <dt>"Email"</dt><dd>{a.email}</dd>
            <dt>"Role"</dt><dd>{ctx.role}</dd>
        </dl>
        <section>
            <h2>"Two-step verification"</h2>
            {mfa}
        </section>
        <section>
            <h2>"Passkeys and security keys"</h2>
            {passkeys}
        </section>
        {password}
        <section>
            <h2>"Where you are signed in"</h2>
            <p class="muted">{if a.directory {"Browsers holding a session of yours. Sign out any you do not recognize, then review your organization sign-in security."} else {"Browsers holding a session of yours. One you do not recognise means someone has your password: sign it out, then change your password."}}</p>
            <table class="list">
                <thead><tr><th>"Browser"</th><th>"Address"</th><th>"Signed in"</th><th>"Last active"</th><th></th></tr></thead>
                <tbody>{session_rows}</tbody>
            </table>
            {revoke_others}
        </section>
    };
    shell("Your account", ctx, Nav::Account, None, body)
}

/// A short name for a user agent ("Edge on Windows"); the full string is shown on hover.
pub fn browser_summary(ua: &str) -> String {
    let browser = [
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
    ]
    .iter()
    .find(|(k, _)| ua.contains(k))
    .map(|(_, v)| *v);
    let os = [
        ("Windows", "Windows"),
        ("iPhone", "iPhone"),
        ("iPad", "iPad"),
        ("Android", "Android"),
        ("Mac OS X", "macOS"),
        ("CrOS", "ChromeOS"),
        ("Linux", "Linux"),
    ]
    .iter()
    .find(|(k, _)| ua.contains(k))
    .map(|(_, v)| *v);
    match (browser, os) {
        (Some(b), Some(o)) => format!("{b} on {o}"),
        (Some(b), None) => b.to_string(),
        (None, Some(o)) => format!("A browser on {o}"),
        (None, None) if ua.is_empty() => "Unknown browser".to_string(),
        (None, None) => ua.chars().take(40).collect(),
    }
}

/// A WebAuthn ceremony as a form: `/static/passkey.js` runs it when the form is submitted, fills the hidden fields and
/// posts. The button starts disabled and the script enables it once it is ready, so a click
/// before the script has loaded cannot post the form with its ceremony fields empty. `fields` are the visible inputs that go with it.
fn ceremony_form(
    c: WebAuthnCeremony,
    csrf: String,
    fields: impl IntoView + 'static,
    button: &'static str,
) -> impl IntoView {
    let err = c
        .error
        .map(|e| view! { <p class="flash bad" role="alert">{e}</p> });
    let hidden = [
        "client_data_json",
        "attestation_object",
        "credential_id",
        "authenticator_data",
        "signature",
    ]
    .map(|n| view! { <input type="hidden" name=n value=""/> });
    view! {
        {err}
        <form method="post" action=c.action id="webauthn" class="stack" data-options=c.options>
            <input type="hidden" name="csrf" value=csrf/>
            {fields}
            {hidden}
            <button type="submit" disabled=true>{button}</button>
            <p id="webauthn-status" class="muted" role="status"></p>
        </form>
        <noscript><p class="flash bad">"Passkeys need JavaScript in this browser."</p></noscript>
    }
}

/// Registering a passkey or security key.
pub fn passkey_new_page(ctx: &PageCtx, v: PasskeyNewView) -> String {
    let password = v.needs_password.then(|| view! {
        <p class="muted">"Your first passkey needs your password, so that someone holding only your signed-in browser cannot add one."</p>
        <label>"Password"<input type="password" name="password" autocomplete="current-password" required=true/></label>
    });
    let code = v.needs_code.then(|| view! {
        <label>"Current code"<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required=true maxlength="12"/></label>
    });
    let fields = view! {
        <label>"Name"<input type="text" name="name" required=true maxlength="100" placeholder="YubiKey on my keyring"/></label>
        {password}
        {code}
    };
    let body = view! {
        <h1>"Add a passkey"</h1>
        <p class="muted">"A passkey or security key confirms changes that widen what can run (sudo mode), and will sign script approvals. It must check that it is you (a PIN, a fingerprint or your device's unlock), not only be touched."</p>
        {ceremony_form(v.ceremony, ctx.csrf.clone(), fields, "Add passkey")}
        <p><a href="/account">"Cancel"</a></p>
    };
    shell_with(
        "Add a passkey",
        ctx,
        Nav::Account,
        None,
        Some("/static/passkey.js"),
        body,
    )
}

/// Sudo mode: confirm a passkey before a change that widens what can run.
pub fn sudo_page(ctx: &PageCtx, v: SudoView) -> String {
    let next = v.next.clone();
    let inner = match v.ceremony {
        Some(c) => {
            let fields = view! { <input type="hidden" name="next" value=next/> };
            view! {
                <p class="muted">{format!("Changes to custom field definitions, users, API tokens and two-step verification need a fresh confirmation with your passkey. It lasts {} minutes; then come back and make the change.", v.minutes)}</p>
                {ceremony_form(c, ctx.csrf.clone(), fields, "Confirm with passkey")}
            }
            .into_any()
        }
        None => view! {
            <p>"This change needs a passkey or security key, and you have not added one yet."</p>
            <p><a class="button" href="/account/passkeys/new">"Add a passkey"</a></p>
        }
        .into_any(),
    };
    let body = view! {
        <h1>"Confirm it is you"</h1>
        {inner}
        <p><a href=v.next>"Back"</a></p>
    };
    shell_with(
        "Confirm it is you",
        ctx,
        Nav::Account,
        None,
        Some("/static/passkey.js"),
        body,
    )
}

fn sessions_cell(u: &UserRow, csrf: &str) -> impl IntoView {
    if u.sessions == 0 {
        return view! { <span class="muted">"none"</span> }.into_any();
    }
    let url = format!("/admin/users/{}/sign-out", u.id);
    view! {
        {u.sessions.to_string()}
        <form method="post" action=url class="inline-form">
            <input type="hidden" name="csrf" value=csrf.to_string()/>
            <button type="submit" class="link" title="Ends every session of theirs and the support sessions they started">"Sign out everywhere"</button>
        </form>
    }
    .into_any()
}

fn mfa_cell(u: &UserRow, csrf: &str) -> impl IntoView {
    if !u.mfa && u.passkeys == 0 {
        return view! { <span class="badge neutral">"Not set up"</span> }.into_any();
    }
    let keys = (u.passkeys > 0).then(|| {
        let n = if u.passkeys == 1 {
            "1 passkey".to_string()
        } else {
            format!("{} passkeys", u.passkeys)
        };
        view! { " "<span class="badge good">{n}</span> }
    });
    let code = if u.mfa {
        view! { <span class="badge good">"On"</span> }.into_any()
    } else {
        view! { <span class="badge neutral">"No code"</span> }.into_any()
    };
    let url = format!("/admin/users/{}/mfa/reset", u.id);
    view! {
        {code}
        {keys}
        <form method="post" action=url class="inline-form">
            <input type="hidden" name="csrf" value=csrf.to_string()/>
            <button type="submit" class="link" title="Removes their authenticator, recovery codes and passkeys, and signs them out everywhere">"Reset"</button>
        </form>
    }
    .into_any()
}

// ---------------------------------------------------------------------------------------
// Script library (ADR-0014)

/// Largest file the editor loads (the server's limit on a script).
const MAX_SCRIPT_BYTES: usize = 256 * 1024;

fn script_scope(s: &ScriptView) -> impl IntoView {
    match &s.organization {
        Some(o) => {
            let href = format!("/organizations/{}", o.id);
            view! { <a href=href>{o.name.clone()}</a> }.into_any()
        }
        None => {
            view! { <span class="badge neutral">"global"</span>" every organization" }.into_any()
        }
    }
}

fn diff_table(rows: Vec<DiffRow>) -> impl IntoView {
    let body = rows
        .into_iter()
        .map(|r| match r {
            DiffRow::Same { old, new, text } => view! {
                <tr><td class="n">{old}</td><td class="n">{new}</td><td class="t">{format!("  {text}")}</td></tr>
            }
            .into_any(),
            DiffRow::Removed { old, text } => view! {
                <tr class="del"><td class="n">{old}</td><td class="n"></td><td class="t">{format!("- {text}")}</td></tr>
            }
            .into_any(),
            DiffRow::Added { new, text } => view! {
                <tr class="add"><td class="n"></td><td class="n">{new}</td><td class="t">{format!("+ {text}")}</td></tr>
            }
            .into_any(),
            DiffRow::Folded(n) => view! {
                <tr class="fold"><td colspan="3">{format!("⋯ {n} unchanged line{}", if n == 1 { "" } else { "s" })}</td></tr>
            }
            .into_any(),
        })
        .collect_view();
    view! { <table class="diff"><tbody>{body}</tbody></table> }
}

/// What the server's checks found, for a saved revision.
fn script_checks(
    r: &RevisionView,
    problems: &[ScriptProblem],
    missing: &[MissingRequired],
) -> impl IntoView {
    let source_problems = problems.iter().any(|p| p.section == "source");
    let syntax = match (&r.checker, &r.unchecked) {
        (Some(c), _) if !source_problems => format!("Syntax checked by {c}: no problems found."),
        (Some(c), _) => format!("Syntax checked by {c} when saved: see below."),
        (None, Some(why)) => why.clone(),
        (None, None) => "Not checked.".into(),
    };
    let tone = if r.checker.is_some() { "" } else { "flash bad" };
    let list = (!problems.is_empty()).then(|| {
        let items = problems
            .iter()
            .map(|p| {
                let place = match p.line {
                    Some(n) => format!(
                        "{}, line {n}: ",
                        if p.section == "source" {
                            "Script"
                        } else {
                            "Parameters"
                        }
                    ),
                    None => format!(
                        "{}: ",
                        if p.section == "source" {
                            "Script"
                        } else {
                            "Parameters"
                        }
                    ),
                };
                view! { <li><strong>{place}</strong>{p.message.clone()}</li> }
            })
            .collect_view();
        view! { <ul class="problems">{items}</ul> }
    });
    let missing_view = (!missing.is_empty()).then(|| {
        let items = missing
            .iter()
            .map(|m| {
                let text = if m.level == "global" {
                    format!("{} ({}): no global value or default", m.label, m.key)
                } else {
                    format!(
                        "{} ({}): {} {}(s) without a value",
                        m.label, m.key, m.total, m.level
                    )
                };
                view! { <li>{text}</li> }
            })
            .collect_view();
        view! {
            <p>"Required values this script reads are missing; it would not run there:"</p>
            <ul class="problems">{items}</ul>
        }
    });
    view! {
        <section class="card">
            <h2>"Checks"</h2>
            <p class=tone>{syntax}</p>
            {list}
            {missing_view}
            <p class="hint">"A clean check says nothing about what a script does."</p>
        </section>
    }
}

pub fn scripts_page(
    ctx: &PageCtx,
    rows: Vec<ScriptListRow>,
    orgs: Vec<OrgRef>,
    can_edit: bool,
) -> String {
    let now = ctx.now;
    let none = rows.is_empty();
    let body_rows = rows
        .into_iter()
        .map(|r| {
            let href = format!("/scripts/{}", r.id);
            let scope = match r.organization {
                Some(o) => view! { <span>{o}</span> }.into_any(),
                None => view! { <span class="badge neutral">"global"</span> }.into_any(),
            };
            let latest = match (r.latest, r.risk_class) {
                (Some(n), Some(risk)) => format!("revision {n} · {risk}"),
                _ => "no revision yet".into(),
            };
            let saved = match (r.updated_by, r.updated_at) {
                (Some(by), Some(at)) => {
                    view! { <span>{by}" · "<time datetime=fmt::iso(at)>{fmt::ago(now, at)}</time></span> }.into_any()
                }
                _ => view! { <span class="muted">"—"</span> }.into_any(),
            };
            view! {
                <tr>
                    <td data-label="Script"><a href=href><strong>{r.name}</strong></a></td>
                    <td data-label="Belongs to">{scope}</td>
                    <td data-label="Language">{r.language_label}</td>
                    <td data-label="Latest">{latest}</td>
                    <td data-label="Saved">{saved}</td>
                </tr>
            }
        })
        .collect_view();
    let create = can_edit.then(|| {
        let options = orgs
            .into_iter()
            .map(|o| view! { <option value=o.id.to_string()>{o.name}</option> })
            .collect_view();
        view! {
            <section class="card">
                <h2>"New script"</h2>
                <form method="post" action="/scripts" class="stack">
                    <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                    <label>"Name"<input type="text" name="name" required=true maxlength="100"/></label>
                    <label>"Belongs to"<select name="scope">
                        <option value="global">"Global: every organization"</option>
                        {options}
                    </select></label>
                    <label>"Language"<select name="language">
                        <option value="powershell">"PowerShell"</option>
                        <option value="bash">"Bash"</option>
                        <option value="python">"Python"</option>
                    </select></label>
                    <label>"Description (optional)"<textarea name="description" rows="2" maxlength="2000"></textarea></label>
                    <button type="submit">"Create"</button>
                </form>
            </section>
        }
    });
    let body = view! {
        <h1>"Scripts"</h1>
        <p class="lead">"Every save is a new revision; none is ever changed or removed. All are drafts for now: nothing runs scripts yet, and approval comes next."</p>
        {none.then(|| view! { <p class="empty">"No scripts yet."</p> })}
        <section hidden=none>
            <table class="list">
                <thead><tr><th scope="col">"Script"</th><th scope="col">"Belongs to"</th><th scope="col">"Language"</th><th scope="col">"Latest"</th><th scope="col">"Saved"</th></tr></thead>
                <tbody>{body_rows}</tbody>
            </table>
        </section>
        {create}
    };
    shell("Scripts", ctx, Nav::Scripts, None, body)
}

#[allow(clippy::too_many_arguments)]
pub fn script_page(
    ctx: &PageCtx,
    s: ScriptView,
    latest: Option<RevisionView>,
    problems: Vec<ScriptProblem>,
    missing: Vec<MissingRequired>,
    history: Vec<RevisionSummary>,
    draft: ScriptDraft,
    can_edit: bool,
) -> String {
    let now = ctx.now;
    let id = s.id;
    let facts = latest.as_ref().map(|r| {
        let download = format!("/scripts/{id}/revisions/{}/download", r.number);
        let view_href = format!("/scripts/{id}/revisions/{}", r.number);
        view! {
            <dl class="facts card">
                <dt>"Latest"</dt><dd><a href=view_href>{format!("Revision {}", r.number)}</a>" · draft · "<a href=download>"download"</a></dd>
                <dt>"Risk class"</dt><dd>{r.risk_class.clone()}</dd>
                <dt>"Saved"</dt><dd>{r.author.clone()}" · "<time datetime=fmt::iso(r.created_at)>{fmt::timestamp(r.created_at)}</time></dd>
                <dt>"SHA-256"</dt><dd class="mono">{r.hash.clone()}</dd>
            </dl>
        }
    });
    let checks = latest
        .as_ref()
        .map(|r| script_checks(r, &problems, &missing));
    let editor = if can_edit {
        let action = format!("/scripts/{id}/revisions");
        let risks = [
            ("C0", "C0: read-only"),
            ("C1", "C1: bounded and reversible"),
            (
                "C2",
                "C2: consequential (each run will need a second approval)",
            ),
            ("C3", "C3: irreversible (interactive, one device at a time)"),
        ]
        .into_iter()
        .map(|(v, l)| view! { <option value=v selected=draft.risk_class == v>{l}</option> })
        .collect_view();
        let accept = format!(".{},.txt", s.extension);
        let save_label = format!("Save as revision {}", draft.base + 1);
        view! {
            <section class="card">
                <h2>{if draft.base == 0 { "First revision" } else { "Edit" }}</h2>
                <form method="post" action=action class="stack">
                    <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                    <input type="hidden" name="base" value=draft.base.to_string()/>
                    <label>{format!("Script ({})", s.language_label)}
                        <textarea id="source" name="source" class="code tall" rows="24" wrap="off" spellcheck="false" autocomplete="off" autocapitalize="off">{textarea_text(&draft.source)}</textarea>
                    </label>
                    <p class="hint">"Tab inserts a tab; Esc then Tab moves on. Values are never put into the text: read them as parameters."</p>
                    <div hidden=true>
                        <label>"Or load a file (review it before saving)"<input type="file" id="upload" accept=accept data-max=MAX_SCRIPT_BYTES.to_string()/></label>
                    </div>
                    <p id="upload-status" class="hint" aria-live="polite"></p>
                    <label>"Parameters"
                        <textarea name="parameters" class="code" rows="5" wrap="off" spellcheck="false" autocomplete="off" autocapitalize="off">{textarea_text(&draft.parameters)}</textarea>
                    </label>
                    <p class="hint">"One per line: "<span class="mono">"Share = {{org.backup_share}}"</span>", "<span class="mono">"Retries = \"3\""</span>", or "<span class="mono">"Reason = ask \"Why?\""</span>". Fields: global, org, device."</p>
                    <label>"Risk class"<select name="risk_class">{risks}</select></label>
                    <label>"What changed (optional)"<input type="text" name="note" maxlength="500" value=draft.note.clone()/></label>
                    <button type="submit">{save_label}</button>
                </form>
            </section>
        }
        .into_any()
    } else {
        match &latest {
            Some(r) => {
                let params = (!r.parameters.is_empty()).then(|| {
                    view! { <h2>"Parameters"</h2><pre class="code">{r.parameters.clone()}</pre> }
                });
                view! { <section class="card"><h2>"Script"</h2><pre class="code">{r.source.clone()}</pre>{params}</section> }
                    .into_any()
            }
            None => view! { <p class="empty">"No revision yet."</p> }.into_any(),
        }
    };
    let revisions = (!history.is_empty()).then(|| {
        let rows = history
            .into_iter()
            .map(|h| {
                let href = format!("/scripts/{id}/revisions/{}", h.number);
                let note = if h.note.is_empty() {
                    view! { <span class="muted">"—"</span> }.into_any()
                } else {
                    view! { <span>{h.note}</span> }.into_any()
                };
                view! {
                    <tr>
                        <td data-label="Revision"><a href=href>{h.number}</a></td>
                        <td data-label="Risk">{h.risk_class}</td>
                        <td data-label="What changed">{note}</td>
                        <td data-label="By">{h.author}</td>
                        <td data-label="When"><time datetime=fmt::iso(h.created_at)>{fmt::ago(now, h.created_at)}</time></td>
                        <td data-label="SHA-256" class="mono">{h.hash_prefix}</td>
                    </tr>
                }
            })
            .collect_view();
        view! {
            <section>
                <h2>"Revisions"</h2>
                <table class="list">
                    <thead><tr><th scope="col">"#"</th><th scope="col">"Risk"</th><th scope="col">"What changed"</th><th scope="col">"By"</th><th scope="col">"When"</th><th scope="col">"SHA-256"</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </section>
        }
    });
    let description = (!s.description.is_empty())
        .then(|| view! { <p class="muted notes">{s.description.clone()}</p> });
    let title = s.name.clone();
    let body = view! {
        <p class="crumbs"><a href="/scripts">"Scripts"</a>" / "</p>
        <h1>{title.clone()}</h1>
        <p>{s.language_label}" · "{script_scope(&s)}</p>
        {description}
        <p class="flash bad">"Drafts only: nothing runs scripts yet, and no revision is approved."</p>
        {facts}
        {checks}
        {editor}
        {revisions}
    };
    shell_with(
        &title,
        ctx,
        Nav::Scripts,
        None,
        can_edit.then_some("/static/editor.js"),
        body,
    )
}

/// One revision in full, and what changed since the one before.
pub fn script_revision_page(
    ctx: &PageCtx,
    s: ScriptView,
    r: RevisionView,
    problems: Vec<ScriptProblem>,
    missing: Vec<MissingRequired>,
    changes: Option<RevisionChanges>,
) -> String {
    let id = s.id;
    let n = r.number;
    let unchanged = |rows: &[DiffRow]| rows.iter().all(|d| matches!(d, DiffRow::Folded(_)));
    let changes_view = changes.map(|c| {
        let (source, params) = (c.source, c.parameters);
        let risk = c.risk_from.map(|old| view! { <p><strong>{format!("Risk class: {old} → {}", r.risk_class)}</strong></p> });
        let section = |label: &'static str, rows: Option<Vec<DiffRow>>| match rows {
            None => view! { <p>{format!("{label}: too large to compare here; download both revisions.")}</p> }.into_any(),
            Some(rows) if unchanged(&rows) => view! { <p class="muted">{format!("{label}: unchanged.")}</p> }.into_any(),
            Some(rows) => view! { <h3>{label}</h3>{diff_table(rows)} }.into_any(),
        };
        view! {
            <section class="card">
                <h2>{format!("Changes from revision {}", n - 1)}</h2>
                {risk}
                {section("Script", source)}
                {section("Parameters", params)}
            </section>
        }
    });
    let checks = script_checks(&r, &problems, &missing);
    let download = format!("/scripts/{id}/revisions/{n}/download");
    let script_href = format!("/scripts/{id}");
    let note =
        (!r.note.is_empty()).then(|| view! { <dt>"What changed"</dt><dd>{r.note.clone()}</dd> });
    let params = (!r.parameters.is_empty())
        .then(|| view! { <h2>"Parameters"</h2><pre class="code">{r.parameters.clone()}</pre> });
    let title = format!("{}: revision {n}", s.name);
    let body = view! {
        <p class="crumbs"><a href="/scripts">"Scripts"</a>" / "<a href=script_href>{s.name.clone()}</a>" / "</p>
        <h1>{title.clone()}</h1>
        <p>{s.language_label}" · "{script_scope(&s)}" · draft"</p>
        <dl class="facts card">
            <dt>"Risk class"</dt><dd>{r.risk_class.clone()}</dd>
            <dt>"Saved"</dt><dd>{r.author.clone()}" · "<time datetime=fmt::iso(r.created_at)>{fmt::timestamp(r.created_at)}</time></dd>
            {note}
            <dt>"SHA-256"</dt><dd class="mono">{r.hash.clone()}</dd>
            <dt>"File"</dt><dd><a href=download>"Download"</a></dd>
        </dl>
        {checks}
        {changes_view}
        <section class="card">
            <h2>"Script"</h2>
            <pre class="code">{r.source.clone()}</pre>
            {params}
        </section>
    };
    shell(&title, ctx, Nav::Scripts, None, body)
}

/// A committed same-origin document lets the following user navigation send Strict cookies.
pub fn oidc_complete_page() -> String {
    card_page(
        "Sign-in complete",
        view! {<h1>"Sign-in complete"</h1><p>"Your organization has signed you in."</p><p><a class="button" href="/">"Continue to flyw8t"</a></p>},
    )
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
            can_support: true,
            can_control: true,
            can_manage_devices: true,
            can_retire: true,
            can_view_scripts: true,
            flash: None,
            version: "9.9.9",
            family: Vec::new(),
        }
    }

    fn first_page() -> JobsView {
        JobsView {
            page: 1,
            ..Default::default()
        }
    }

    fn user(role: &str) -> UserDetail {
        UserDetail {
            directory: false,
            id: Uuid::nil(),
            email: "pat@example.com".into(),
            display_name: "Pat <img src=x>".into(),
            role: role.into(),
            disabled_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            organization_ids: vec![],
            mfa: false,
            passkeys: 0,
            sessions: 0,
            api_tokens: 0,
            password_changed_at: None,
            password_temporary: false,
            is_self: false,
            only_admin: false,
        }
    }

    #[test]
    fn a_users_page_offers_only_the_changes_that_can_be_made() {
        let html = crate::admin::user_page(&ctx(), user("technician"), vec![], None);
        assert!(!html.contains("<img src=x>"), "a name must be escaped");
        assert!(html.contains("Pat &lt;img src=x&gt;"));
        assert!(html.contains(r#"<select name="role""#));
        assert!(html.contains("/disable"));
        assert!(html.contains("/password"));
        // Yourself: no role choice, no disabling, and your password is changed on your own page.
        let mut me = user("admin");
        me.is_self = true;
        let html = crate::admin::user_page(&ctx(), me, vec![], None);
        assert!(!html.contains(r#"<select name="role""#));
        assert!(html.contains(r#"<input type="hidden" name="role" value="admin""#));
        assert!(!html.contains("/disable"));
        assert!(!html.contains("/password\""));
        // The only administrator, seen by someone else: the role stays and the account cannot be disabled.
        let mut last = user("admin");
        last.only_admin = true;
        let html = crate::admin::user_page(&ctx(), last, vec![], None);
        assert!(!html.contains(r#"<select name="role""#));
        assert!(!html.contains("/disable"));
        // A disabled account is offered enabling, not disabling.
        let mut off = user("readonly");
        off.disabled_at = Some(OffsetDateTime::UNIX_EPOCH);
        let html = crate::admin::user_page(&ctx(), off, vec![], None);
        assert!(html.contains("/enable"));
        assert!(!html.contains("/disable"));
    }

    #[test]
    fn the_audit_page_escapes_what_devices_and_people_put_in_the_log() {
        let row = AuditRow {
            id: 7,
            at: OffsetDateTime::UNIX_EPOCH,
            actor_label: "<script>alert(1)</script>".into(),
            channel: "agent".into(),
            action: "device.connect".into(),
            target_type: None,
            target_id: None,
            outcome: "success".into(),
            organization: Some("<b>Org".into()),
            detail: serde_json::json!({ "note": "</td><img src=x>" }),
            client_ip: Some("203.0.113.9".into()),
            credential: None,
        };
        let filter = AuditFilter {
            actor: "\"><script>".into(),
            action: "user.".into(),
            ..Default::default()
        };
        let html = crate::admin::audit_page(
            &ctx(),
            AuditPage {
                rows: vec![row],
                filter,
                older: Some(6),
                organizations: vec![],
            },
        );
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("<img src=x>"));
        assert!(!html.contains("<b>Org"));
        assert!(!html.contains(r#"value=""><script>"#));
        assert!(html.contains("203.0.113.9"));
        // The filters travel with the export and the next page, percent-encoded.
        assert!(html.contains("/audit.csv?actor=%22%3E%3Cscript%3E&amp;action=user."));
        assert!(html.contains("/audit?actor=%22%3E%3Cscript%3E&amp;action=user.&amp;before=6"));
    }

    #[test]
    fn configured_products_are_links_that_leave_the_console() {
        let mut c = ctx();
        assert!(!jobs_page(&c, vec![], first_page()).contains("Products"));
        c.family = vec![FamilyLink {
            label: "Desk <b>".into(),
            url: "https://desk.example.com/?a=1&b=2".into(),
        }];
        let html = jobs_page(&c, vec![], first_page());
        assert!(html.contains("Products"));
        assert!(html.contains("Desk &lt;b&gt;"));
        assert!(html
            .contains(r#"href="https://desk.example.com/?a=1&amp;b=2" rel="noopener noreferrer""#));
    }

    #[test]
    fn the_jobs_list_offers_the_pages_that_exist() {
        let one = jobs_page(&ctx(), vec![], first_page());
        assert!(!one.contains("pagination"), "one page needs no paging");
        let v = JobsView {
            page: 2,
            more: true,
            action: "net.ping".into(),
            state: Some(ExecState::Failed),
            batch: None,
        };
        let html = jobs_page(&ctx(), vec![], v);
        assert!(html.contains("/jobs?page=1&amp;state=failed&amp;action=net.ping"));
        assert!(html.contains("/jobs?page=3&amp;state=failed&amp;action=net.ping"));
        assert!(html.contains("Page 2"));
        let last = JobsView {
            page: 3,
            ..Default::default()
        };
        let html = jobs_page(&ctx(), vec![], last);
        assert!(html.contains(">Newer<"));
        assert!(!html.contains(">Older<"));
    }

    #[test]
    fn textarea_text_cannot_close_the_textarea() {
        let html = render(
            view! { <textarea>{textarea_text("a </textarea><script>x</script> &amp; b")}</textarea> },
        );
        assert!(
            html.contains(
                "<textarea>\na &lt;/textarea>&lt;script>x&lt;/script> &amp;amp; b</textarea>"
            ),
            "{html}"
        );
        assert_eq!(html.matches("</textarea>").count(), 1);
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
            first_page(),
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
            first_page(),
        );
        assert!(html.contains("Verification failed"));
        assert!(!html.contains(">Succeeded<"));
        let html = jobs_page(
            &ctx(),
            vec![job(ExecState::Dispatched, Verification::Pending)],
            first_page(),
        );
        assert!(html.contains(">Sent<"));
    }

    #[test]
    fn readonly_users_get_no_admin_navigation() {
        let mut c = ctx();
        c.is_admin = false;
        let html = jobs_page(&c, vec![], first_page());
        assert!(!html.contains("href=\"/admin\""));
        assert!(!html.contains("href=\"/audit\""));
    }
}
