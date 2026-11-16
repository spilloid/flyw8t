//! Administration pages added after the first console: one user's page, and the audit log with its filters.
use crate::fmt;
use crate::model::*;
use crate::pages::{query_value, revealed_box, shell, time_cell, Nav};
use leptos::prelude::*;
use time::OffsetDateTime;

fn role_label(role: &str) -> &'static str {
    match role {
        "admin" => "Administrator",
        "technician" => "Technician",
        "readonly" => "Read-only",
        _ => "Unknown role",
    }
}

fn count(n: i64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// An administrator's page about one user: what they can reach, and the changes only an administrator makes.
pub fn user_page(
    ctx: &PageCtx,
    u: UserDetail,
    orgs: Vec<OrgRef>,
    revealed: Option<RevealedSecret>,
) -> String {
    let now = ctx.now;
    let id = u.id;
    let csrf = ctx.csrf.clone();
    let disabled = u.disabled_at.is_some();
    let badges = view! {
        <span class="badge neutral">{role_label(&u.role)}</span>
        {disabled.then(|| view! { <span class="badge bad">"Disabled"</span> })}
        {u.is_self.then(|| view! { <span class="badge busy">"You"</span> })}
    };
    let two_step = match (u.mfa, u.passkeys) {
        (false, 0) => "Not set up".to_string(),
        (true, 0) => "Authenticator code".to_string(),
        (true, n) => format!("Authenticator code, {}", count(n, "passkey", "passkeys")),
        (false, n) => count(n, "passkey", "passkeys"),
    };
    let password = match (u.password_temporary, u.password_changed_at) {
        (true, Some(at)) => view! {
            <span class="badge unknown">"Temporary"</span>" set by an administrator "{time_cell(now, at)}", not yet replaced"
        }
        .into_any(),
        (_, Some(at)) => view! { "Changed "{time_cell(now, at)} }.into_any(),
        (_, None) => view! { <span class="muted">"Unchanged since the account was created"</span> }.into_any(),
    };
    let sign_out = (u.sessions > 0).then(|| {
        let url = format!("/admin/users/{id}/sign-out");
        view! {
            <form method="post" action=url class="inline-form">
                <input type="hidden" name="csrf" value=csrf.clone()/>
                <button type="submit" class="link" title="Ends every session of theirs and the support sessions they started">"Sign out everywhere"</button>
            </form>
        }
    });
    let org_checks = orgs
        .iter()
        .map(|o| {
            let checked = u.organization_ids.contains(&o.id);
            view! { <label class="inline"><input type="checkbox" name="org" value=o.id.to_string() checked=checked/>{o.name.clone()}</label> }
        })
        .collect_view();
    // A person cannot change their own role, and the only administrator cannot stop being one: the choice is not offered.
    let role_fixed = u.is_self || u.only_admin;
    let role_field = if role_fixed {
        let why = if u.is_self {
            "Your own role is changed by another administrator."
        } else {
            "This is the only administrator who can sign in, so the role stays."
        };
        view! {
            <input type="hidden" name="role" value=u.role.clone()/>
            <p class="muted">{format!("Role: {}. {why}", role_label(&u.role))}</p>
        }
        .into_any()
    } else {
        let option = |value: &'static str, label: &'static str| {
            view! { <option value=value selected={u.role == value}>{label}</option> }
        };
        view! {
            <label>"Role"<select name="role">
                {option("technician", "Technician: view and run diagnostics in assigned organizations")}
                {option("readonly", "Read-only: view assigned organizations")}
                {option("admin", "Administrator: everything, every organization")}
            </select></label>
        }
        .into_any()
    };
    let edit_url = format!("/admin/users/{id}/edit");
    let password_card = if u.directory {
        view! {<section class="card"><h2>"Directory account"</h2><p>"Sign-in and MFA are managed by your organization. Group access is configured on the "<a href="/admin/directory">"directory page"</a>". No local password is available."</p></section>}.into_any()
    } else if u.is_self {
        view! {
            <section class="card">
                <h2>"Password"</h2>
                <p>"Change your own password on "<a href="/account">"your account page"</a>"."</p>
            </section>
        }
        .into_any()
    } else {
        let url = format!("/admin/users/{id}/password");
        view! {
            <details class="card">
                <summary>"Give a temporary password"</summary>
                <p>"For someone who cannot sign in. The server makes up a password and shows it to you once. Their old password stops working and they are signed out everywhere. Two-step verification is not changed: if they have lost that too, reset it from the users table."</p>
                <form method="post" action=url>
                    <input type="hidden" name="csrf" value=csrf.clone()/>
                    <button type="submit" class="secondary">"Make a temporary password"</button>
                </form>
            </details>
        }
        .into_any()
    };
    let state_card = if u.is_self {
        None
    } else if disabled {
        let url = format!("/admin/users/{id}/enable");
        Some(
            view! {
                <section class="card">
                    <h2>"Account disabled"</h2>
                    <p>"They cannot sign in, and their API tokens were revoked. Enabling the account lets them sign in again with the password and second factor they had; revoked tokens stay revoked."</p>
                    <form method="post" action=url>
                        <input type="hidden" name="csrf" value=csrf.clone()/>
                        <button type="submit" class="secondary">"Enable account"</button>
                    </form>
                </section>
            }
            .into_any(),
        )
    } else if u.only_admin {
        None
    } else {
        let url = format!("/admin/users/{id}/disable");
        Some(
            view! {
                <details class="card dangerzone">
                    <summary>"Disable this account"</summary>
                    <p>"They are signed out everywhere and cannot sign in. Their API tokens and unspent enrollment tokens are revoked, and the support sessions they started end. Jobs they already queued still run. Their history and audit trail stay."</p>
                    <form method="post" action=url>
                        <input type="hidden" name="csrf" value=csrf.clone()/>
                        <button type="submit" class="bad">"Disable account"</button>
                    </form>
                </details>
            }
            .into_any(),
        )
    };
    let title = u.display_name.clone();
    let body = view! {
        <p class="crumbs"><a href="/admin">"Administration"</a>" / "</p>
        <h1>{title.clone()}{badges}</h1>
        {revealed.map(revealed_box)}
        <div class="grid">
            <section class="card">
                <h2>"Account"</h2>
                <dl class="facts">
                    <dt>"Email"</dt><dd>{u.email.clone()}</dd>
                    <dt>"Created"</dt><dd>{time_cell(now, u.created_at)}</dd>
                    <dt>"Two-step"</dt><dd>{two_step}</dd>
                    <dt>"Password"</dt><dd>{password}</dd>
                    <dt>"Sessions"</dt><dd>{count(u.sessions, "live session", "live sessions")}{sign_out}</dd>
                    <dt>"API tokens"</dt><dd>{count(u.api_tokens, "working token", "working tokens")}</dd>
                    {u.disabled_at.map(|at| view! { <dt>"Disabled"</dt><dd>{time_cell(now, at)}</dd> })}
                </dl>
            </section>
            {(!u.directory).then(|| view! { <section class="card">
                <h2>"Name, role and organizations"</h2>
                <form method="post" action=edit_url class="stack">
                    <input type="hidden" name="csrf" value=csrf.clone()/>
                    <label>"Name"<input type="text" name="display_name" required=true maxlength="200" value=u.display_name.clone()/></label>
                    {role_field}
                    <fieldset><legend>"Organizations"</legend>{org_checks}</fieldset>
                    <p class="hint">"Administrators reach every organization, whatever is ticked. Lowering a role or removing an organization takes effect on their next page and ends the support sessions they started."</p>
                    <button type="submit">"Save"</button>
                </form>
            </section> })}
        </div>
        {password_card}
        {state_card}
        <p class="hint">"Changes on this page ask you to confirm a passkey first."</p>
    };
    shell(&title, ctx, Nav::Admin, None, body)
}

fn day(d: time::Date) -> String {
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// The audit filters as a query string (without `before`), for the export link and the next page.
pub fn audit_query(f: &AuditFilter) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !f.actor.is_empty() {
        parts.push(format!("actor={}", query_value(&f.actor)));
    }
    if !f.action.is_empty() {
        parts.push(format!("action={}", query_value(&f.action)));
    }
    if let Some(o) = &f.outcome {
        parts.push(format!("outcome={}", query_value(o)));
    }
    if let Some(o) = f.organization {
        parts.push(format!("org={o}"));
    }
    if let Some(d) = f.from {
        parts.push(format!("from={}", day(d)));
    }
    if let Some(d) = f.to {
        parts.push(format!("to={}", day(d)));
    }
    parts.join("&")
}

fn audit_row(now: OffsetDateTime, a: AuditRow) -> impl IntoView {
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
    let detail = if a.detail.as_object().is_some_and(|o| o.is_empty()) {
        String::new()
    } else {
        a.detail.to_string()
    };
    let from = a
        .client_ip
        .clone()
        .map(|ip| view! { <div class="muted small mono">{ip}</div> });
    view! {
        <tr>
            <td data-label="When">{time_cell(now, a.at)}</td>
            <td data-label="Actor">{a.actor_label.clone()}<span class="muted">{format!(" via {}", a.channel)}</span>{from}</td>
            <td data-label="Action" class="mono">{a.action.clone()}</td>
            <td data-label="Target" class="mono">{target}</td>
            <td data-label="Result"><span class=class>{a.outcome.clone()}</span></td>
            <td data-label="Detail" class="mono small">{a.organization.clone().map(|o| format!("[{o}] "))}{detail}</td>
        </tr>
    }
}

pub fn audit_page(ctx: &PageCtx, page: AuditPage) -> String {
    let now = ctx.now;
    let f = page.filter.clone();
    let query = audit_query(&f);
    let outcome = |value: &'static str, label: &'static str| {
        view! { <option value=value selected={f.outcome.as_deref() == Some(value)}>{label}</option> }
    };
    let org_options = page
        .organizations
        .iter()
        .map(|o| view! { <option value=o.id.to_string() selected={f.organization == Some(o.id)}>{o.name.clone()}</option> })
        .collect_view();
    let none = page.rows.is_empty();
    let filtered = !f.is_empty();
    let rows = page
        .rows
        .into_iter()
        .map(|a| audit_row(now, a))
        .collect_view();
    let export_href = if query.is_empty() {
        "/audit.csv".to_string()
    } else {
        format!("/audit.csv?{query}")
    };
    let older = page.older.map(|id| {
        let href = if query.is_empty() {
            format!("/audit?before={id}")
        } else {
            format!("/audit?{query}&before={id}")
        };
        view! { <a class="button secondary" href=href>"Older events"</a> }
    });
    let newest = f.before.map(|_| {
        let href = if query.is_empty() {
            "/audit".to_string()
        } else {
            format!("/audit?{query}")
        };
        view! { <a class="button secondary" href=href>"Newest"</a> }
    });
    let empty = none.then(|| {
        let msg = if filtered || f.before.is_some() {
            "No events match."
        } else {
            "Nothing has been recorded yet."
        };
        view! { <p class="empty">{msg}</p> }
    });
    let table = (!none).then(|| view! {
        <table class="list">
            <thead><tr><th scope="col">"When"</th><th scope="col">"Actor"</th><th scope="col">"Action"</th><th scope="col">"Target"</th><th scope="col">"Result"</th><th scope="col">"Detail"</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    });
    let body = view! {
        <h1>"Audit"</h1>
        <p class="sub">"Append-only: the database rejects updates and deletes on this table. Newest first, 100 to a page."</p>
        <form method="get" action="/audit" class="filters card">
            <label class="search-field">"Actor"<input type="search" name="actor" value=f.actor.clone() maxlength="200" placeholder="Email or device name"/></label>
            <label>"Action"<input type="text" name="action" value=f.action.clone() maxlength="100" placeholder="user. or job.create"/></label>
            <label>"Result"<select name="outcome">
                <option value="">"Any"</option>
                {outcome("success", "Success")}
                {outcome("denied", "Denied")}
                {outcome("failed", "Failed")}
            </select></label>
            <label>"Organization"<select name="org"><option value="">"Any"</option>{org_options}</select></label>
            <label>"From"<input type="date" name="from" value=f.from.map(day).unwrap_or_default()/></label>
            <label>"To"<input type="date" name="to" value=f.to.map(day).unwrap_or_default()/></label>
            <button type="submit">"Apply filters"</button>
            {filtered.then(|| view! { <a class="button secondary" href="/audit">"Clear"</a> })}
        </form>
        <p><a class="button secondary" href=export_href>"Export as CSV"</a>" "<span class="muted small">"These filters, newest first, at most 10,000 events. Days are UTC. The export is itself recorded."</span></p>
        {empty}
        {table}
        <div class="pagination">{newest}{older}</div>
    };
    shell("Audit", ctx, Nav::Audit, None, body)
}

/// The account page's password card.
pub(crate) fn password_card(
    ctx: &PageCtx,
    temporary: bool,
    changed_at: Option<OffsetDateTime>,
) -> impl IntoView {
    let notice = temporary.then(|| view! {
        <p class="flash bad" role="status">"An administrator gave you a temporary password. Choose your own now: someone else has seen this one."</p>
    });
    let changed = match changed_at {
        Some(at) if !temporary => {
            view! { <p class="muted">"Last changed "{time_cell(ctx.now, at)}"."</p> }.into_any()
        }
        _ => ().into_any(),
    };
    view! {
        <section>
            <h2>"Password"</h2>
            {notice}
            {changed}
            <form method="post" action="/account/password" class="stack card">
                <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"Current password"<input type="password" name="current" required=true autocomplete="current-password"/></label>
                <label>"New password (12 or more characters)"<input type="password" name="new" required=true minlength="12" maxlength="1024" autocomplete="new-password"/></label>
                <label>"New password again"<input type="password" name="repeat" required=true minlength="12" maxlength="1024" autocomplete="new-password"/></label>
                <p class="hint">"Changing it signs you out of every other browser."</p>
                <button type="submit">"Change password"</button>
            </form>
        </section>
    }
}
