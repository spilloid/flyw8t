//! Scheduling forms in a technician's existing device context.

use crate::fmt;
use crate::model::PageCtx;
use crate::pages::{shell, Nav};
use leptos::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct ScheduleRow {
    pub id: Uuid,
    pub script: String,
    pub revision: i32,
    pub cadence: String,
    pub next: Option<OffsetDateTime>,
    pub stop_reason: Option<String>,
    pub creator: String,
    pub can_cancel: bool,
}

pub struct OccurrenceRow {
    pub script: String,
    pub revision: i32,
    pub due: OffsetDateTime,
    pub label: String,
    pub reason: Option<String>,
    pub job_id: Option<Uuid>,
}

pub fn index(
    ctx: &PageCtx,
    device: Uuid,
    hostname: &str,
    schedules: Vec<ScheduleRow>,
    history: Vec<OccurrenceRow>,
    page: u32,
    has_older: bool,
) -> String {
    let back = format!("/devices/{device}");
    let empty = schedules.is_empty();
    let empty_history = history.is_empty();
    let rows = schedules
        .into_iter()
        .map(|row| {
            let timing = row
                .next
                .map(fmt::timestamp)
                .or(row.stop_reason)
                .unwrap_or_default();
            let cancel = (row.can_cancel && row.next.is_some()).then(|| view! {
            <form method="post" action=format!("/devices/{device}/schedules/{}/cancel", row.id)>
                <input name="csrf" type="hidden" value=ctx.csrf.clone()/>
                <button type="submit" class="secondary">"Cancel schedule"</button>
            </form>
        });
            view! {
                <tr>
                    <td data-label="Script">{row.script}" · revision "{row.revision}</td>
                    <td data-label="Cadence">{row.cadence}</td>
                    <td data-label="Next run">{timing}</td>
                    <td data-label="Owner">{row.creator}</td>
                    <td data-label="Actions">{cancel}</td>
                </tr>
            }
        })
        .collect_view();
    let history_rows = history.into_iter().map(|row| {
        let job = row.job_id.map(|id| view! { <a href=format!("/jobs/{id}")>"View job"</a> });
        view! {
            <tr>
                <td data-label="Script">{row.script}" · revision "{row.revision}</td>
                <td data-label="Due">{fmt::timestamp(row.due)}</td>
                <td data-label="Outcome">{row.label}{row.reason.map(|reason| view! { <p class="small muted">{reason}</p> })}</td>
                <td data-label="Job">{job}</td>
            </tr>
        }
    }).collect_view();
    let body = view! {
        <p class="crumbs"><a href=back>{hostname.to_string()}</a></p>
        <h1>"Script schedules"</h1>
        <p><a href=format!("/devices/{device}/scripts")>"Choose an approved revision"</a></p>
        <section class="card">
            <h2>"Upcoming and stopped schedules"</h2>
            {empty.then(|| view! { <p class="muted">"No upcoming or stopped schedules."</p> })}
            {(!empty).then(|| view! {
                <p class="muted small">"Cancel schedule stops future occurrences. Manage any jobs already queued from their job pages."</p>
                <table class="list">
                    <thead><tr><th>"Script"</th><th>"Cadence"</th><th>"Next run (UTC)"</th><th>"Owner"</th><th>"Actions"</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            })}
        </section>
        <section class="card">
            <h2>"Occurrence history"</h2>
            {empty_history.then(|| view! { <p class="muted">"No occurrences on this page."</p> })}
            {(!empty_history).then(|| view! {
                <table class="list">
                    <thead><tr><th>"Script"</th><th>"Due (UTC)"</th><th>"Outcome"</th><th>"Job"</th></tr></thead>
                    <tbody>{history_rows}</tbody>
                </table>
            })}
            <p>
                {(page > 0).then(|| view! { <a href=format!("/devices/{device}/schedules?history_page={}", page - 1)>"Newer"</a> })}
                {has_older.then(|| view! { " " <a href=format!("/devices/{device}/schedules?history_page={}", page.saturating_add(1))>"Older"</a> })}
            </p>
        </section>
    };
    shell("Script schedules", ctx, Nav::Devices, None, body)
}

pub fn new_form(
    ctx: &PageCtx,
    device: Uuid,
    script: Uuid,
    revision: i32,
    name: &str,
    asks: Vec<(String, Option<String>)>,
) -> String {
    let action = format!("/devices/{device}/schedules/new/{script}/{revision}");
    let asks = asks.into_iter().map(|(name, prompt)| {
        let label = prompt.unwrap_or_else(|| name.clone());
        view! { <label>{label}<input type="text" name=format!("v_{name}") maxlength="4096"/></label> }
    }).collect_view();
    let body = view! {
        <p class="crumbs"><a href=format!("/devices/{device}/schedules")>"Script schedules"</a></p>
        <h1>"Schedule " {name.to_string()}</h1>
        <p>"Revision "{revision}". Schedules support approved C0 and C1 PowerShell with non-secret parameters. Input and custom-field values are saved when you create the schedule."</p>
        <p>"Scheduled runs use the Windows agent’s account."</p>
        <form method="post" action=action class="stack card">
            <input name="csrf" type="hidden" value=ctx.csrf.clone()/>
            <label>"First run (UTC)"<input type="datetime-local" name="starts" required/></label>
            <label>"Repeat"<select name="cadence">
                <option value="once">"One time"</option>
                <option value="daily">"Daily at the same UTC time"</option>
                <option value="weekly">"Weekly at the same UTC time"</option>
            </select></label>
            <label>"Deliver after due time for"<select name="delivery">
                <option value="900">"15 minutes"</option>
                <option value="3600">"1 hour"</option>
                <option value="86400">"1 day"</option>
                <option value="604800">"7 days"</option>
            </select></label>
            <label>"Execution timeout (seconds)"<input type="number" name="timeout" min="1" max="3600" value="300" required/></label>
            {asks}
            <button type="submit">"Create schedule"</button>
        </form>
    };
    shell("Schedule a script", ctx, Nav::Devices, None, body)
}
