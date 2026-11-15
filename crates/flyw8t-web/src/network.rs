//! Site-centered network workflows, using the console's normal server-rendered forms.
use crate::fmt;
use crate::model::*;
use crate::pages::{shell, time_cell, Nav};
use flyw8t_domain::network::{fresh, web_port};
use leptos::prelude::*;
use uuid::Uuid;

fn asset_name(a: &NetworkAsset) -> String {
    if a.hostname.is_empty() {
        a.ip.clone()
    } else {
        a.hostname.clone()
    }
}

fn observation_badge(a: &NetworkAsset, ctx: &PageCtx) -> impl IntoView {
    let (label, class) = if a.collector_revoked {
        ("Collector revoked", "neutral")
    } else if !fresh(a.collected_at, ctx.now, a.interval_secs) {
        ("Stale observation", "unknown")
    } else if a.status == "up" {
        ("Reachable when scanned", "good")
    } else if a.status == "down" {
        ("No response when scanned", "bad")
    } else {
        ("Unknown", "neutral")
    };
    view! {<span class=format!("badge {class}")>{label}</span>}
}

fn collector_status(c: &NetworkCollector, ctx: &PageCtx) -> impl IntoView {
    let (label, class) = if c.revoked_at.is_some() {
        ("Revoked", "neutral")
    } else if c
        .heartbeat_at
        .is_some_and(|t| fresh(t, ctx.now, c.interval_secs))
    {
        ("Reporting recently", "good")
    } else if c.heartbeat_at.is_none() {
        ("Awaiting heartbeat", "neutral")
    } else {
        ("Heartbeat overdue", "unknown")
    };
    view! {<span class=format!("badge {class}")>{label}</span>}
}

fn page_href(w: &NetworkWorkspace, page: u32) -> String {
    let encoded: String = w
        .query
        .bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                vec![b as char]
            } else {
                format!("%{b:02X}").chars().collect()
            }
        })
        .collect();
    format!(
        "/network?page={page}&q={encoded}{}",
        w.selected_site
            .map(|s| format!("&site={s}"))
            .unwrap_or_default()
    )
}

pub fn network_page(ctx: &PageCtx, w: NetworkWorkspace) -> String {
    let options=w.sites.iter().map(|s|view!{
        <option value=s.id.to_string() selected=w.selected_site==Some(s.id)>{format!("{} / {}",s.organization,s.name)}</option>
    }).collect_view();
    let rows=w.assets.iter().map(|a|view!{
        <tr>
            <td data-label="Device"><a class="device-link" href=format!("/network/assets/{}",a.id)>{asset_name(a)}</a><span class="small muted block">{a.device_type.clone()}</span></td>
            <td data-label="Address"><span class="mono">{a.ip.clone()}</span><span class="small muted block">{a.mac.clone().unwrap_or_else(||"MAC not reported".into())}</span></td>
            <td data-label="Site"><a href=format!("/sites/{}",a.site.id)>{a.site.name.clone()}</a><span class="small muted block">{a.site.organization.clone()}</span></td>
            <td data-label="Observation">{observation_badge(a,ctx)}<span class="small muted block">{time_cell(ctx.now,a.collected_at)}</span></td>
            <td data-label="Ports"><span class="mono">{a.open_ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")}</span></td>
        </tr>
    }).collect_view();
    let collectors=w.collectors.iter().map(|c|view!{
        <article class="collector-card">
            <div class="section-heading"><a class="device-link" href=format!("/network/collectors/{}",c.id)>{c.name.clone()}</a>{collector_status(c,ctx)}</div>
            <p class="muted small">{format!("{} / {}",c.site.organization,c.site.name)}</p>
            <p class="mono">{c.cidr.clone()}</p>
            <p class="small muted">{c.inventory_at.map(|t|format!("Inventory received {}",fmt::ago(ctx.now,t))).unwrap_or_else(||"No inventory received yet".into())}</p>
        </article>
    }).collect_view();
    let register = if ctx.can_enroll {
        w.selected_site.map(|site|{
            let action=format!("/sites/{site}/network-collectors");
            view!{
                <details class="card setup-card"><summary>"Add a site collector"</summary>
                    <p class="muted">"Register a NetViz probe for this site. Its credential can report inventory only within the range you choose."</p>
                    <form class="stack" method="post" action=action>
                        <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                        <div class="form-grid">
                            <label>"Collector name"<input name="name" required maxlength="120" placeholder="Office discovery"/></label>
                            <label>"IPv4 range"<input name="cidr" required placeholder="192.168.1.0/24"/></label>
                            <label>"Scan interval (seconds)"<input type="number" name="interval_secs" min="30" max="3600" value="60" required/></label>
                        </div>
                        <label>"PortGlass probe fingerprint (optional)"<input name="portglass_fingerprint" maxlength="120" placeholder="sha256:…"/></label>
                        <p class="muted small">"Use the fingerprint of the PortGlass probe at this site. Technicians must already trust that probe in their own controller."</p>
                        <div><button type="submit">"Register collector"</button></div>
                    </form>
                </details>
            }
        }).map(|v|v.into_any())
    } else {
        None
    };
    let previous = (w.page > 1)
        .then(|| view! {<a class="button secondary" href=page_href(&w,w.page-1)>"Previous"</a>});
    let next = (i64::from(w.page) * 50 < w.total)
        .then(|| view! {<a class="button secondary" href=page_href(&w,w.page+1)>"Next"</a>});
    let no_sites = w.sites.is_empty();
    let body = view! {
        <div class="workspace-heading"><div><p class="eyebrow">"flyw8t / Site operations"</p><h1>"Network"</h1><p class="muted">"Discover equipment, inspect observations and open the right management interface."</p></div>
            <div class="capability-chips" aria-label="Available capabilities"><span class="badge busy">"NetViz discovery"</span><span class="badge neutral">"PortGlass access"</span></div>
        </div>
        <form class="filters card" method="get" action="/network">
            <label>"Site"<select name="site"><option value="">"All sites"</option>{options}</select></label>
            <label class="search-field">"Find equipment"<input type="search" name="q" value=w.query.clone() placeholder="Name, IP, MAC or vendor" maxlength="200"/></label>
            <button type="submit">"Apply filters"</button>
        </form>
        {no_sites.then(||view!{<p class="empty">"Create an organization and site before registering a network collector. "<a href="/organizations">"Open organizations"</a></p>})}
        <section class="card"><div class="section-heading"><h2>"Network assets"</h2><span class="muted small">{format!("{} matching assets",w.total)}</span></div>
            <p class="muted small">"Status reflects the last scan. Equipment without an endpoint agent belongs here too."</p>
            {w.assets.is_empty().then(||view!{<p class="empty">"No matching equipment yet. Select a site and register a collector, or adjust your search."</p>})}
            {(!w.assets.is_empty()).then(||view!{<table class="list"><thead><tr><th>"Device"</th><th>"Address"</th><th>"Site"</th><th>"Observation"</th><th>"Ports"</th></tr></thead><tbody>{rows}</tbody></table>})}
            <div class="pagination">{previous}<span class="small muted">{format!("Page {}",w.page)}</span>{next}</div>
        </section>
        <section class="card"><h2>"Site collectors"</h2>
            {w.collectors.is_empty().then(||view!{<p class="empty">"No collectors registered for this selection."</p>})}
            <div class="collector-grid">{collectors}</div>
            {(ctx.can_enroll&&w.selected_site.is_none()&&!no_sites).then(||view!{<p class="muted small">"Select a site above to add its collector."</p>})}
            {(w.collectors.len()==200).then(||view!{<p class="muted small">"Showing the first 200 collectors. Select a site to narrow the list."</p>})}
        </section>
        {register}
    };
    shell("Network", ctx, Nav::Network, None, body)
}

pub fn network_asset_page(
    ctx: &PageCtx,
    a: NetworkAsset,
    c: NetworkCollector,
    history: Vec<NetworkHistory>,
) -> String {
    let title = asset_name(&a);
    let ready = a.status == "up"
        && !a.collector_revoked
        && fresh(a.collected_at, ctx.now, a.interval_secs)
        && c.portglass_fingerprint.is_some();
    let ports=a.open_ports.iter().copied().filter(|&p|u16::try_from(p).is_ok_and(web_port)).map(|p|view!{<option value=p.to_string()>{format!("{} · port {p}",if matches!(p,443|8443){"HTTPS"}else{"HTTP"})}</option>}).collect_view();
    let has_ports = a
        .open_ports
        .iter()
        .any(|&p| u16::try_from(p).is_ok_and(web_port));
    let access=(ctx.can_run&&has_ports).then(||view!{
        <form class="inline-form" method="post" action=format!("/network/assets/{}/open",a.id)>
            <input type="hidden" name="csrf" value=ctx.csrf.clone()/>
            <label>"Management interface"<select name="port">{ports}</select></label><button type="submit" disabled=!ready>"Review in PortGlass"</button>
        </form>
    });
    let history=history.into_iter().map(|h|view!{
        <li><time datetime=fmt::iso(h.collected_at)>{fmt::timestamp(h.collected_at)}</time><p class="small muted">{format!("{} · received {}",h.collector,fmt::timestamp(h.received_at))}</p><details><summary>"Observation details"</summary><pre class="output">{h.observation}</pre></details></li>
    }).collect_view();
    let body = view! {
        <p class="crumbs"><a href="/network">"Network"</a>" / "<a href=format!("/network?site={}",a.site.id)>{a.site.name.clone()}</a></p>
        <div class="workspace-heading"><div><p class="eyebrow">{format!("{} / {}",a.site.organization,a.site.name)}</p><h1>{title.clone()}</h1></div>{observation_badge(&a,ctx)}</div>
        <div class="grid"><section class="card"><h2>"Device details"</h2><dl class="facts">
            <dt>"IP address"</dt><dd class="mono">{a.ip.clone()}</dd><dt>"MAC address"</dt><dd class="mono">{a.mac.clone().unwrap_or_else(||"Not reported".into())}</dd>
            <dt>"Vendor"</dt><dd>{if a.vendor.is_empty(){"Not identified".into()}else{a.vendor.clone()}}</dd><dt>"Device type"</dt><dd>{a.device_type.clone()}</dd>
            <dt>"Open ports"</dt><dd class="mono">{a.open_ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")}</dd>
            <dt>"First received"</dt><dd>{time_cell(ctx.now,a.first_seen_at)}</dd><dt>"Observed"</dt><dd>{time_cell(ctx.now,a.collected_at)}</dd><dt>"Received"</dt><dd>{time_cell(ctx.now,a.received_at)}</dd>
            <dt>"Discovery source"</dt><dd><a href=format!("/network/collectors/{}",c.id)>{c.name.clone()}</a>" · NetViz"</dd>
        </dl></section>
        <section class="card"><h2>"Device access"</h2><p>"Open an authorized web interface in PortGlass on your computer."</p>{access}
            {(!has_ports).then(||view!{<p class="muted">"No supported web interface was reported in this scan."</p>})}
            {(!ready&&has_ports).then(||view!{<p class="muted">"Access needs a recent reachable observation, an active collector and its PortGlass probe fingerprint."</p>})}
            <p class="small muted">"PortGlass asks you to review the destination. The site's probe decides whether access is allowed."</p>
            <a href=format!("/network/collectors/{}",c.id)>"Collector and access settings"</a>
        </section></div>
        <section class="card"><h2>"Discovery history"</h2><p class="muted small">"Latest 30 observations; up to 100 retained per asset. Scan evidence is cached, not a live connection."</p><ol class="timeline">{history}</ol></section>
    };
    shell(&title, ctx, Nav::Network, None, body)
}

pub fn network_collector_page(ctx: &PageCtx, c: NetworkCollector) -> String {
    let manage=(ctx.can_enroll&&c.revoked_at.is_none()).then(||view!{
        <section class="card"><h2>"PortGlass access"</h2><p class="muted">"Identify the PortGlass probe serving this collector's devices. This does not add trust to a technician's controller."</p>
            <form class="stack" method="post" action=format!("/network/collectors/{}/access",c.id)><input type="hidden" name="csrf" value=ctx.csrf.clone()/>
                <label>"Probe SHA-256 fingerprint"<input name="portglass_fingerprint" value=c.portglass_fingerprint.clone().unwrap_or_default() maxlength="120"/></label><div><button>"Save access settings"</button></div>
            </form>
        </section>
        <section class="card"><h2>"Stop accepting reports"</h2><p>"Revoking this collector stops new reports. Existing inventory and history remain available."</p>
            <form method="post" action=format!("/network/collectors/{}/revoke",c.id)><input type="hidden" name="csrf" value=ctx.csrf.clone()/><button class="bad">"Revoke collector"</button></form>
        </section>
    });
    let body = view! {
        <p class="crumbs"><a href="/network">"Network"</a>" / "<a href=format!("/network?site={}",c.site.id)>{c.site.name.clone()}</a></p>
        <div class="workspace-heading"><div><p class="eyebrow">{format!("{} / {}",c.site.organization,c.site.name)}</p><h1>{c.name.clone()}</h1></div>{collector_status(&c,ctx)}</div>
        <section class="card"><h2>"Collector"</h2><dl class="facts"><dt>"Range"</dt><dd class="mono">{c.cidr.clone()}</dd><dt>"Scan interval"</dt><dd>{format!("{} seconds",c.interval_secs)}</dd>
            <dt>"Last heartbeat"</dt><dd>{c.heartbeat_at.map(fmt::timestamp).unwrap_or_else(||"Not received".into())}</dd><dt>"Last inventory"</dt><dd>{c.inventory_at.map(fmt::timestamp).unwrap_or_else(||"Not received".into())}</dd>
            <dt>"Version"</dt><dd>{c.version.clone().unwrap_or_else(||"Not reported".into())}</dd><dt>"Probe fingerprint"</dt><dd class="mono">{c.portglass_fingerprint.clone().unwrap_or_else(||"Not configured".into())}</dd>
        </dl></section>{manage}
    };
    shell(&c.name, ctx, Nav::Network, None, body)
}

pub fn network_collector_created(ctx: &PageCtx, id: Uuid, config: &str) -> String {
    let body = view! {
        <h1>"Set up your site collector"</h1><section class="card reveal"><h2>"Save this configuration now"</h2>
            <p>"The collector key is shown only here. Save this as probe.json on the site machine and restrict the file to the account running NetViz."</p>
            <pre class="output secret">{config.to_owned()}</pre>
            <p>"Run the current NetViz probe with this configuration:"</p><pre class="output">"netviz-probe -config probe.json"</pre>
            <p>"To run it as a service, use NetViz's service installation workflow with the same configuration. No endpoint agent is required."</p>
            <a class="button" href=format!("/network/collectors/{id}")>"View collector status"</a>
        </section>
    };
    shell("Set up collector", ctx, Nav::Network, None, body)
}

pub fn network_launch_page(ctx: &PageCtx, a: NetworkAsset, uri: &str, target: &str) -> String {
    let body = view! {
        <p class="crumbs"><a href=format!("/network/assets/{}",a.id)>{asset_name(&a)}</a>" / Device access"</p><h1>"Continue in PortGlass"</h1>
        <section class="card"><p>{format!("{} / {} · {}",a.site.organization,a.site.name,target)}</p>
            <p>"Open your local PortGlass controller, review the prefilled probe and destination, then connect."</p>
            <a class="button" href=uri.to_owned()>"Open PortGlass"</a>
            <p class="small muted">"Requires a PortGlass controller with console links registered and this site's probe already pinned. This handoff does not confirm a connection."</p>
            <details><summary>"Manual handoff"</summary><p>"If browser links are unavailable, run:"</p><pre class="output">{format!("portglass open-url \"{uri}\"")}</pre></details>
        </section>
    };
    shell("Open device interface", ctx, Nav::Network, None, body)
}
