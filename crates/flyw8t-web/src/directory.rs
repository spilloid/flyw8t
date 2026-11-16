//! Optional directory administration. Secrets are rendered only in the rotation response.
use crate::model::{OrgRef, PageCtx};
use crate::pages::{shell, Nav};
use leptos::prelude::*;
use uuid::Uuid;

pub fn directory_page(
    ctx: &PageCtx,
    issuer: String,
    mappings: Vec<(Uuid, String, String, Vec<Uuid>)>,
    credentials: Vec<(Uuid, String)>,
    orgs: Vec<OrgRef>,
    secret: Option<String>,
) -> String {
    let csrf = ctx.csrf.clone();
    let mapping_rows=mappings.into_iter().map(|(id,key,role,organizations)| {
        let csrf=csrf.clone();
        let scope=if role=="admin" {"All organizations".into()} else {orgs.iter().filter(|o|organizations.contains(&o.id)).map(|o|o.name.clone()).collect::<Vec<_>>().join(", ")};
        view! { <tr><td data-label="Group">{key}</td><td data-label="Role">{role}</td><td data-label="Organizations">{scope}</td><td data-label="Action"><form method="post" action=format!("/admin/directory/mappings/{id}/remove")><input type="hidden" name="csrf" value=csrf/><button type="submit">"Remove"</button></form></td></tr> }
    }).collect_view();
    let credential_rows=credentials.into_iter().map(|(id,prefix)| {
        let csrf=csrf.clone();
        view! { <li><code>{prefix}"…"</code><form class="inline-form" method="post" action=format!("/admin/directory/credentials/{id}/revoke")><input type="hidden" name="csrf" value=csrf/><button type="submit">"Revoke"</button></form></li> }
    }).collect_view();
    let checks=orgs.into_iter().map(|o|view! { <label class="inline"><input type="checkbox" name="org" value=o.id.to_string()/>{o.name}</label> }).collect_view();
    let reveal=secret.map(|s|view! {<section class="card"><h2>"SCIM credential: copy now"</h2><p>"Shown once. Keep it in the provider's secret store. The previous credential is revoked."</p><pre class="output secret"><code>{s}</code></pre></section>});
    shell(
        "Directory",
        ctx,
        Nav::Admin,
        None,
        view! {
            <h1>"Directory sign-in and provisioning"</h1>
            <p><a href="/admin">"Administration"</a></p>
            <p>"OpenID Connect issuer: "<code>{issuer}</code>". Local break-glass accounts remain available."</p>
            <p>"The provider manages MFA. A flyw8t passkey is still required for sudo mode. Directory identities are never linked to local accounts by email."</p>
            {reveal}
            <section><h2>"Group access"</h2><p>"Map exact directory group keys. Matching groups grant the highest role and the combined organizations. An administrator spans every organization. No matching group means no access."</p>
            <div class="table-wrap"><table class="list"><thead><tr><th>"Group"</th><th>"Role"</th><th>"Organizations"</th><th>"Action"</th></tr></thead><tbody>{mapping_rows}</tbody></table></div>
            <form method="post" action="/admin/directory/mappings" class="stack">
            <input type="hidden" name="csrf" value=csrf.clone()/>
            <label>"Group key"<input name="group_key" required=true maxlength="200"/></label>
            <label>"Role"<select name="role"><option value="readonly">"Read-only"</option><option value="technician">"Technician"</option><option value="admin">"Administrator"</option></select></label>
            <fieldset><legend>"Organizations"</legend>{checks}</fieldset>
            <button type="submit">"Save group access"</button></form></section>
            <section><h2>"SCIM provisioning"</h2><p>"Use /scim/v2 with a separate bearer credential. Users.externalId must equal the OIDC subject; Groups.externalId must equal the signed groups claim key. Synchronization controls membership for provisioned users."</p>
            <ul>{credential_rows}</ul><form method="post" action="/admin/directory/credentials"><input type="hidden" name="csrf" value=csrf/><button type="submit">"Rotate SCIM credential"</button></form></section>
        },
    )
}
