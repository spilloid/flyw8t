//! Fleet health in the console: what each device last reported about its disks and memory, the
//! devices that need attention, and the enrollment commands. Everything is scoped like a read,
//! and a device's report can never break or script a page.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::{json, Value};
use uuid::Uuid;

const GIB: u64 = 1 << 30;

async fn org_with_devices(
    server: &TestServer,
    admin: &Browser,
    name: &str,
    n: usize,
) -> (Uuid, Vec<Uuid>) {
    let org = admin.create_org(server, name).await;
    let token = admin
        .enrollment_token(server, org, "60", &n.max(1).to_string())
        .await;
    let mut devices = Vec::new();
    for _ in 0..n {
        let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
        devices.push(agent.device_id);
        // The state directory is not needed: these devices never connect.
        std::mem::forget(agent);
    }
    (org, devices)
}

async fn technician(server: &TestServer, admin: &Browser, email: &str, org: Uuid) -> Browser {
    let r = admin
        .post(
            server,
            "/admin/users",
            &[
                ("email", email),
                ("display_name", "Tech"),
                ("password", "tech-password-123"),
                ("role", "technician"),
                ("org", &org.to_string()),
            ],
        )
        .await;
    assert_eq!(r.location(), "/admin?m=user-created", "{}", r.body);
    server.login(email, "tech-password-123").await
}

/// An inventory report as an agent would send it, with one fixed disk `used_percent` full.
fn inventory(mount: &str, used_percent: u64) -> Value {
    json!({
        "collected_at": "2026-11-01T10:00:00Z",
        "hostname": "host",
        "os": {"family": "windows", "name": "Windows", "version": "11", "long_version": "Windows 11 Pro",
               "kernel_version": "26100", "arch": "x86_64"},
        "hardware": {"cpu_model": "cpu", "cpu_logical_cores": 8, "cpu_physical_cores": 4,
                     "memory_total_bytes": 16 * GIB, "memory_available_bytes": 4 * GIB},
        "disks": [
            {"mount_point": mount, "file_system": "NTFS", "total_bytes": 100 * GIB,
             "available_bytes": (100 - used_percent) * GIB, "removable": false},
            // A full removable disk is not a fault and must not be the one shown.
            {"mount_point": "E:\\", "file_system": "FAT32", "total_bytes": 8 * GIB,
             "available_bytes": 0, "removable": true},
        ],
        "network": [],
        "uptime_secs": 3600,
        "agent_version": "0.1.2",
    })
}

async fn report(server: &TestServer, device: Uuid, data: Value) {
    sqlx::query(
        "INSERT INTO inventory_snapshots (device_id, collected_at, source, data) VALUES ($1, now(), 'periodic', $2)",
    )
    .bind(device)
    .bind(data)
    .execute(&server.state.db)
    .await
    .unwrap();
}

/// Mark a device as last heard from `days` ago (it is not connected in these tests).
async fn last_seen(server: &TestServer, device: Uuid, days: i32) {
    sqlx::query(
        "UPDATE devices SET last_connected_at = now() - make_interval(days => $2),
                            last_seen_at = now() - make_interval(days => $2) WHERE id = $1",
    )
    .bind(device)
    .bind(days)
    .execute(&server.state.db)
    .await
    .unwrap();
}

/// Where each device's row starts in a device list page, in page order.
fn order(body: &str, devices: &[Uuid]) -> Vec<usize> {
    let mut at: Vec<(usize, usize)> = devices
        .iter()
        .enumerate()
        .filter_map(|(i, d)| body.find(&format!("href=\"/devices/{d}\"")).map(|p| (p, i)))
        .collect();
    at.sort();
    at.into_iter().map(|(_, i)| i).collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_device_list_shows_what_devices_reported_and_orders_and_filters_by_it() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (_, d) = org_with_devices(&server, &admin, "Contoso", 4).await;
    let (full, roomy, silent, hostile) = (d[0], d[1], d[2], d[3]);
    report(&server, full, inventory("C:\\", 95)).await;
    report(&server, roomy, inventory("D:\\", 40)).await;
    last_seen(&server, full, 0).await;
    last_seen(&server, roomy, 0).await;
    last_seen(&server, silent, 30).await;
    // A device may send anything. This one's report does not parse, and its text is markup.
    report(
        &server,
        hostile,
        json!({"collected_at": "<script>alert(1)</script>", "disks": "<img src=x>", "os": {"family": "<b>x</b>"}}),
    )
    .await;
    last_seen(&server, hostile, 0).await;

    let page = admin.get(&server, "/devices").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    // The fixed disk, not the full removable one, with its share and what is free.
    assert!(page.body.contains("C:\\ · 5.0 GiB free"), "{}", page.body);
    assert!(page.body.contains("D:\\ · 60.0 GiB free"), "{}", page.body);
    assert!(!page.body.contains("E:\\"), "removable disk shown");
    assert!(page.body.contains("value=\"95\""), "{}", page.body);
    assert!(
        page.body.contains("4.0 GiB free of 16.0 GiB"),
        "{}",
        page.body
    );
    // Device-reported figures say how old they are.
    assert!(page.body.contains("reported <time"), "{}", page.body);
    // The unreadable report gives no figures and no markup.
    assert!(!page.body.contains("<script>alert"), "{}", page.body);
    assert!(!page.body.contains("<img src=x>"), "{}", page.body);
    assert!(!page.body.contains("<b>x</b>"), "{}", page.body);

    // Fullest disk first; devices with no figures last, in name order between themselves.
    let by_disk = admin.get(&server, "/devices?sort=disk").await;
    let o = order(&by_disk.body, &d);
    assert_eq!(&o[..2], &[0, 1], "fullest first: {o:?}");
    // Longest silent first.
    let by_seen = admin.get(&server, "/devices?sort=seen").await;
    assert_eq!(order(&by_seen.body, &d)[0], 2, "longest silent first");
    // An unknown order is name order, not an error.
    let odd = admin.get(&server, "/devices?sort=%27;drop").await;
    assert_eq!(odd.status, StatusCode::OK);
    assert_eq!(order(&odd.body, &d).len(), 4);

    // Needing attention: the full disk and the long silence. Not the roomy one, nor the one
    // whose report could not be read (it was heard from today).
    let attention = admin.get(&server, "/devices?attention=1").await;
    let shown = order(&attention.body, &d);
    assert!(shown.contains(&0) && shown.contains(&2), "{shown:?}");
    assert!(!shown.contains(&1) && !shown.contains(&3), "{shown:?}");

    // The API carries the same figures.
    let r = admin
        .post(
            &server,
            "/admin/tokens",
            &[("name", "t"), ("scope", "read"), ("ttl_days", "30")],
        )
        .await;
    let token = extract(&r.body, r"(fw8_[A-Za-z0-9_-]{43})").expect("api token");
    let api = server
        .api(
            axum::http::Method::GET,
            "/api/v1/devices",
            &token,
            None,
            None,
        )
        .await
        .json();
    let row = api
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == full.to_string())
        .unwrap();
    assert_eq!(row["health"]["fullest_disk"]["mount_point"], "C:\\");
    assert_eq!(row["health"]["memory_total_bytes"], 16 * GIB);
    // The server's receipt time travels with the figures.
    assert!(row["health"]["received_at"].is_string(), "{row}");
    let bad = api
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == hostile.to_string())
        .unwrap();
    assert!(bad["health"].is_null(), "{bad}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn the_overview_lists_devices_needing_attention_only_within_the_callers_organizations() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;

    // Nothing enrolled yet: the first-run steps, not an empty table.
    let empty = admin.get(&server, "/").await;
    assert!(
        empty.body.contains("Enroll your first device"),
        "{}",
        empty.body
    );
    assert!(!empty.body.contains("Devices needing attention"));

    let (contoso, c) = org_with_devices(&server, &admin, "Contoso", 2).await;
    let (_fabrikam, f) = org_with_devices(&server, &admin, "Fabrikam", 1).await;
    report(&server, c[0], inventory("C:\\", 97)).await;
    last_seen(&server, c[0], 0).await;
    last_seen(&server, c[1], 0).await;
    report(&server, f[0], inventory("F:\\", 99)).await;
    last_seen(&server, f[0], 9).await;
    // A version only Fabrikam's device runs, to show whose versions are counted.
    sqlx::query("UPDATE devices SET agent_version = '9.8.7-fabrikam' WHERE id = $1")
        .bind(f[0])
        .execute(&server.state.db)
        .await
        .unwrap();

    let all = admin.get(&server, "/").await;
    assert!(all.body.contains("9.8.7-fabrikam"), "{}", all.body);
    assert!(!all.body.contains("Enroll your first device"));
    assert!(all.body.contains("C:\\ 97% full"), "{}", all.body);
    assert!(all.body.contains("F:\\ 99% full"), "{}", all.body);
    assert!(all.body.contains("Offline 9 d"), "{}", all.body);
    assert!(
        all.body
            .contains("<span class=\"num\">2</span> devices need attention"),
        "{}",
        all.body
    );
    // The healthy device is not listed.
    assert!(!all.body.contains(&format!("href=\"/devices/{}\"", c[1])));

    // A technician of Contoso sees nothing of Fabrikam: not its device, its disk or its count.
    let tech = technician(&server, &admin, "tech@example.test", contoso).await;
    let scoped = tech.get(&server, "/").await;
    assert_eq!(scoped.status, StatusCode::OK);
    assert!(scoped.body.contains("C:\\ 97% full"), "{}", scoped.body);
    assert!(!scoped.body.contains("F:\\"), "{}", scoped.body);
    assert!(!scoped.body.contains(&f[0].to_string()), "{}", scoped.body);
    assert!(!scoped.body.contains("9.8.7-fabrikam"), "{}", scoped.body);
    assert!(
        scoped
            .body
            .contains("<span class=\"num\">1</span> devices need attention"),
        "{}",
        scoped.body
    );
    let list = tech.get(&server, "/devices?attention=1&sort=disk").await;
    assert!(!list.body.contains(&f[0].to_string()), "{}", list.body);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_new_enrollment_token_comes_with_the_commands_to_run() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let org = admin.create_org(&server, "Contoso").await;
    let r = admin
        .post(
            &server,
            &format!("/organizations/{org}/enrollment-tokens"),
            &[("ttl_minutes", "60"), ("max_uses", "1"), ("site", "")],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let token = extract(&r.body, r"(fw8e_[A-Za-z0-9_-]{43})").unwrap();
    let public_url = &server.state.config.public_url;
    assert!(r.body.contains(&format!("$server = '{public_url}'")));
    assert!(r.body.contains("Get-AuthenticodeSignature"));
    assert!(r.body.contains("FLYW8T_ENROLL_TOKEN"));
    assert_eq!(
        r.body.matches(&token).count(),
        1,
        "token must stay out of setup commands"
    );
    let script = flyw8t_web::ENROLLMENT_COPY_JS;
    assert!(r.body.contains(script));
    let digest = ring::digest::digest(&ring::digest::SHA256, script.as_bytes());
    use base64::Engine;
    let hash = base64::engine::general_purpose::STANDARD.encode(digest);
    assert!(r.headers["content-security-policy"]
        .to_str()
        .unwrap()
        .ends_with(&format!("script-src 'sha256-{hash}'")));
    // Shown once: the page that carries a secret is never stored, and a reload shows no token.
    assert_eq!(r.headers["cache-control"], "no-store");
    let again = admin.get(&server, &format!("/organizations/{org}")).await;
    assert!(!again.body.contains("fw8e_"), "{}", again.body);
    assert!(!again.body.contains("Get-AuthenticodeSignature"));
    assert!(again
        .body
        .contains("Deploy quietly with Intune or Group Policy"));
    assert!(again.body.contains("Flyw8t-Setup-x64.exe --quiet"));
    assert!(again.body.contains("Download Intune bundle"));
    assert!(again.body.contains("Download Intune detection script"));
    assert!(!again.headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("script-src"));

    // The token shown separately can enroll a device.
    let agent = TestAgent::enroll(&server.url(), &token).await.unwrap();
    let recorded = flyw8t_agent::AgentConfig::load(agent.dir.path()).unwrap();
    assert_eq!(
        recorded.enrollment_scope,
        Some(flyw8t_protocol::messages::EnrollmentScope {
            organization_id: org,
            site_id: None,
        })
    );
    let list = admin.get(&server, "/devices").await;
    assert!(list.body.contains(&agent.device_id.to_string()));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_windows_installer_only_enrolls_into_its_selected_site() {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request};
    use flyw8t_protocol::enrollment_package::EnrollmentPackage;
    use std::io::Cursor;
    use tower::ServiceExt;

    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let org = admin.create_org(&server, "Contoso").await;
    let site: Uuid = sqlx::query_scalar(
        "INSERT INTO sites (organization_id, name) VALUES ($1, 'Main Office') RETURNING id",
    )
    .bind(org)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    let path = format!("/organizations/{org}/enrollment-tokens");
    let detection = admin
        .post(
            &server,
            &path,
            &[
                ("site", &site.to_string()),
                ("download", "intune-detection"),
            ],
        )
        .await;
    assert_eq!(detection.status, StatusCode::OK);
    assert_eq!(detection.headers[header::CACHE_CONTROL], "no-store");
    assert!(detection.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("Detect-Flyw8t.ps1"));
    assert!(detection.body.starts_with('\u{feff}'));
    assert!(detection
        .body
        .contains(&format!("$expectedOrganization = '{org}'")));
    assert!(detection
        .body
        .contains(&format!("$expectedSite = '{site}'")));
    assert!(detection.body.contains(&format!(
        "$expectedServer = '{}'",
        server.state.config.public_url
    )));
    assert!(!detection.body.contains("fw8e_"));
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM enrollment_tokens")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(tokens, 0, "detection download does not issue a credential");
    for download in ["intune", "intune-detection"] {
        let invalid = admin
            .post(
                &server,
                &path,
                &[
                    ("site", &Uuid::new_v4().to_string()),
                    ("download", download),
                ],
            )
            .await;
        assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    let base = b"MZ synthetic test agent";
    server
        .state
        .windows_agent_template
        .set(base.to_vec())
        .unwrap();
    for (download, filename) in [
        ("windows", "Flyw8t-Setup-x64.exe"),
        ("intune", "Flyw8t-Intune.zip"),
    ] {
        let body = format!("csrf={}&site={site}&download={download}", admin.csrf);
        let reply = flyw8t_server::router(server.state.clone())
            .oneshot(
                Request::post(&path)
                    .header(header::COOKIE, &admin.cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            reply.headers()[header::CONTENT_DISPOSITION],
            format!("attachment; filename={filename}")
        );
        let bytes = to_bytes(reply.into_body(), 32 * 1024).await.unwrap();
        let installer = if download == "intune" {
            unpack_intune_installer(&bytes, &detection.body)
        } else {
            bytes.to_vec()
        };
        let (base_len, package) = EnrollmentPackage::read(&mut Cursor::new(&installer))
            .unwrap()
            .unwrap();
        assert_eq!(base_len as usize, base.len());
        assert_eq!(&installer[..base_len as usize], base);
        assert_eq!(package.organization, "Contoso");
        assert_eq!(package.site.as_deref(), Some("Main Office"));
        let device = TestAgent::enroll(&server.url(), &package.token)
            .await
            .unwrap();
        let saved: (Uuid, Option<Uuid>) =
            sqlx::query_as("SELECT organization_id, site_id FROM devices WHERE id = $1")
                .bind(device.device_id)
                .fetch_one(&server.state.db)
                .await
                .unwrap();
        assert_eq!(saved, (org, Some(site)));
        let recorded = flyw8t_agent::AgentConfig::load(device.dir.path()).unwrap();
        assert_eq!(
            recorded.enrollment_scope,
            Some(flyw8t_protocol::messages::EnrollmentScope {
                organization_id: org,
                site_id: Some(site),
            })
        );
        assert!(
            TestAgent::enroll(&server.url(), &package.token)
                .await
                .is_err(),
            "default setup allows one PC"
        );
    }
    server.stop().await;
}

fn unpack_intune_installer(bundle: &[u8], expected_detector: &str) -> Vec<u8> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ring::{digest, hmac};
    use std::io::{Cursor, Read};
    use zip::ZipArchive;

    fn file(zip: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        zip.by_name(name).unwrap().read_to_end(&mut bytes).unwrap();
        bytes
    }

    let mut bundle = ZipArchive::new(Cursor::new(bundle)).unwrap();
    assert_eq!(bundle.len(), 3);
    assert_eq!(
        file(&mut bundle, "Detect-Flyw8t.ps1"),
        expected_detector.as_bytes()
    );
    let instructions = String::from_utf8(file(&mut bundle, "README.txt")).unwrap();
    assert!(instructions.contains("Flyw8t-Setup-x64.exe --quiet"));
    assert!(instructions.contains("cmd.exe /d /c Uninstall-Flyw8t.cmd"));

    let app = file(&mut bundle, "Flyw8t-Setup-x64.intunewin");
    let mut app = ZipArchive::new(Cursor::new(app.as_slice())).unwrap();
    assert_eq!(app.len(), 2);
    let metadata =
        String::from_utf8(file(&mut app, "IntuneWinPackage/Metadata/Detection.xml")).unwrap();
    let field = |name: &str| {
        metadata
            .split_once(&format!("<{name}>"))
            .unwrap()
            .1
            .split_once(&format!("</{name}>"))
            .unwrap()
            .0
    };
    assert_eq!(field("SetupFile"), "Flyw8t-Setup-x64.exe");
    assert_eq!(field("FileName"), "IntunePackage.intunewin");
    assert_eq!(field("ProfileIdentifier"), "ProfileVersion1");
    assert_eq!(field("FileDigestAlgorithm"), "SHA256");
    let mut encrypted = file(
        &mut app,
        "IntuneWinPackage/Contents/IntunePackage.intunewin",
    );
    assert_eq!(encrypted[..32], STANDARD.decode(field("Mac")).unwrap());
    assert_eq!(
        encrypted[32..48],
        STANDARD.decode(field("InitializationVector")).unwrap()
    );
    let key = hmac::Key::new(
        hmac::HMAC_SHA256,
        &STANDARD.decode(field("MacKey")).unwrap(),
    );
    hmac::verify(&key, &encrypted[32..], &encrypted[..32]).unwrap();
    encrypted[48] ^= 1;
    assert!(hmac::verify(&key, &encrypted[32..], &encrypted[..32]).is_err());
    encrypted[48] ^= 1;
    let decrypted = cbc::Decryptor::<aes::Aes256>::new_from_slices(
        &STANDARD.decode(field("EncryptionKey")).unwrap(),
        &encrypted[32..48],
    )
    .unwrap()
    .decrypt_padded_mut::<Pkcs7>(&mut encrypted[48..])
    .unwrap();
    assert_eq!(
        decrypted.len(),
        field("UnencryptedContentSize").parse::<usize>().unwrap()
    );
    assert_eq!(
        digest::digest(&digest::SHA256, decrypted).as_ref(),
        STANDARD.decode(field("FileDigest")).unwrap()
    );
    let mut payload = ZipArchive::new(Cursor::new(decrypted)).unwrap();
    assert_eq!(payload.len(), 2);
    let uninstall = String::from_utf8(file(&mut payload, "Uninstall-Flyw8t.cmd")).unwrap();
    assert!(uninstall.contains("service uninstall"));
    file(&mut payload, "Flyw8t-Setup-x64.exe")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn a_device_past_the_first_page_is_still_found_by_filters_orders_and_the_overview() {
    let server = start_fresh().await;
    let admin = server.admin_sudo().await;
    let (org, d) = org_with_devices(&server, &admin, "Contoso", 1).await;
    // One page of quiet devices, and after them by name the one with a nearly full disk.
    sqlx::query(
        "INSERT INTO devices (organization_id, hostname, os_family, last_seen_at, last_connected_at)
         SELECT $1, 'bulk-' || lpad(n::text, 4, '0'), 'windows', now(), now() FROM generate_series(1, 2000) n",
    )
    .bind(org)
    .execute(&server.state.db)
    .await
    .unwrap();
    sqlx::query("UPDATE devices SET hostname = 'zzz-last' WHERE id = $1")
        .bind(d[0])
        .execute(&server.state.db)
        .await
        .unwrap();
    report(&server, d[0], inventory("C:\\", 99)).await;
    last_seen(&server, d[0], 0).await;
    let row = format!("href=\"/devices/{}\"", d[0]);

    // The plain list is one page, and says it has been cut.
    let plain = admin.get(&server, "/devices").await;
    assert!(!plain.body.contains(&row));
    assert!(plain.body.contains("Only the first 2000 are shown"));
    // Filtering and ordering look past that page.
    let wanted = admin.get(&server, "/devices?attention=1").await;
    assert!(wanted.body.contains(&row));
    assert!(wanted.body.contains("1 device(s)."));
    let fullest = admin.get(&server, "/devices?sort=disk").await;
    assert!(fullest.body.contains(&row));
    // So does the overview, which therefore makes no partial-fleet remark.
    let overview = admin.get(&server, "/").await;
    assert!(overview.body.contains("C:\\ 99% full"));
    assert!(overview
        .body
        .contains("<span class=\"num\">1</span> devices need attention"));
    assert!(!overview.body.contains("were examined"));
    server.stop().await;
}
