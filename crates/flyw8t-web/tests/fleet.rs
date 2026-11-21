//! Fleet health as the console shows it: when a device counts as needing attention, and that
//! nothing a device reports can become markup.

use flyw8t_web::model::*;
use flyw8t_web::{device_page, devices_page, organization_page, overview_page};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::days(400)
}

fn ctx() -> PageCtx {
    PageCtx {
        user_name: "Ada".into(),
        role: "admin",
        csrf: "csrf".into(),
        now: now(),
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

fn device(connection: Connection, health: Option<DeviceHealth>) -> DeviceRow {
    DeviceRow {
        id: Uuid::from_u128(7),
        hostname: "host".into(),
        display_name: None,
        tags: vec![],
        organization: OrgRef {
            id: Uuid::from_u128(1),
            name: "Org".into(),
        },
        site: None,
        os: Some("Windows 11 Pro".into()),
        agent_version: Some("0.1.2".into()),
        connection,
        retired: false,
        health,
    }
}

fn health(used_percent: u64, age: Duration) -> DeviceHealth {
    DeviceHealth {
        collected_at: now() - age,
        received_at: now() - age,
        memory_total_bytes: 16 << 30,
        memory_available_bytes: 4 << 30,
        uptime_secs: 3600,
        fullest_disk: Some(DiskUse {
            mount_point: "C:\\".into(),
            total_bytes: 1000,
            available_bytes: 1000 - used_percent * 10,
        }),
    }
}

fn seen(ago: Duration) -> Connection {
    Connection::Disconnected {
        last_seen: Some(now() - ago),
    }
}

fn connected() -> Connection {
    Connection::Connected {
        since: now() - Duration::hours(1),
    }
}

#[test]
fn device_page_opens_only_the_explicit_desktop_modes() {
    let context = ctx();
    let mut d = DeviceDetail {
        row: device(seen(Duration::hours(1)), None),
        os_family: "windows".into(),
        enrolled_at: now(),
        inventory: None,
        credential: None,
        recent_jobs: Vec::new(),
        remote_access: "No external provider configured.".into(),
        notes: String::new(),
        site_id: None,
        sites: Vec::new(),
        fields: Vec::new(),
    };
    let modes = ["assist", "console", "sign-in"];
    // A friendly name is not the network address; agent presence is independent of RDP reachability.
    d.row.display_name = Some("Operator's workstation".into());
    for host in ["WS-01", "ws-01.lab.example.", "192.0.2.8"] {
        d.row.hostname = host.into();
        let html = device_page(&context, d.clone());
        for mode in modes {
            assert!(html.contains(&format!(r#"href="flyw8t://open/{mode}?host={host}""#)));
        }
        assert_eq!(html.matches("flyw8t://").count(), modes.len());
        assert!(html.contains("Enable for this Windows user"));
        let version = env!("CARGO_PKG_VERSION");
        assert!(html.contains(&format!("https://github.com/spilloid/flyw8t/releases/download/v{version}/flyw8t-technician-v{version}-x86_64-pc-windows-msvc.exe")));
    }
    for host in [
        "",
        " host ",
        "ws?host=other",
        "example:3389",
        "127.1",
        "010.0.0.1",
        "host..example",
    ] {
        d.row.hostname = host.into();
        let html = device_page(&context, d.clone());
        for mode in modes {
            assert!(
                html.contains(&format!(r#"href="flyw8t://open/{mode}""#)),
                "{host}"
            );
        }
        assert!(html.contains("Enter the computer name or IP address"));
    }
    let mut readonly = ctx();
    readonly.can_support = false;
    assert!(!device_page(&readonly, d.clone()).contains("flyw8t://"));
    d.row.retired = true;
    assert!(!device_page(&context, d.clone()).contains("flyw8t://"));
    d.row.retired = false;
    for family in ["linux", "darwin", ""] {
        d.os_family = family.into();
        assert!(!device_page(&context, d.clone()).contains("flyw8t://"));
    }
}

#[test]
fn used_percent_rounds_down_and_survives_nonsense() {
    assert_eq!(used_percent(1000, 100), 90);
    assert_eq!(used_percent(1000, 101), 89);
    assert_eq!(used_percent(0, 0), 0, "no division by zero");
    assert_eq!(
        used_percent(10, 50),
        0,
        "more free than total is not negative"
    );
    assert_eq!(used_percent(u64::MAX, 0), 100, "no overflow");
}

#[test]
fn a_disk_needs_attention_from_ninety_percent() {
    let at = |p| device(connected(), Some(health(p, Duration::hours(1)))).concerns(now());
    assert!(at(89).is_empty());
    assert_eq!(
        at(90),
        vec![Concern::DiskNearlyFull {
            mount_point: "C:\\".into(),
            used_percent: 90
        }]
    );
}

#[test]
fn silence_needs_attention_from_seven_days_and_never_connecting_always_does() {
    let quiet = |d: Duration| device(seen(d), None).concerns(now());
    assert!(quiet(Duration::days(7) - Duration::seconds(1)).is_empty());
    assert_eq!(
        quiet(Duration::days(7)),
        vec![Concern::LongOffline { days: 7 }]
    );
    assert_eq!(
        device(Connection::NeverConnected, None).concerns(now()),
        vec![Concern::NeverConnected]
    );
    assert_eq!(
        device(Connection::Disconnected { last_seen: None }, None).concerns(now()),
        vec![Concern::NeverConnected]
    );
}

#[test]
fn stale_inventory_matters_only_while_connected() {
    let old = Duration::days(3);
    // Connected and silent about itself: something is wrong with the agent.
    assert_eq!(
        device(connected(), Some(health(10, old))).concerns(now()),
        vec![Concern::StaleInventory { days: 3 }]
    );
    // Offline for a day: of course its inventory is old. Not a second concern.
    assert!(device(seen(Duration::days(1)), Some(health(10, old)))
        .concerns(now())
        .is_empty());
    assert!(device(connected(), Some(health(10, Duration::hours(47))))
        .concerns(now())
        .is_empty());
    // Two days exactly is stale.
    assert_eq!(
        device(connected(), Some(health(10, Duration::days(2)))).concerns(now()),
        vec![Concern::StaleInventory { days: 2 }]
    );
}

#[test]
fn staleness_goes_by_when_the_server_received_the_report_not_the_devices_clock() {
    // A device whose clock is years ahead: the report it sent three days ago is still stale.
    let mut ahead = health(10, Duration::days(3));
    ahead.collected_at = now() + Duration::days(3650);
    assert_eq!(
        device(connected(), Some(ahead)).concerns(now()),
        vec![Concern::StaleInventory { days: 3 }]
    );
    // One whose clock is years behind is not stale if the report has just arrived.
    let mut behind = health(10, Duration::ZERO);
    behind.collected_at = now() - Duration::days(3650);
    assert!(device(connected(), Some(behind)).concerns(now()).is_empty());
}

#[test]
fn connected_for_two_days_with_no_readable_inventory_needs_attention() {
    let since = |d: Duration| Connection::Connected { since: now() - d };
    assert_eq!(
        device(since(Duration::days(2)), None).concerns(now()),
        vec![Concern::NoInventory { days: 2 }]
    );
    // Newly connected: its first inventory may still be on its way.
    assert!(device(since(Duration::hours(47)), None)
        .concerns(now())
        .is_empty());
}

#[test]
fn a_retired_device_needs_nothing() {
    let mut d = device(
        Connection::NeverConnected,
        Some(health(99, Duration::days(30))),
    );
    d.retired = true;
    assert!(d.concerns(now()).is_empty());
}

#[test]
fn the_most_serious_concern_comes_first() {
    let d = device(
        seen(Duration::days(20)),
        Some(health(95, Duration::days(20))),
    );
    let c = d.concerns(now());
    assert!(matches!(c[0], Concern::DiskNearlyFull { .. }), "{c:?}");
    assert_eq!(c[1], Concern::LongOffline { days: 20 });
}

#[test]
fn what_a_device_reports_is_never_markup_in_the_list() {
    let mut h = health(95, Duration::hours(2));
    h.fullest_disk.as_mut().unwrap().mount_point = "<img src=x onerror=alert(1)>".into();
    let mut d = device(connected(), Some(h));
    d.os = Some("<script>alert(2)</script>".into());
    d.agent_version = Some("\"><b>v</b>".into());
    let filter = DeviceFilter {
        q: "a&b=c <x>".into(),
        ..Default::default()
    };
    let html = devices_page(&ctx(), vec![d], filter, vec![], vec![]);
    assert!(!html.contains("<img src=x"), "{html}");
    assert!(!html.contains("<script>alert(2)"), "{html}");
    assert!(!html.contains("<b>v</b>"), "{html}");
    assert!(html.contains("&lt;img src=x"), "{html}");
    // The bar carries the figure, and the figures say how old they are.
    assert!(html.contains("value=\"95\""), "{html}");
    assert!(html.contains("reported <time"), "{html}");
    // Sort links keep the search, encoded, so it cannot add parameters or markup.
    assert!(
        html.contains("href=\"/devices?q=a%26b%3Dc%20%3Cx%3E&amp;sort=disk\""),
        "{html}"
    );
}

#[test]
fn a_device_with_no_readable_report_shows_dashes_not_zeroes() {
    let html = devices_page(
        &ctx(),
        vec![device(connected(), None)],
        DeviceFilter::default(),
        vec![],
        vec![],
    );
    assert!(!html.contains("<meter"), "no bar without a figure: {html}");
    assert!(!html.contains("reported <time"));
    assert!(!html.contains("0%"), "{html}");
}

fn overview(devices_total: i64, organizations: Vec<OrgRef>) -> Overview {
    Overview {
        devices_total,
        devices_connected: 0,
        jobs_in_flight: 0,
        jobs_succeeded_24h: 0,
        jobs_failed_24h: 0,
        jobs_unknown: 0,
        attention: vec![],
        recent: vec![],
        organizations,
        device_attention: vec![],
        device_attention_total: 0,
        agent_versions: vec![],
        devices_truncated: false,
    }
}

#[test]
fn the_first_run_steps_show_only_until_a_device_exists_and_only_what_the_person_can_do() {
    let org = OrgRef {
        id: Uuid::from_u128(5),
        name: "Org".into(),
    };
    let html = overview_page(&ctx(), overview(0, vec![]));
    assert!(html.contains("Enroll your first device"));
    assert!(html.contains("href=\"/organizations\""));
    let html = overview_page(&ctx(), overview(0, vec![org.clone()]));
    assert!(html.contains(&format!("href=\"/organizations/{}#enroll-device\"", org.id)));
    assert!(html.contains("class=\"done\""));
    let second = OrgRef {
        id: Uuid::from_u128(6),
        name: "Second".into(),
    };
    let multi = overview_page(&ctx(), overview(0, vec![org.clone(), second.clone()]));
    for visible in [&org, &second] {
        assert!(multi.contains(&format!("/organizations/{}#enroll-device", visible.id)));
    }
    // Someone who cannot enroll is not told to.
    let mut readonly = ctx();
    readonly.can_enroll = false;
    readonly.is_admin = false;
    let html = overview_page(&readonly, overview(0, vec![org]));
    assert!(!html.contains("Enroll your first device"));
    assert!(html.contains("No devices are enrolled"));
    // With a device, the steps are gone and the health sections are there.
    let html = overview_page(&ctx(), overview(1, vec![]));
    assert!(!html.contains("Enroll your first device"));
    assert!(html.contains("Devices needing attention"));
    assert!(html.contains("This server is 9.9.9"));
}

#[test]
fn devices_offer_enrollment_in_visible_organizations() {
    let one = OrgRef {
        id: Uuid::from_u128(1),
        name: "First".into(),
    };
    let two = OrgRef {
        id: Uuid::from_u128(2),
        name: "Second".into(),
    };
    let render = |context: &PageCtx, orgs, selected| {
        devices_page(
            context,
            vec![],
            DeviceFilter {
                organization: selected,
                ..Default::default()
            },
            orgs,
            vec![],
        )
    };
    let link = |id| format!("/organizations/{id}#enroll-device");
    let single = render(&ctx(), vec![one.clone()], None);
    assert!(single.contains(&link(one.id)));
    assert!(single.contains("Enroll a Windows device"));
    let orgs = vec![one.clone(), two.clone()];
    let foreign = Uuid::from_u128(3);
    let all = render(&ctx(), orgs.clone(), Some(foreign));
    assert!(all.contains(&link(one.id)) && all.contains(&link(two.id)));
    assert!(!all.contains(&link(foreign)));
    let filtered = render(&ctx(), orgs.clone(), Some(two.id));
    assert!(filtered.contains(&link(two.id)) && !filtered.contains(&link(one.id)));
    assert!(render(&ctx(), vec![], None).contains("Create an organization to enroll a device"));
    let mut reader = ctx();
    reader.can_enroll = false;
    assert!(!render(&reader, orgs, None).contains("Enroll a Windows device"));
}

#[test]
fn enrollment_downloads_are_pinned_and_setup_commands_are_separate_from_the_token() {
    let org = OrgSummary {
        id: Uuid::from_u128(5),
        name: "Org".into(),
        device_count: 0,
        sites: vec![],
        created_at: now(),
    };
    let revealed = RevealedSecret {
        label: "Enrollment token".into(),
        secret: "fw8e_abc".into(),
        hint: "hint".into(),
        commands: Some("Write-Output 'before </textarea><b> after'".into()),
    };
    let version = env!("CARGO_PKG_VERSION");
    let release = format!("https://github.com/spilloid/flyw8t/releases/download/v{version}/");
    let normal = organization_page(&ctx(), org.clone(), vec![], None, vec![]);
    assert!(normal.contains(&format!(
        "{release}flyw8t-agent-v{version}-x86_64-pc-windows-msvc.exe"
    )));
    assert!(normal.contains(&format!("{release}SHA256SUMS")));
    assert!(!normal.contains("<script"));
    let html = organization_page(&ctx(), org, vec![], Some(revealed), vec![]);
    assert!(html.contains("Write-Output 'before &lt;/textarea>&lt;b> after'"));
    assert!(!html.contains("</textarea><b>"));
    assert!(html.contains(r#"value="fw8e_abc""#));
    assert_eq!(html.matches("fw8e_abc").count(), 1);
    assert!(html.contains(&format!(
        "<script>{}</script>",
        flyw8t_web::ENROLLMENT_COPY_JS
    )));
    assert!(html.contains("Copy token") && html.contains("Copy setup commands"));
}
