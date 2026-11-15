//! The console frame's links to the operator's other products. They are the process's configuration (set by the
//! first server a process starts), so this file holds the only test that configures them.

mod common;

use axum::http::StatusCode;
use common::*;
use flyw8t_server::config::FamilyLink;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL: set FLYW8T_TEST_DATABASE_URL"]
async fn configured_products_are_plain_links_in_the_frame_of_every_page() {
    let mut config = test_config(&fresh_database().await);
    config.family_links = vec![
        FamilyLink {
            label: "AnchorDesk".into(),
            url: "https://desk.example.com/".into(),
        },
        FamilyLink {
            label: "Port<Glass>".into(),
            url: "https://portglass.example.com/?a=1&b=2".into(),
        },
    ];
    let server = start(config).await;
    let admin = server.admin().await;
    // The last is a device nobody has: an error page inside the frame.
    let missing = format!("/devices/{}", uuid::Uuid::new_v4());
    for path in ["/", "/devices", "/audit", "/account", missing.as_str()] {
        let page = admin.get(&server, path).await;
        if path == missing {
            assert_eq!(page.status, StatusCode::NOT_FOUND);
        } else {
            assert_eq!(page.status, StatusCode::OK, "{path}");
        }
        assert!(page.body.contains(">Products<"), "{path}");
        assert!(
            page.body.contains(
                r#"<a href="https://desk.example.com/" rel="noopener noreferrer" class="family">AnchorDesk</a>"#
            ),
            "{path}: {}",
            page.body
        );
        // A label is text and an address is an attribute: neither becomes markup.
        assert!(page.body.contains("Port&lt;Glass&gt;"), "{path}");
        assert!(
            page.body
                .contains(r#"href="https://portglass.example.com/?a=1&amp;b=2""#),
            "{path}"
        );
    }
    // The sign-in page is for people who have not signed in: it names no other product.
    let login = server
        .request(
            axum::http::Request::get("/login")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert!(!login.body.contains("desk.example.com"));
    server.stop().await;
}
