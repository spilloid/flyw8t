//! TLS client configuration: public web PKI roots, plus one optional private CA.

use anyhow::{Context, Result};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

pub fn client_config(extra_ca_pem: Option<&str>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_ca_pem {
        let mut added = 0;
        for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
            roots
                .add(cert.context("parsing CA certificate")?)
                .context("adding CA certificate")?;
            added += 1;
        }
        anyhow::ensure!(added > 0, "CA file contains no certificates");
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}
