//! OIDC code + PKCE sign-in. The library verifies tokens; the transport is bounded and
//! restricted to the operator's configured issuer origin. No provider token is retained.
use crate::audit::Audit;
use crate::auth;
use crate::directory;
use crate::error::{AppError, AppResult};
use crate::Shared;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Redirect, Response};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreProviderMetadata,
};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IdToken, IssuerUrl,
    Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
}
impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .finish()
    }
}
impl OidcConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_url(&self.issuer)?;
        let issuer = reqwest::Url::parse(&self.issuer)?;
        anyhow::ensure!(
            issuer.query().is_none(),
            "OIDC issuer cannot contain a query"
        );
        anyhow::ensure!(
            !self.client_id.trim().is_empty() && self.client_id.len() <= 500,
            "OIDC client id is required and bounded"
        );
        anyhow::ensure!(
            !self.client_secret.is_empty() && self.client_secret.len() <= 4096,
            "OIDC client secret is required and bounded"
        );
        Ok(())
    }
}

pub fn validate_url(raw: &str) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("OIDC endpoint has no host"))?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "OIDC endpoints require HTTPS except loopback"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "OIDC endpoint cannot contain credentials or a fragment"
    );
    Ok(url)
}

const TTL: Duration = Duration::from_secs(300);
const MAX_RESPONSE: usize = 1024 * 1024;
struct Flow {
    resume: Option<Resume>,
    browser_hash: Vec<u8>,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    expires: Instant,
}
#[derive(Default)]
pub struct Flows(Mutex<HashMap<Vec<u8>, Flow>>);

fn flow_cookie_name(state: &Shared) -> &'static str {
    if state.config.secure_cookies() {
        "__Host-flyw8t_oidc"
    } else {
        "flyw8t_oidc"
    }
}
fn flow_cookie(state: &Shared, value: &str, age: u64) -> String {
    let secure = if state.config.secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}{secure}",
        flow_cookie_name(state)
    )
}
fn presented_cookie<'a>(state: &Shared, headers: &'a HeaderMap) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .find_map(|(n, v)| (n == flow_cookie_name(state)).then_some(v))
}
fn provider_failed() -> AppError {
    AppError::BadRequest("The identity provider could not complete this sign-in. Start again, or use a local break-glass account.".into())
}

#[derive(Clone)]
struct Transport {
    client: reqwest::Client,
    origin: reqwest::Url,
}
impl Transport {
    fn client_builder() -> reqwest::ClientBuilder {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .no_proxy()
    }
    fn new(config: &OidcConfig) -> AppResult<Self> {
        let client = Self::client_builder()
            .build()
            .map_err(|_| provider_failed())?;
        Ok(Self {
            client,
            origin: validate_url(&config.issuer).map_err(|_| provider_failed())?,
        })
    }
    fn allowed(&self, raw: &str) -> bool {
        validate_url(raw).is_ok_and(|url| url.origin() == self.origin.origin())
    }
    async fn request(
        &self,
        request: openidconnect::HttpRequest,
    ) -> Result<openidconnect::HttpResponse, std::io::Error> {
        let reject = || std::io::Error::other("OIDC transport refused or failed");
        if !self.allowed(&request.uri().to_string()) || request.body().len() > 64 * 1024 {
            return Err(reject());
        }
        let (parts, body) = request.into_parts();
        let mut response = self
            .client
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| reject())?;
        if response.status().is_redirection()
            || response
                .content_length()
                .is_some_and(|n| n > MAX_RESPONSE as u64)
        {
            return Err(reject());
        }
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| reject())? {
            if body.len() + chunk.len() > MAX_RESPONSE {
                return Err(reject());
            }
            body.extend_from_slice(&chunk);
        }
        let mut out = openidconnect::http::Response::builder()
            .status(status)
            .body(body)
            .map_err(|_| reject())?;
        *out.headers_mut() = headers;
        Ok(out)
    }
    async fn discover(&self, cfg: &OidcConfig) -> AppResult<CoreProviderMetadata> {
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(cfg.issuer.clone()).map_err(|_| provider_failed())?,
            self,
        )
        .await
        .map_err(|_| provider_failed())?;
        if !self.allowed(metadata.authorization_endpoint().as_str())
            || !self.allowed(metadata.jwks_uri().as_str())
            || !metadata
                .token_endpoint()
                .is_some_and(|url| self.allowed(url.as_str()))
        {
            return Err(provider_failed());
        }
        Ok(metadata)
    }
}

impl<'c> openidconnect::AsyncHttpClient<'c> for Transport {
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<openidconnect::HttpResponse, Self::Error>>
                + Send
                + 'c,
        >,
    >;
    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        Box::pin(self.request(request))
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Resume {
    Mcp,
    Passkey,
}

#[derive(Deserialize)]
pub struct StartQuery {
    resume: Option<Resume>,
}

pub async fn start(
    State(state): State<Shared>,
    Query(query): Query<StartQuery>,
    crate::client_ip::ClientIp(ip): crate::client_ip::ClientIp,
) -> Response {
    let result: AppResult<Response> = async {
        let cfg = state.config.oidc.as_ref().ok_or(AppError::NotFound)?;
        if !state.limiter.allow(&format!("oidc-start:{ip}"), 10, TTL) {
            return Err(AppError::RateLimited);
        }
        let transport = Transport::new(cfg)?;
        let metadata = transport.discover(cfg).await?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(cfg.client_id.clone()),
            Some(ClientSecret::new(cfg.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/login/oidc/callback", state.config.public_url))
                .map_err(|_| provider_failed())?,
        );
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("groups".into()))
            .set_max_age(if query.resume.is_some() {
                Duration::ZERO
            } else {
                TTL
            })
            .set_pkce_challenge(challenge)
            .url();
        let browser = auth::random_secret(32);
        {
            let mut flows = state
                .oidc_flows
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("OIDC flow lock poisoned"))?;
            flows.retain(|_, f| f.expires > Instant::now());
            if flows.len() >= 1024 {
                return Err(AppError::RateLimited);
            }
            flows.insert(
                auth::digest(csrf.secret()),
                Flow {
                    resume: query.resume,
                    browser_hash: auth::digest(&browser),
                    nonce,
                    verifier,
                    expires: Instant::now() + TTL,
                },
            );
        }
        Ok((
            [(
                header::SET_COOKIE,
                flow_cookie(&state, &browser, TTL.as_secs()),
            )],
            Redirect::to(url.as_str()),
        )
            .into_response())
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Deserialize)]
pub struct Callback {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}
#[derive(Debug, Deserialize, Serialize)]
struct Groups {
    #[serde(default)]
    groups: Vec<String>,
}
impl openidconnect::AdditionalClaims for Groups {}
type DirectoryToken =
    IdToken<Groups, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;

pub async fn callback(
    State(state): State<Shared>,
    crate::client_ip::ClientIp(ip): crate::client_ip::ClientIp,
    headers: HeaderMap,
    Query(params): Query<Callback>,
) -> Response {
    let result: AppResult<Response> = async {
        let cfg = state.config.oidc.as_ref().ok_or(AppError::NotFound)?;
        let browser = presented_cookie(&state, &headers).ok_or(AppError::Unauthorized)?;
        let key = auth::digest(
            params
                .state
                .as_deref()
                .filter(|s| s.len() <= 500)
                .ok_or(AppError::Unauthorized)?,
        );
        let flow = {
            let mut flows = state
                .oidc_flows
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("OIDC flow lock poisoned"))?;
            let matched = flows.get(&key).is_some_and(|f| {
                f.expires > Instant::now() && f.browser_hash == auth::digest(browser)
            });
            if !matched {
                return Err(AppError::Unauthorized);
            }
            flows.remove(&key).ok_or(AppError::Unauthorized)?
        };
        if params.error.is_some() {
            return Err(provider_failed());
        }
        let code = params
            .code
            .filter(|c| !c.is_empty() && c.len() <= 4096)
            .ok_or(AppError::Unauthorized)?;
        let transport = Transport::new(cfg)?;
        let metadata = transport.discover(cfg).await?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(cfg.client_id.clone()),
            Some(ClientSecret::new(cfg.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/login/oidc/callback", state.config.public_url))
                .map_err(|_| provider_failed())?,
        );

        let tokens = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| provider_failed())?
            .set_pkce_verifier(flow.verifier)
            .request_async(&transport)
            .await
            .map_err(|_| provider_failed())?;
        let token: DirectoryToken = tokens
            .id_token()
            .ok_or_else(provider_failed)?
            .to_string()
            .parse()
            .map_err(|_| provider_failed())?;
        let verifier = client.id_token_verifier().set_allowed_algs([
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        ]);
        let claims = token
            .claims(&verifier, &flow.nonce)
            .map_err(|_| provider_failed())?;
        if claims
            .authorized_party()
            .is_some_and(|party| party.as_str() != cfg.client_id)
        {
            return Err(provider_failed());
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if claims.issue_time().timestamp() > now + 60 {
            return Err(provider_failed());
        }
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                tokens.access_token(),
                token.signing_alg().map_err(|_| provider_failed())?,
                token
                    .signing_key(&verifier)
                    .map_err(|_| provider_failed())?,
            )
            .map_err(|_| provider_failed())?;
            if &actual != expected {
                return Err(provider_failed());
            }
        }
        let groups = &claims.additional_claims().groups;
        if groups.len() > 1000
            || groups
                .iter()
                .any(|g| g.is_empty() || g.len() > 200 || g.chars().any(char::is_control))
        {
            return Err(provider_failed());
        }
        let subject = claims.subject().as_str();
        let email = claims.email().ok_or_else(provider_failed)?.as_str();
        let name = claims
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.as_str())
            .unwrap_or(email);
        let auth_at = claims
            .auth_time()
            .map(|t| t.timestamp())
            .filter(|t| *t <= now && now - *t <= 300)
            .and_then(|t| time::OffsetDateTime::from_unix_timestamp(t).ok());
        let mut tx = state.db.begin().await?;
        directory::lock_all(&mut tx).await?;
        let user =
            directory::ensure_identity(&mut tx, &cfg.issuer, subject, email, name, false).await?;
        sqlx::query("UPDATE directory_users SET groups=$2 WHERE user_id=$1 AND NOT managed")
            .bind(user)
            .bind(groups)
            .execute(&mut *tx)
            .await?;
        let revoked = directory::reconcile(&mut tx, user).await?;
        let (enabled,): (bool,) =
            sqlx::query_as("SELECT disabled_at IS NULL FROM users WHERE id=$1")
                .bind(user)
                .fetch_one(&mut *tx)
                .await?;
        let cookie = if enabled {
            Some(
                create_session(
                    &state,
                    &mut tx,
                    user,
                    &ip,
                    headers
                        .get(header::USER_AGENT)
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or(""),
                    auth_at,
                )
                .await?,
            )
        } else {
            None
        };
        let audit = Audit::anonymous("web", email, "user.login.oidc")
            .ip(ip)
            .target("user", user);
        if enabled {
            audit.record(&mut *tx).await?;
        } else {
            audit.denied().record(&mut *tx).await?;
        }
        tx.commit().await?;
        if revoked {
            directory::finish_revocations(&state, vec![user]).await?;
        }
        let cookie = cookie.ok_or(AppError::Unauthorized)?;
        // Commit a same-origin document before navigation: a redirect chain originating
        // at a cross-site IdP suppresses Strict cookies even on the final same-origin hop.
        let (href, label) = match flow.resume {
            Some(Resume::Mcp) => ("/admin#mcp-client", "Continue to MCP setup"),
            Some(Resume::Passkey) => ("/account/passkeys/new", "Continue to add a passkey"),
            None => ("/", "Continue to flyw8t"),
        };
        let mut response = Html(flyw8t_web::oidc_return_page(
            href,
            label,
            flow.resume.is_some() && auth_at.is_none(),
        ))
        .into_response();
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie.parse().map_err(|_| provider_failed())?,
        );
        response.headers_mut().append(
            header::SET_COOKIE,
            flow_cookie(&state, "", 0)
                .parse()
                .map_err(|_| provider_failed())?,
        );
        Ok(response)
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn create_session(
    state: &Shared,
    tx: &mut sqlx::PgConnection,
    user: Uuid,
    ip: &str,
    ua: &str,
    auth_at: Option<time::OffsetDateTime>,
) -> AppResult<String> {
    let secret = auth::random_secret(32);
    sqlx::query("INSERT INTO sessions(user_id,token_hash,csrf_token,expires_at,client_ip,user_agent,stage,auth_method,provider_authenticated_at) VALUES($1,$2,$3,now()+make_interval(secs=>$4),$5,$6,'full','oidc',$7)")
        .bind(user).bind(auth::digest(&secret)).bind(auth::random_secret(24)).bind(state.config.session_ttl.as_secs_f64()).bind(ip).bind(ua.chars().take(500).collect::<String>()).bind(auth_at).execute(tx).await?;
    Ok(auth::set_cookie(
        state,
        &secret,
        state.config.session_ttl.as_secs(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_urls_require_https_except_loopback_and_never_credentials() {
        for good in [
            "https://id.example.com/application/o/flyw8t/",
            "http://127.0.0.1:1234/",
            "http://[::1]:8080/",
        ] {
            assert!(validate_url(good).is_ok(), "{good}");
        }
        for bad in [
            "http://example.com/",
            "http://localhost.example.com/",
            "https://user:pass@example.com/",
            "https://example.com/#x",
            "file:///x",
        ] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn client_secret_is_redacted_from_debug() {
        let cfg = OidcConfig {
            issuer: "https://id.example.com/".into(),
            client_id: "client".into(),
            client_secret: "sensitive".into(),
        };
        assert!(!format!("{cfg:?}").contains("sensitive"));
    }
}
#[cfg(test)]
mod flow_expiry_tests {
    use super::*;
    #[tokio::test]
    async fn expired_browser_flows_are_rejected_before_contacting_the_provider() {
        let config = crate::config::Config {
            oidc: Some(OidcConfig {
                issuer: "http://127.0.0.1:9".into(),
                client_id: "test".into(),
                client_secret: "test".into(),
            }),
            ..crate::config::Config::defaults()
        };
        let state = std::sync::Arc::new(crate::AppState {
            db: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://postgres@127.0.0.1:9/postgres")
                .unwrap(),
            config,
            registry: Default::default(),
            limiter: Default::default(),
            remote_access: Box::new(crate::remote_access::NotConfigured),
            support: Default::default(),
            started_unix: 0,
            bodies: Default::default(),
            oidc_flows: Default::default(),
            windows_agent_template: Default::default(),
        });
        state.oidc_flows.0.lock().unwrap().insert(
            auth::digest("state"),
            Flow {
                browser_hash: auth::digest("browser"),
                resume: None,
                nonce: Nonce::new("nonce".into()),
                verifier: PkceCodeVerifier::new("v".repeat(43)),
                expires: Instant::now() - Duration::from_secs(1),
            },
        );
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "flyw8t_oidc=browser".parse().unwrap());
        let response = callback(
            State(state),
            crate::client_ip::ClientIp("127.0.0.1".into()),
            headers,
            Query(Callback {
                state: Some("state".into()),
                code: Some("code".into()),
                error: None,
            }),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod https_root_tests {
    use super::*;
    fn config(issuer: &str) -> OidcConfig {
        OidcConfig {
            issuer: issuer.into(),
            client_id: "unused-read-only-test".into(),
            client_secret: "unused-read-only-test".into(),
        }
    }

    // Public-CA trust cannot be proven by injecting a private test root: that would also
    // pass with the broken 0.1.4 manual-root feature. This mandatory release check uses
    // the production client and requires external HTTPS egress, without credentials.
    #[tokio::test]
    #[ignore = "requires outbound public HTTPS; mandatory release/full --include-ignored check"]
    async fn production_oidc_client_trusts_bundled_public_https_roots() {
        let transport = Transport::new(&config("https://example.com/")).unwrap();
        let response = transport
            .client
            .get("https://example.com/")
            .send()
            .await
            .unwrap_or_else(|error| {
                panic!("production OIDC client rejected public-CA HTTPS: {error:?}")
            });
        assert!(
            !response.status().is_redirection(),
            "public HTTPS fixture changed to a redirect"
        );
    }

    #[tokio::test]
    async fn oidc_https_rejects_untrusted_certificates_and_wrong_hostnames() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            pem.clone().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "TLS fixture" }));
        let server = tokio::spawn(
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(app.into_make_service()),
        );
        let url = format!("https://localhost:{port}/");
        let production = Transport::new(&config(&url)).unwrap();
        let error = production.client.get(&url).send().await.unwrap_err();
        assert!(
            format!("{error:?}").contains("UnknownIssuer"),
            "wrong failure, not untrusted certificate: {error:?}"
        );
        // Trust only this fixture's CA as a test control, keeping verification enabled.
        let control = Transport::client_builder()
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        assert_eq!(
            control.get(&url).send().await.unwrap().status(),
            reqwest::StatusCode::OK
        );
        let error = control
            .get(format!("https://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap_err();
        assert!(
            format!("{error:?}").contains("NotValidForName"),
            "wrong failure, not hostname mismatch: {error:?}"
        );
        server.abort();
    }
}
