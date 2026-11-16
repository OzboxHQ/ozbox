//! Cloud-account providers behind the credential broker: AWS Bedrock (SigV4), Azure OpenAI (a key, or an Entra token) and
//! Google Vertex (a service-account token) (ADR 0017 item 4, ADR 0028).
//!
//! A run never holds these credentials. The stored secret `model-key-<id>` is either a plain token (a Bedrock API key, an
//! Azure `api-key`, a Vertex `x-goog-api-key`: sent in the one header the provider reads, as before) or a JSON document that
//! the broker turns into a signed request or a short-lived bearer token **inside the secrets service**:
//!
//! | Provider | JSON credential | What goes upstream |
//! |---|---|---|
//! | Bedrock | `{"access_key_id","secret_access_key","session_token"?}` | an AWS Signature Version 4 `Authorization` header (+ `x-amz-date`, `x-amz-security-token`) computed for this one request |
//! | Azure OpenAI | `{"tenant_id","client_id","client_secret"}` | `Authorization: Bearer` from a client-credentials token for `cognitiveservices.azure.com` |
//! | Vertex | a Google service-account key file | `Authorization: Bearer` from a self-signed JWT exchanged at Google's token endpoint |
//!
//! The run is handed only its `ozrt_` per-run token, exactly as for every other provider. Tokens fetched here are cached in
//! memory until a minute before they expire and are never logged, returned or put in an error. A credential that does not
//! parse, a signature that cannot be made or a token endpoint that refuses ends in one plain sentence; nothing here falls
//! back to forwarding what the run sent.
//!
//! Not verified against the real services: every test here uses fakes (a known-answer SigV4 vector, a fake token endpoint).

use std::collections::BTreeMap;
use std::sync::Mutex;

use ring::digest::{digest, SHA256};
use ring::hmac;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::netguard::{Guard, HttpRequest};
use crate::settings::ModelKind;

const ENTRA_SCOPE: &str = "https://cognitiveservices.azure.com/.default";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// A token is refreshed this long before it expires.
const REFRESH_BEFORE_MS: u64 = 60_000;

/// A credential, parsed from what the store holds.
pub enum Cred {
    /// A plain token for the provider's own header (Bedrock API key, Azure `api-key`, Vertex `x-goog-api-key`).
    Plain(String),
    Aws {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
    Entra {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    Gcp {
        client_email: String,
        private_key: String,
        /// The account's project: a run names none of its own, the broker puts this one in the path.
        project_id: Option<String>,
    },
}

impl std::fmt::Debug for Cred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cred(..)")
    }
}

fn field(v: &Value, k: &str) -> Result<String, String> {
    v[k].as_str()
        .filter(|s| !s.is_empty() && s.len() <= 8192)
        .map(str::to_string)
        .ok_or_else(|| "the saved credentials are missing a field".to_string())
}

fn plain_chars(s: &str, extra: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || extra.contains(&b))
}

/// Read what the store holds for a provider of this kind. A value that does not start with `{` is a plain token.
pub fn parse(kind: ModelKind, text: &str) -> Result<Cred, String> {
    let t = text.trim();
    if !t.starts_with('{') {
        return Ok(Cred::Plain(t.to_string()));
    }
    let v: Value = serde_json::from_str(t)
        .map_err(|_| "the saved credentials are not valid JSON".to_string())?;
    match kind {
        ModelKind::Bedrock => Ok(Cred::Aws {
            access_key_id: field(&v, "access_key_id")?,
            secret_access_key: field(&v, "secret_access_key")?,
            session_token: v["session_token"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        }),
        ModelKind::AzureOpenai => {
            let c = Cred::Entra {
                tenant_id: field(&v, "tenant_id")?,
                client_id: field(&v, "client_id")?,
                client_secret: field(&v, "client_secret")?,
            };
            if let Cred::Entra {
                tenant_id,
                client_id,
                ..
            } = &c
            {
                if !plain_chars(tenant_id, &[]) || !plain_chars(client_id, &[]) {
                    return Err("the saved Azure tenant or client id is not valid".into());
                }
            }
            Ok(c)
        }
        ModelKind::Vertex => Ok(Cred::Gcp {
            client_email: field(&v, "client_email")?,
            private_key: field(&v, "private_key")?,
            project_id: v["project_id"]
                .as_str()
                .filter(|p| plain_chars(p, &[]))
                .map(str::to_string),
        }),
        _ => Err("this provider does not take JSON credentials".into()),
    }
}

impl Cred {
    /// Every secret string in the credential, for removing an echo from an answer.
    pub fn secrets(&self) -> Vec<String> {
        match self {
            Cred::Plain(k) => vec![k.clone()],
            Cred::Aws {
                secret_access_key,
                session_token,
                ..
            } => std::iter::once(secret_access_key.clone())
                .chain(session_token.clone())
                .collect(),
            Cred::Entra { client_secret, .. } => vec![client_secret.clone()],
            Cred::Gcp { private_key, .. } => vec![private_key.clone()],
        }
    }

    /// Whether this needs signing or a token exchange rather than one header.
    /// The Google project a service-account credential names.
    pub fn project(&self) -> Option<&str> {
        match self {
            Cred::Gcp { project_id, .. } => project_id.as_deref(),
            _ => None,
        }
    }

    pub fn structured(&self) -> bool {
        !matches!(self, Cred::Plain(_))
    }

    fn fingerprint(&self) -> String {
        let mut all = self.secrets().join("\u{1}");
        if let Cred::Aws { access_key_id, .. } = self {
            all.push_str(access_key_id);
        }
        ozbox_core::audit::hex(digest(&SHA256, all.as_bytes()).as_ref())
    }
}

/// What one request is sent through to fetch a token: the broker's upstream, or the connection test's client.
pub type Send<'a> = &'a dyn Fn(&HttpRequest) -> Result<(u16, Vec<u8>), String>;

#[derive(Default)]
pub struct TokenCache {
    /// provider id -> (token, expires at ms, fingerprint of the credential it came from)
    map: Mutex<BTreeMap<String, (String, u64, String)>>,
}

impl TokenCache {
    fn get(&self, id: &str, fp: &str, now_ms: u64) -> Option<String> {
        let m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        m.get(id)
            .filter(|(_, exp, f)| *exp > now_ms + REFRESH_BEFORE_MS && f == fp)
            .map(|(t, _, _)| t.clone())
    }
    fn put(&self, id: &str, fp: &str, token: String, exp_ms: u64) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string(), (token, exp_ms, fp.to_string()));
    }
}

/// What a request needs to be authorised for one provider.
pub struct Ctx<'a> {
    pub kind: ModelKind,
    pub provider_id: &'a str,
    pub region: Option<&'a str>,
    pub now_ms: u64,
}

/// Put authorisation on `req` for this credential. A plain token goes in the provider's one header; a structured credential
/// is signed or exchanged for a bearer token. Never leaves `req` half-authorised: an error means nothing was added.
pub fn authorize(
    req: &mut HttpRequest,
    ctx: &Ctx<'_>,
    cred: &Cred,
    cache: &TokenCache,
    send: Send<'_>,
) -> Result<(), String> {
    match cred {
        Cred::Plain(k) => {
            let (n, v) = plain_header(ctx.kind, k);
            req.headers.push((n.to_string(), v));
            Ok(())
        }
        Cred::Aws {
            access_key_id,
            secret_access_key,
            session_token,
        } => {
            let region = ctx.region.ok_or("the Bedrock region is not set")?;
            let h = sign_v4(
                req,
                &AwsKeys {
                    access_key_id,
                    secret_access_key,
                    session_token: session_token.as_deref(),
                },
                region,
                "bedrock",
                ctx.now_ms / 1000,
            )?;
            req.headers.extend(h);
            Ok(())
        }
        Cred::Entra { .. } | Cred::Gcp { .. } => {
            let fp = cred.fingerprint();
            let token = match cache.get(ctx.provider_id, &fp, ctx.now_ms) {
                Some(t) => t,
                None => {
                    let (t, exp) = fetch_token(cred, ctx.now_ms, send)?;
                    cache.put(ctx.provider_id, &fp, t.clone(), exp);
                    t
                }
            };
            req.headers
                .push(("Authorization".into(), format!("Bearer {token}")));
            Ok(())
        }
    }
}

/// The one header a plain token goes in, per provider.
pub fn plain_header(kind: ModelKind, key: &str) -> (&'static str, String) {
    match kind {
        ModelKind::Anthropic => ("x-api-key", key.to_string()),
        ModelKind::Google | ModelKind::Vertex => ("x-goog-api-key", key.to_string()),
        ModelKind::AzureOpenai => ("api-key", key.to_string()),
        _ => ("Authorization", format!("Bearer {key}")),
    }
}

/// The token a bearer answer carries, for scrubbing from what comes back to a run.
pub fn cached_tokens(cache: &TokenCache) -> Vec<String> {
    cache
        .map
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .map(|(t, _, _)| t.clone())
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------------
// tokens

fn token_answer(status: u16, body: &[u8], now_ms: u64) -> Result<(String, u64), String> {
    if !(200..300).contains(&status) {
        return Err("the cloud account refused the saved credentials".into());
    }
    let v: Value = serde_json::from_slice(body)
        .map_err(|_| "the cloud account's token answer could not be read".to_string())?;
    let token = v["access_token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .ok_or("the cloud account's token answer had no token")?;
    let secs = v["expires_in"]
        .as_u64()
        .or_else(|| v["expires_in"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(300)
        .clamp(60, 3600);
    Ok((token.to_string(), now_ms + secs * 1000))
}

fn fetch_token(cred: &Cred, now_ms: u64, send: Send<'_>) -> Result<(String, u64), String> {
    let req = match cred {
        Cred::Entra {
            tenant_id,
            client_id,
            client_secret,
        } => HttpRequest::new(
            "POST",
            format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"),
            Guard::Public,
        )
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", ENTRA_SCOPE),
            ("grant_type", "client_credentials"),
        ]),
        Cred::Gcp {
            client_email,
            private_key,
            ..
        } => {
            let jwt = google_jwt(client_email, private_key, now_ms / 1000)?;
            HttpRequest::new("POST", GOOGLE_TOKEN_URL, Guard::Public).form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
        }
        _ => return Err("these credentials need no token".into()),
    };
    let (status, body) =
        send(&req).map_err(|_| "the cloud account could not be reached".to_string())?;
    token_answer(status, &body, now_ms)
}

fn b64url(data: &[u8]) -> String {
    crate::serve::auth::b64::encode_url(data)
}

/// RS256 over `header.claims`, with the service account's PKCS#8 key.
fn google_jwt(email: &str, pem: &str, iat: u64) -> Result<String, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    let der = crate::serve::auth::b64::decode_std(&body)
        .ok_or("the saved service-account key is not valid")?;
    let kp = ring::signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|_| "the saved service-account key is not valid".to_string())?;
    let head = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "iss": email, "scope": GOOGLE_SCOPE, "aud": GOOGLE_TOKEN_URL, "iat": iat, "exp": iat + 3600
    });
    let signing_input = format!("{head}.{}", b64url(claims.to_string().as_bytes()));
    let mut sig = vec![0u8; kp.public().modulus_len()];
    kp.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        signing_input.as_bytes(),
        &mut sig,
    )
    .map_err(|_| "the service-account key could not sign".to_string())?;
    Ok(format!("{signing_input}.{}", b64url(&sig)))
}

// ---------------------------------------------------------------------------------------------------------------------
// AWS Signature Version 4

pub struct AwsKeys<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub session_token: Option<&'a str>,
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg)
        .as_ref()
        .to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// AWS's URI encoding: everything but `A-Z a-z 0-9 - _ . ~` is `%XX` (and `/` stays unless asked).
fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b'/' if keep_slash => o.push('/'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                o.push(v);
                i += 3;
                continue;
            }
        }
        o.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&o).into_owned()
}

/// `20150830T123600Z` and `20150830` from Unix seconds.
fn amz_dates(unix: u64) -> (String, String) {
    let (days, rem) = (unix / 86400, unix % 86400);
    // civil-from-days (Howard Hinnant)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let date = format!("{y:04}{m:02}{d:02}");
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    (stamp, date)
}

/// `(host, path, query)` of an `https://` address.
fn split_url(url: &str) -> Result<(String, String, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("only https addresses are signed")?;
    let (host, tail) = rest.split_once('/').map_or((rest, ""), |(h, t)| (h, t));
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    Ok((host.to_string(), format!("/{path}"), query.to_string()))
}

/// The headers (`x-amz-date`, `x-amz-security-token`, `authorization`) that sign `req` for `service` in `region`. Every header
/// already on `req` (bar the transport's own) is signed along with `host`, so the caller sets `Content-Type`, `X-Amz-Target`
/// and the rest BEFORE calling this, and sends exactly what it signed.
pub fn sign_v4(
    req: &HttpRequest,
    keys: &AwsKeys<'_>,
    region: &str,
    service: &str,
    unix: u64,
) -> Result<Vec<(String, String)>, String> {
    let (host, path, query) = split_url(&req.url)?;
    let (stamp, date) = amz_dates(unix);
    // A path already percent-encoded once on the wire is encoded again for every service but S3.
    let canonical_uri = path
        .split('/')
        .map(|seg| uri_encode(seg, false))
        .collect::<Vec<_>>()
        .join("/");
    let mut q: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                uri_encode(&pct_decode(k), false),
                uri_encode(&pct_decode(v), false),
            )
        })
        .collect();
    q.sort();
    let canonical_query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut hdrs: Vec<(String, String)> = Vec::new();
    // Every header the request carries is signed (AWS refuses a request whose `Content-Type` or `x-amz-*` headers are not in
    // SignedHeaders), so a header added after signing breaks the signature instead of riding along. Only the ones the signer
    // owns, and the ones a transport sets for itself, are left out.
    for (k, v) in &req.headers {
        let k = k.to_ascii_lowercase();
        if matches!(
            k.as_str(),
            "host"
                | "x-amz-date"
                | "x-amz-security-token"
                | "authorization"
                | "user-agent"
                | "connection"
                | "content-length"
                | "expect"
                | "transfer-encoding"
                | "x-amzn-trace-id"
        ) {
            continue;
        }
        let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
        match hdrs.iter_mut().find(|(n, _)| *n == k) {
            // the transport (`ureq`'s `set`) sends one header per name, the last one given, so that is the one signed
            Some((_, old)) => *old = v,
            None => hdrs.push((k, v)),
        }
    }
    hdrs.push(("host".into(), host));
    hdrs.push(("x-amz-date".into(), stamp.clone()));
    let token = keys.session_token.map(|t| Zeroizing::new(t.to_string()));
    if let Some(t) = &token {
        hdrs.push(("x-amz-security-token".into(), t.to_string()));
    }
    hdrs.sort();
    let canonical_headers: Zeroizing<String> =
        Zeroizing::new(hdrs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect());
    let signed = hdrs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    for (k, v) in hdrs.iter_mut() {
        if k == "x-amz-security-token" {
            v.zeroize();
        }
    }
    let payload = hex(digest(&SHA256, req.body.as_deref().unwrap_or(&[])).as_ref());
    let canonical = Zeroizing::new(format!(
        "{}\n{canonical_uri}\n{canonical_query}\n{}\n{signed}\n{payload}",
        req.method,
        canonical_headers.as_str()
    ));
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(digest(&SHA256, canonical.as_bytes()).as_ref())
    );
    let seed = Zeroizing::new(format!("AWS4{}", keys.secret_access_key));
    let k = Zeroizing::new(hmac(seed.as_bytes(), date.as_bytes()));
    let k = Zeroizing::new(hmac(&k, region.as_bytes()));
    let k = Zeroizing::new(hmac(&k, service.as_bytes()));
    let k = Zeroizing::new(hmac(&k, b"aws4_request"));
    let sig = hex(&hmac(&k, to_sign.as_bytes()));
    let mut out = vec![("x-amz-date".to_string(), stamp)];
    if let Some(t) = &token {
        out.push(("x-amz-security-token".into(), t.to_string()));
    }
    out.push((
        "Authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
            keys.access_key_id
        ),
    ));
    Ok(out)
}

/// The path of a Vertex request with the account's own project in it. A run is given a placeholder project (the SDK wants
/// one in every path); the broker is what knows the real one.
pub fn vertex_project_path(path: &str, project: Option<&str>) -> String {
    let Some(project) = project else {
        return path.to_string();
    };
    let mut parts: Vec<&str> = path.split('/').collect();
    if let Some(i) = parts.iter().position(|s| *s == "projects") {
        if i + 1 < parts.len() {
            parts[i + 1] = project;
        }
    }
    parts.join("/")
}

/// The host a Vertex request goes to, from the location in its path (`/v1/projects/P/locations/L/...`): `global` (and
/// anything else) is the global endpoint, a valid region its own. Never a host taken from the run.
pub fn vertex_base(path: &str) -> String {
    let loc = path
        .split('/')
        .skip_while(|s| *s != "locations")
        .nth(1)
        .unwrap_or("global");
    let ok = !loc.is_empty()
        && loc.len() <= 24
        && loc != "global"
        && loc
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        format!("https://{loc}-aiplatform.googleapis.com")
    } else {
        "https://aiplatform.googleapis.com".to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn aws<'a>(token: Option<&'a str>) -> AwsKeys<'a> {
        AwsKeys {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: SECRET,
            session_token: token,
        }
    }

    #[test]
    fn sigv4_matches_the_published_get_vanilla_vector() {
        // AWS's Signature Version 4 test suite, "get-vanilla": 2015-08-30T12:36:00Z, us-east-1, service "service".
        let req = HttpRequest::new("GET", "https://example.amazonaws.com/", Guard::Public);
        let h = sign_v4(&req, &aws(None), "us-east-1", "service", 1_440_938_160).unwrap();
        let auth = &h.iter().find(|(k, _)| k == "Authorization").unwrap().1;
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert_eq!(
            h[0],
            ("x-amz-date".to_string(), "20150830T123600Z".to_string())
        );
    }

    /// The vector's expected `Authorization` for a `POST /` with `headers` and `body`, signed the way the suite signs.
    fn suite_auth(headers: &[(&str, &str)], body: &str) -> String {
        let mut req = HttpRequest::new("POST", "https://example.amazonaws.com/", Guard::Public);
        for (k, v) in headers {
            req = req.header(k, *v);
        }
        req.body = Some(body.as_bytes().to_vec());
        let h = sign_v4(&req, &aws(None), "us-east-1", "service", 1_440_938_160).unwrap();
        h.iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap()
            .1
            .clone()
    }

    #[test]
    fn sigv4_matches_the_published_post_x_www_form_urlencoded_vector() {
        // AWS's Signature Version 4 test suite, "post-x-www-form-urlencoded": a Content-Type header that must be signed.
        // (This failed before the signer covered the request's own headers: it signed host and x-amz-date only.)
        let auth = suite_auth(
            &[("Content-Type", "application/x-www-form-urlencoded")],
            "Param1=value1",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"
        );
    }

    #[test]
    fn the_headers_a_request_carries_are_all_signed_and_its_own_authorization_never_is() {
        let a = suite_auth(
            &[
                ("X-Amz-Target", "TrentService.Encrypt"),
                ("Content-Type", "application/x-amz-json-1.1"),
                ("Authorization", "run-supplied"),
                ("User-Agent", "x"),
                ("Content-Length", "3"),
            ],
            "{}",
        );
        assert!(
            a.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-target,"),
            "{a}"
        );
        // names are lowercased, values trimmed and inner runs of spaces collapsed, as AWS canonicalises them
        let loose = suite_auth(
            &[
                ("x-amz-target", "  TrentService.Encrypt "),
                ("CONTENT-TYPE", "application/x-amz-json-1.1"),
            ],
            "{}",
        );
        let tidy = suite_auth(
            &[
                ("X-Amz-Target", "TrentService.Encrypt"),
                ("Content-Type", "application/x-amz-json-1.1"),
            ],
            "{}",
        );
        assert_eq!(loose, tidy);
    }

    #[test]
    fn a_bedrock_request_is_signed_over_the_headers_it_is_sent_with() {
        // the broker copies the run's headers onto the upstream request, then authorises it: whatever is on the request when it
        // goes out must be what was signed (an independent verifier recomputes the signature from the request as sent)
        let mut req = HttpRequest::new(
            "POST",
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/m1/converse",
            Guard::Public,
        )
        .header("Content-Type", "application/json")
        .header("anthropic-version", "2023-06-01")
        // a repeated name: only the last is sent, so only the last is signed
        .header("Accept", "text/plain")
        .header("accept", "application/json");
        req.body = Some(br#"{"messages":[]}"#.to_vec());
        let cred = Cred::Aws {
            access_key_id: crate::aws_native::fakes::ACCESS_KEY.into(),
            secret_access_key: crate::aws_native::fakes::SECRET_KEY.into(),
            session_token: Some(crate::aws_native::fakes::SESSION_TOKEN.into()),
        };
        let ctx = Ctx {
            kind: ModelKind::Bedrock,
            provider_id: "br",
            region: Some("us-east-1"),
            now_ms: 1_440_938_160_000,
        };
        authorize(&mut req, &ctx, &cred, &TokenCache::default(), &|_| {
            Err("no".into())
        })
        .unwrap();
        let mut sent = req.headers.clone();
        // ureq sends one header per name, the last
        sent.retain(|(k, v)| !(k == "Accept" && v == "text/plain"));
        sent.push((
            "Host".into(),
            "bedrock-runtime.us-east-1.amazonaws.com".into(),
        ));
        let seen = crate::aws_native::fakes::Seen {
            method: "POST".into(),
            url: "/model/m1/converse".into(),
            headers: sent,
            body: String::from_utf8(req.body.clone().unwrap()).unwrap(),
        };
        let auth = seen.header("authorization").unwrap();
        assert!(
            auth.contains("SignedHeaders=accept;anthropic-version;content-type;host;x-amz-date;x-amz-security-token,"),
            "{auth}"
        );
        assert_eq!(
            crate::aws_native::fakes::verify_sigv4_with(
                &seen,
                "/model/m1/converse",
                &["content-type", "anthropic-version"]
            ),
            Ok(())
        );
    }

    #[test]
    fn a_colon_in_a_model_id_is_encoded_twice_in_the_canonical_request() {
        let req = HttpRequest::new(
            "POST",
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-v1%3A0/converse",
            Guard::Public,
        );
        // the canonical URI is not exposed, so check that the signature differs from the once-encoded form
        let twice = sign_v4(&req, &aws(None), "us-east-1", "bedrock", 1_440_938_160).unwrap();
        let mut once_req = req.clone();
        once_req.url = once_req.url.replace("%3A", ":");
        let once = sign_v4(&once_req, &aws(None), "us-east-1", "bedrock", 1_440_938_160).unwrap();
        assert_ne!(twice.last(), once.last());
        assert_eq!(uri_encode("v1%3A0", false), "v1%253A0");
    }

    #[test]
    fn a_session_token_is_signed_and_sent() {
        let req = HttpRequest::new("GET", "https://example.amazonaws.com/", Guard::Public);
        let h = sign_v4(
            &req,
            &aws(Some("TOKEN-SENTINEL-1234")),
            "us-east-1",
            "service",
            1_440_938_160,
        )
        .unwrap();
        assert!(h
            .iter()
            .any(|(k, v)| k == "x-amz-security-token" && v == "TOKEN-SENTINEL-1234"));
        let auth = &h.iter().find(|(k, _)| k == "Authorization").unwrap().1;
        assert!(auth.contains("SignedHeaders=host;x-amz-date;x-amz-security-token"));
        assert!(!auth.contains(SECRET));
    }

    #[test]
    fn dates_come_out_right() {
        assert_eq!(amz_dates(0).0, "19700101T000000Z");
        assert_eq!(amz_dates(1_440_938_160).1, "20150830");
        assert_eq!(amz_dates(1_709_164_800).1, "20240229");
    }

    fn token_fake(
        calls: &RefCell<Vec<String>>,
    ) -> impl Fn(&HttpRequest) -> Result<(u16, Vec<u8>), String> + '_ {
        move |r: &HttpRequest| {
            calls.borrow_mut().push(r.url.clone());
            Ok((
                200,
                br#"{"access_token":"tok-SENTINEL-abcdef","expires_in":3599}"#.to_vec(),
            ))
        }
    }

    #[test]
    fn an_entra_credential_becomes_a_cached_bearer_token() {
        let cred = parse(
            ModelKind::AzureOpenai,
            r#"{"tenant_id":"contoso.onmicrosoft.com","client_id":"1234-abcd","client_secret":"SECRET-SENTINEL-xyz"}"#,
        )
        .unwrap();
        let calls = RefCell::new(Vec::new());
        let cache = TokenCache::default();
        let ctx = Ctx {
            kind: ModelKind::AzureOpenai,
            provider_id: "az",
            region: None,
            now_ms: 1_000_000,
        };
        let send = token_fake(&calls);
        let mut r = HttpRequest::new("POST", "https://res.openai.azure.com/x", Guard::Public);
        authorize(&mut r, &ctx, &cred, &cache, &send).unwrap();
        assert!(r
            .headers
            .contains(&("Authorization".into(), "Bearer tok-SENTINEL-abcdef".into())));
        // the second request reuses the token
        let mut r2 = HttpRequest::new("POST", "https://res.openai.azure.com/x", Guard::Public);
        authorize(&mut r2, &ctx, &cred, &cache, &send).unwrap();
        assert_eq!(calls.borrow().len(), 1);
        assert_eq!(
            calls.borrow()[0],
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
        );
        // after it nearly expires it is fetched again
        let later = Ctx {
            now_ms: 1_000_000 + 3_550_000,
            ..ctx
        };
        let mut r3 = HttpRequest::new("POST", "https://res.openai.azure.com/x", Guard::Public);
        authorize(&mut r3, &later, &cred, &cache, &send).unwrap();
        assert_eq!(calls.borrow().len(), 2);
        // the credential is never in what a request prints
        assert!(!format!("{r:?}{cred:?}").contains("SECRET-SENTINEL"));
    }

    #[test]
    fn a_refused_exchange_adds_nothing_and_says_so_plainly() {
        let cred = parse(
            ModelKind::AzureOpenai,
            r#"{"tenant_id":"t","client_id":"c","client_secret":"SECRET-SENTINEL-xyz"}"#,
        )
        .unwrap();
        let cache = TokenCache::default();
        let ctx = Ctx {
            kind: ModelKind::AzureOpenai,
            provider_id: "az",
            region: None,
            now_ms: 5,
        };
        let send = |_: &HttpRequest| Ok((401, br#"{"error":"bad SECRET-SENTINEL-xyz"}"#.to_vec()));
        let mut r = HttpRequest::new("POST", "https://x.openai.azure.com/", Guard::Public);
        let e = authorize(&mut r, &ctx, &cred, &cache, &send).unwrap_err();
        assert!(r.headers.is_empty());
        assert!(!e.contains("SENTINEL"), "{e}");
    }

    #[test]
    fn plain_tokens_keep_their_own_header() {
        for (kind, name) in [
            (ModelKind::Bedrock, "Authorization"),
            (ModelKind::AzureOpenai, "api-key"),
            (ModelKind::Vertex, "x-goog-api-key"),
        ] {
            let cred = parse(kind, "plain-token-123456").unwrap();
            assert!(!cred.structured());
            let mut r = HttpRequest::new("POST", "https://x/", Guard::Public);
            let cache = TokenCache::default();
            let ctx = Ctx {
                kind,
                provider_id: "p",
                region: Some("us-east-1"),
                now_ms: 0,
            };
            authorize(&mut r, &ctx, &cred, &cache, &|_| Err("no".into())).unwrap();
            assert_eq!(r.headers[0].0, name);
        }
    }

    #[test]
    fn bad_credentials_are_refused_without_echoing_them() {
        let e = parse(
            ModelKind::Bedrock,
            r#"{"access_key_id":"AKIA","secret_access_key":""}"#,
        )
        .unwrap_err();
        assert!(e.contains("missing a field"));
        assert!(parse(
            ModelKind::AzureOpenai,
            r#"{"tenant_id":"a/b","client_id":"c","client_secret":"s"}"#
        )
        .is_err());
        assert!(parse(ModelKind::Bedrock, "{not json").is_err());
    }

    #[test]
    fn a_vertex_host_comes_only_from_a_valid_location() {
        assert_eq!(
            vertex_base(
                "/v1/projects/p/locations/us-east5/publishers/anthropic/models/m:rawPredict"
            ),
            "https://us-east5-aiplatform.googleapis.com"
        );
        assert_eq!(
            vertex_base("/v1/projects/p/locations/global/publishers/x"),
            "https://aiplatform.googleapis.com"
        );
        assert_eq!(
            vertex_base("/v1/projects/p/locations/evil.example.com/x"),
            "https://aiplatform.googleapis.com"
        );
        assert_eq!(
            vertex_base("/v1/models"),
            "https://aiplatform.googleapis.com"
        );
    }

    #[test]
    fn the_secrets_of_a_credential_are_each_listed_for_scrubbing() {
        let c = parse(
            ModelKind::Bedrock,
            r#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"SK-SENTINEL-1","session_token":"ST-SENTINEL-2"}"#,
        )
        .unwrap();
        assert_eq!(c.secrets(), vec!["SK-SENTINEL-1", "ST-SENTINEL-2"]);
    }
}
