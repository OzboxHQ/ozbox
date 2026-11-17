//! `ozbox secrets native-check`: a real round trip through the SHIPPED program's own key-service and parameter-store clients,
//! against loopback stand-ins it starts and stops itself (ADR 0029 Amendment 18).
//!
//! The image has no `aws` command, so a box's secrets store on the fleet's KMS key and a box's own secrets in Parameter Store
//! are reached only by this program's native client (Amendments 13 and 14). The image workflow used to show the shipped program
//! has that client by looking for a few strings in it. This runs it instead: the same `KmsProvider` the store uses wraps and
//! unwraps a random key, and the same `AwsSsm` the loader uses reads two pages of parameters, each request signed with SigV4
//! by credentials the stand-in metadata service hands out, and each signature recomputed by the stand-in from the bytes that
//! arrived, by its own canonicalisation. The workflow runs it with an empty PATH, so a program that started a command fails.
//!
//! What it cannot reach: anything but `127.0.0.1`. The stand-ins listen there, on ports the kernel picks; the client it builds
//! accepts plain http to `127.0.0.1` only, and no client the store or the loader builds does. The credentials are random
//! words made for this run, never a real key, and no real AWS address is called.

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tiny_http::{Header, Response, Server};
use zeroize::Zeroizing;

use crate::box_secrets::Backend;
use crate::secrets_enc::KeyProvider;

/// What the round trip did, for a person and for `--json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub kms_requests: usize,
    pub ssm_requests: usize,
    pub parameters: usize,
}

fn random_word(n: usize) -> Result<String, String> {
    let mut raw = vec![0u8; n];
    getrandom::getrandom(&mut raw).map_err(|_| "no random numbers are available".to_string())?;
    Ok(raw.iter().map(|b| format!("{:02x}", b)).collect())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, msg).as_ref().to_vec()
}

struct Arrived {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Arrived {
    fn of(r: &mut tiny_http::Request) -> Self {
        let mut body = String::new();
        let _ = std::io::Read::read_to_string(
            &mut std::io::Read::take(r.as_reader(), 256 * 1024),
            &mut body,
        );
        Arrived {
            method: r.method().to_string(),
            url: r.url().to_string(),
            headers: r
                .headers()
                .iter()
                .map(|h| (h.field.as_str().to_string(), h.value.as_str().to_string()))
                .collect(),
            body,
        }
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// What AWS does with a request: rebuild the canonical request from what arrived (the headers in `SignedHeaders`, the body as
/// received), derive the signing key from the secret and compare. Shares no code with the program's signer, so a signer that
/// signs the wrong bytes cannot agree with itself here.
fn verify(a: &Arrived, access: &str, secret: &str) -> Result<(), &'static str> {
    let auth = a.header("authorization").ok_or("no Authorization")?;
    let rest = auth.strip_prefix("AWS4-HMAC-SHA256 ").ok_or("not SigV4")?;
    let field = |name: &str| {
        rest.split(", ")
            .find_map(|p| p.strip_prefix(name))
            .map(str::to_string)
    };
    let cred = field("Credential=").ok_or("no Credential")?;
    let signed = field("SignedHeaders=").ok_or("no SignedHeaders")?;
    let sig = field("Signature=").ok_or("no Signature")?;
    let (akid, scope) = cred.split_once('/').ok_or("bad Credential")?;
    if akid != access {
        return Err("wrong access key");
    }
    let names: Vec<&str> = signed.split(';').collect();
    for need in [
        "content-type",
        "x-amz-target",
        "host",
        "x-amz-date",
        "x-amz-security-token",
    ] {
        if !names.contains(&need) {
            return Err("a required header is not signed");
        }
    }
    let mut canonical_headers = String::new();
    for n in &names {
        let v = a.header(n).ok_or("a signed header was not sent")?;
        canonical_headers.push_str(&format!("{n}:{}\n", v.trim()));
    }
    let payload = hex(ring::digest::digest(&ring::digest::SHA256, a.body.as_bytes()).as_ref());
    let canonical = format!(
        "{}\n/\n\n{canonical_headers}\n{signed}\n{payload}",
        a.method
    );
    let stamp = a.header("x-amz-date").ok_or("no x-amz-date")?;
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes()).as_ref())
    );
    let mut parts = scope.split('/');
    let mut key = hmac(
        format!("AWS4{secret}").as_bytes(),
        parts.next().unwrap_or("").as_bytes(),
    );
    for p in parts {
        key = hmac(&key, p.as_bytes());
    }
    if hex(&hmac(&key, to_sign.as_bytes())) == sig {
        Ok(())
    } else {
        Err("the signature does not match")
    }
}

fn text(s: &str, code: u16) -> Response<Cursor<Vec<u8>>> {
    Response::from_string(s).with_status_code(code)
}

fn aws_json(code: u16, v: &Value) -> Response<Cursor<Vec<u8>>> {
    let r = Response::from_string(v.to_string()).with_status_code(code);
    match Header::from_bytes("Content-Type", "application/x-amz-json-1.1") {
        Ok(h) => r.with_header(h),
        Err(_) => r,
    }
}

/// A running stand-in, stopped when dropped.
struct StandIn {
    server: Arc<Server>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn start(
    handle: impl Fn(&mut tiny_http::Request) -> Response<Cursor<Vec<u8>>> + Send + 'static,
) -> Result<(String, StandIn), String> {
    let server = Arc::new(
        Server::http("127.0.0.1:0")
            .map_err(|_| "a loopback stand-in could not listen".to_string())?,
    );
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or("a loopback stand-in has no address")?;
    let s = server.clone();
    let thread = std::thread::spawn(move || {
        for mut r in s.incoming_requests() {
            let resp = handle(&mut r);
            let _ = r.respond(resp);
        }
    });
    Ok((
        format!("http://{addr}"),
        StandIn {
            server,
            thread: Some(thread),
        },
    ))
}

/// Run the round trip. `Ok` only when every request arrived signed and the answers were read back to what was sent.
pub fn run() -> Result<Checked, String> {
    let access = format!("AKIA{}", random_word(8)?.to_ascii_uppercase());
    let secret = Zeroizing::new(random_word(20)?);
    let session = Zeroizing::new(random_word(16)?);
    let imds_token = random_word(16)?;
    let refused: Arc<Mutex<Vec<&'static str>>> = Arc::default();
    let kms_seen = Arc::new(Mutex::new(0usize));
    let ssm_seen = Arc::new(Mutex::new(0usize));

    // the metadata service: a token first (IMDSv2), then the role and its credentials
    let creds = json!({
        "Code": "Success", "AccessKeyId": access, "SecretAccessKey": secret.as_str(),
        "Token": session.as_str(), "Expiration": "2099-01-01T00:00:00Z"
    })
    .to_string();
    let tok = imds_token.clone();
    let (imds, _imds) = start(move |r| {
        let a = Arrived::of(r);
        let ok = a.header("x-aws-ec2-metadata-token") == Some(tok.as_str());
        match (a.method.as_str(), a.url.as_str()) {
            ("PUT", "/latest/api/token") => text(&tok, 200),
            _ if !ok => text("unauthorized", 401),
            ("GET", "/latest/meta-data/iam/security-credentials/") => {
                text("ozbox-self-check\n", 200)
            }
            ("GET", "/latest/meta-data/iam/security-credentials/ozbox-self-check") => {
                text(&creds, 200)
            }
            ("GET", "/latest/meta-data/placement/region") => text("us-east-1", 200),
            _ => text("no", 404),
        }
    })?;

    // the key service and the parameter store, on one stand-in, told apart by X-Amz-Target
    let (acc, sec) = (access.clone(), Zeroizing::new(secret.to_string()));
    let (rf, ks, ss) = (refused.clone(), kms_seen.clone(), ssm_seen.clone());
    let (svc, _svc) = start(move |r| {
        let a = Arrived::of(r);
        if let Err(why) = verify(&a, &acc, &sec) {
            if let Ok(mut v) = rf.lock() {
                v.push(why);
            }
            return aws_json(403, &json!({"__type": "InvalidSignatureException"}));
        }
        let body: Value = serde_json::from_str(&a.body).unwrap_or(Value::Null);
        match a.header("x-amz-target") {
            Some("TrentService.Encrypt") => {
                if let Ok(mut n) = ks.lock() {
                    *n += 1;
                }
                let pt = body["Plaintext"].as_str().unwrap_or("");
                let ctx = body["EncryptionContext"].to_string();
                let blob = crate::serve::auth::b64::encode_std(format!("CT|{ctx}|{pt}").as_bytes());
                aws_json(200, &json!({"CiphertextBlob": blob}))
            }
            Some("TrentService.Decrypt") => {
                if let Ok(mut n) = ks.lock() {
                    *n += 1;
                }
                let blob = body["CiphertextBlob"].as_str().unwrap_or("");
                let raw = crate::serve::auth::b64::decode_std(blob).unwrap_or_default();
                let raw = String::from_utf8(raw).unwrap_or_default();
                let ctx = body["EncryptionContext"].to_string();
                match raw.strip_prefix(&format!("CT|{ctx}|")) {
                    Some(pt) => aws_json(200, &json!({"Plaintext": pt})),
                    // a different encryption context is refused, as KMS refuses it
                    None => aws_json(400, &json!({"__type": "InvalidCiphertextException"})),
                }
            }
            Some("AmazonSSM.GetParametersByPath") => {
                if let Ok(mut n) = ss.lock() {
                    *n += 1;
                }
                // two pages, so the client's NextToken loop is part of the trip
                if body["NextToken"].is_null() {
                    aws_json(
                        200,
                        &json!({"Parameters": [{"Name": "/ozbox/self-check/role/A", "Value": "one"}], "NextToken": "page-2"}),
                    )
                } else {
                    aws_json(
                        200,
                        &json!({"Parameters": [{"Name": "/ozbox/self-check/role/B", "Value": "two"}]}),
                    )
                }
            }
            _ => aws_json(400, &json!({"__type": "UnknownOperationException"})),
        }
    })?;

    // the store's own key provider: wrap a random key and read it back
    let kms = crate::secrets_enc::KmsProvider::build(
        crate::aws_native::AwsJson::for_loopback(&imds),
        "alias/ozbox-self-check",
        Some("us-east-1"),
        Some(&svc),
    )
    .map_err(|e| e.0)?;
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(key.as_mut())
        .map_err(|_| "no random numbers are available".to_string())?;
    let aad = b"ozbox-store\0self-check\0box\0native-check";
    let wrapped = kms
        .wrap(&key, aad)
        .map_err(|e| format!("the key service round trip failed: {}", e.0))?;
    let back = kms
        .unwrap(&wrapped, aad)
        .map_err(|e| format!("the key service round trip failed: {}", e.0))?;
    if back.as_slice() != key.as_slice() {
        return Err("the key service round trip gave back a different key".into());
    }
    // the loader's own parameter-store client: every page
    let ssm = crate::box_secrets::AwsSsm::build(
        crate::aws_native::AwsJson::for_loopback(&imds),
        "us-east-1",
        Some(&svc),
    );
    let params = ssm
        .fetch("/ozbox/self-check/role")
        .map_err(|e| format!("the parameter store round trip failed: {e}"))?;
    if params.len() != 2 {
        return Err("the parameter store round trip did not read every page".into());
    }
    let bad = refused.lock().map(|v| v.len()).unwrap_or(1);
    if bad > 0 {
        return Err("a request arrived without a valid signature".into());
    }
    let kms_requests = kms_seen.lock().map(|n| *n).unwrap_or(0);
    let ssm_requests = ssm_seen.lock().map(|n| *n).unwrap_or(0);
    if kms_requests != 2 || ssm_requests != 2 {
        return Err("the round trip did not reach the stand-ins as expected".into());
    }
    Ok(Checked {
        kms_requests,
        ssm_requests,
        parameters: params.len(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_programs_own_clients_make_a_signed_round_trip_against_the_stand_ins() {
        let c = run().unwrap();
        assert_eq!(
            c,
            Checked {
                kms_requests: 2,
                ssm_requests: 2,
                parameters: 2
            }
        );
    }

    /// The loopback allowance is the self-check's client's alone: the client the store and the loader build refuses plain http,
    /// even to 127.0.0.1, without sending anything.
    #[test]
    fn only_a_loopback_client_speaks_plain_http_and_only_to_127_0_0_1() {
        let (base, _s) = start(|_| text("should not be reached", 200)).unwrap();
        let real = crate::aws_native::AwsJson::new();
        assert!(real
            .call(
                &base,
                "us-east-1",
                "kms",
                "TrentService.Encrypt",
                Zeroizing::new(b"{}".to_vec())
            )
            .is_err());
        let lo = crate::aws_native::AwsJson::for_loopback("http://127.0.0.1:1");
        assert!(lo
            .call(
                "http://example.com",
                "us-east-1",
                "kms",
                "TrentService.Encrypt",
                Zeroizing::new(b"{}".to_vec())
            )
            .is_err());
    }

    #[test]
    fn a_signature_that_does_not_match_is_refused_by_the_stand_in() {
        let a = Arrived {
            method: "POST".into(),
            url: "/".into(),
            headers: vec![(
                "authorization".into(),
                "AWS4-HMAC-SHA256 Credential=AKIAX/20260101/us-east-1/kms/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=00".into(),
            )],
            body: String::new(),
        };
        assert!(verify(&a, "AKIAX", "s").is_err());
        assert!(verify(&a, "AKIAY", "s").is_err());
    }
}
