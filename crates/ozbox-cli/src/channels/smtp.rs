//! A small SMTP sender. It exists instead of a general mail crate for two reasons the rules of this project care about:
//! the connection is made to an address that has been checked (the same public-address rule as every other outbound
//! request, see `netguard`), and encryption is never optional: either the connection starts encrypted (port 465) or it
//! is upgraded with STARTTLS before a password or a message is sent, and a server that does not offer the upgrade is
//! refused. The server's certificate is verified against the public root certificates, for the host name given.
//!
//! The message body is sent base64-encoded, which keeps it safe from line-length and dot-stuffing surprises and keeps
//! every header free of the text of an alert.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{b64_std, one_line, SendResult};
use crate::netguard::{address_allowed, Guard};
use crate::notify_config::SmtpSecurity;

const MAX_LINE: usize = 2048;
const MAX_REPLY_LINES: usize = 64;
/// The whole delivery (name lookup aside) - connecting, encrypting, signing in and sending - gets this long, however the
/// server paces its answers. A per-read timeout alone lets a server that trickles one byte at a time hold the sender for
/// minutes.
pub const TOTAL: Duration = Duration::from_secs(10);
const REFUSED: &str = "that address resolves to a private or reserved network and is refused";

/// Everything one delivery needs.
pub struct Plan<'a> {
    pub security: SmtpSecurity,
    /// What this computer calls itself in EHLO.
    pub helo: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub from: &'a str,
    pub to: &'a [String],
    /// The whole message, headers and body, with CRLF line ends.
    pub message: &'a str,
}

struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn has(&self, word: &str) -> bool {
        self.lines.iter().any(|l| {
            let u = l.to_ascii_uppercase();
            u == word || u.starts_with(&format!("{word} ")) || u.starts_with(&format!("{word}="))
        })
    }
}

fn read_reply<S: Read>(s: &mut S) -> Result<Reply, String> {
    let mut lines = Vec::new();
    loop {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match s.read(&mut b) {
                Ok(0) => return Err("the mail server closed the connection".into()),
                Ok(_) => {}
                Err(_) => return Err("the mail server was too slow to answer (try again)".into()),
            }
            if b[0] == b'\n' {
                break;
            }
            if b[0] != b'\r' {
                line.push(b[0]);
            }
            if line.len() > MAX_LINE {
                return Err("the mail server sent an answer that is too long".into());
            }
        }
        let text = String::from_utf8_lossy(&line).to_string();
        let (Some(code), Some(sep)) = (text.get(..3), text.as_bytes().get(3).copied()) else {
            return Err("the mail server sent an answer that could not be read".into());
        };
        let Ok(code) = code.parse::<u16>() else {
            return Err("the mail server sent an answer that could not be read".into());
        };
        lines.push(text.get(4..).unwrap_or("").to_string());
        if sep == b' ' {
            return Ok(Reply { code, lines });
        }
        if sep != b'-' || lines.len() > MAX_REPLY_LINES {
            return Err("the mail server sent an answer that could not be read".into());
        }
    }
}

fn say<S: Read + Write>(s: &mut S, line: &str) -> Result<(), String> {
    s.write_all(line.as_bytes())
        .and_then(|()| s.write_all(b"\r\n"))
        .and_then(|()| s.flush())
        .map_err(|_| "the mail server closed the connection (try again)".to_string())
}

fn expect<S: Read + Write>(
    s: &mut S,
    line: Option<&str>,
    ok: &[u16],
    what: &str,
) -> Result<Reply, String> {
    if let Some(l) = line {
        say(s, l)?;
    }
    let r = read_reply(s)?;
    if ok.contains(&r.code) {
        Ok(r)
    } else if (400..500).contains(&r.code) {
        Err(format!(
            "the mail server could not take the message just now ({what}) (try again)"
        ))
    } else {
        Err(format!("the mail server refused {what}"))
    }
}

/// Run the whole conversation. `upgrade` turns the plain stream into an encrypted one after STARTTLS.
pub fn deliver<S: Read + Write>(
    mut s: S,
    plan: &Plan<'_>,
    upgrade: impl FnOnce(S) -> Result<S, String>,
) -> SendResult {
    expect(&mut s, None, &[220], "the connection")?;
    let ehlo = format!("EHLO {}", plan.helo);
    let mut caps = expect(&mut s, Some(&ehlo), &[250], "the greeting")?;
    let mut s = match plan.security {
        SmtpSecurity::Tls => s,
        SmtpSecurity::Starttls => {
            if !caps.has("STARTTLS") {
                return Err("the mail server does not offer STARTTLS, so nothing was sent".into());
            }
            expect(
                &mut s,
                Some("STARTTLS"),
                &[220],
                "the switch to an encrypted connection",
            )?;
            let mut up = upgrade(s)?;
            caps = expect(&mut up, Some(&ehlo), &[250], "the greeting")?;
            up
        }
    };
    if !plan.username.is_empty() {
        if caps.has("AUTH")
            && caps
                .lines
                .iter()
                .any(|l| l.to_ascii_uppercase().contains("PLAIN"))
        {
            let blob = b64_std(format!("\0{}\0{}", plan.username, plan.password).as_bytes());
            expect(
                &mut s,
                Some(&format!("AUTH PLAIN {blob}")),
                &[235],
                "the user name or password",
            )?;
        } else if caps.has("AUTH") {
            expect(&mut s, Some("AUTH LOGIN"), &[334], "the sign-in")?;
            expect(
                &mut s,
                Some(&b64_std(plan.username.as_bytes())),
                &[334],
                "the user name",
            )?;
            expect(
                &mut s,
                Some(&b64_std(plan.password.as_bytes())),
                &[235],
                "the user name or password",
            )?;
        } else {
            return Err("the mail server offers no sign-in, but a user name is set".into());
        }
    }
    expect(
        &mut s,
        Some(&format!("MAIL FROM:<{}>", plan.from)),
        &[250],
        "the sender",
    )?;
    for r in plan.to {
        expect(
            &mut s,
            Some(&format!("RCPT TO:<{r}>")),
            &[250, 251],
            "a recipient",
        )?;
    }
    expect(&mut s, Some("DATA"), &[354], "the message")?;
    s.write_all(plan.message.as_bytes())
        .and_then(|()| s.write_all(b"\r\n.\r\n"))
        .and_then(|()| s.flush())
        .map_err(|_| "the mail server closed the connection (try again)".to_string())?;
    expect(&mut s, None, &[250], "the message")?;
    // The message is accepted; a failure to say goodbye changes nothing.
    let _ = say(&mut s, "QUIT");
    Ok("sent".into())
}

// ---------- the message ----------

fn rfc2047(s: &str) -> String {
    let s = one_line(s);
    if s.is_ascii() {
        s
    } else {
        format!("=?UTF-8?B?{}?=", b64_std(s.as_bytes()))
    }
}

fn wrap76(b64: &str) -> String {
    b64.as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// `Mon, 02 Jan 2006 15:04:05 +0000` for a Unix time.
pub fn rfc5322_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[(days.rem_euclid(7)) as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub struct Message<'a> {
    pub from: &'a str,
    pub reply_to: &'a str,
    pub to: &'a [String],
    pub subject: &'a str,
    pub text: &'a str,
    pub now_secs: u64,
    pub id_seed: &'a str,
    pub domain: &'a str,
}

pub fn build_message(m: &Message<'_>) -> String {
    let mut h = vec![
        format!("From: <{}>", m.from),
        format!(
            "To: {}",
            m.to.iter()
                .map(|t| format!("<{t}>"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("Subject: {}", rfc2047(m.subject)),
        format!("Date: {}", rfc5322_date(m.now_secs)),
        format!("Message-ID: <{}@{}>", m.id_seed, m.domain),
        "Auto-Submitted: auto-generated".to_string(),
        "MIME-Version: 1.0".to_string(),
        "Content-Type: text/plain; charset=utf-8".to_string(),
        "Content-Transfer-Encoding: base64".to_string(),
    ];
    if !m.reply_to.is_empty() {
        h.insert(1, format!("Reply-To: <{}>", m.reply_to));
    }
    format!(
        "{}\r\n\r\n{}",
        h.join("\r\n"),
        wrap76(&b64_std(m.text.as_bytes()))
    )
}

// ---------- the real connection ----------

/// A connection that stops working when the delivery's deadline passes: before every read and write the socket's
/// timeout is set to the time that is left, so the deadline covers the whole conversation, not each read.
#[derive(Debug)]
pub struct Deadlined {
    tcp: TcpStream,
    deadline: Instant,
}

impl Deadlined {
    pub fn new(tcp: TcpStream, deadline: Instant) -> Self {
        Self { tcp, deadline }
    }

    fn left(&self) -> std::io::Result<Duration> {
        let d = self.deadline.saturating_duration_since(Instant::now());
        if d.is_zero() {
            Err(std::io::ErrorKind::TimedOut.into())
        } else {
            Ok(d)
        }
    }
}

impl Read for Deadlined {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.left()?))?;
        self.tcp.read(b)
    }
}

impl Write for Deadlined {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.left()?))?;
        self.tcp.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}

/// Resolve once and refuse unless every address is a public one; then connect to the first that answers, within the
/// delivery's deadline.
pub fn connect_guarded(host: &str, port: u16, deadline: Instant) -> Result<Deadlined, String> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| "the mail server's name could not be found (try again)".to_string())?
        .collect();
    if addrs.is_empty()
        || addrs
            .iter()
            .any(|a| !address_allowed(Guard::Public, a.ip()))
    {
        return Err(REFUSED.into());
    }
    for a in &addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        if let Ok(s) = TcpStream::connect_timeout(a, left.min(Duration::from_secs(8))) {
            return Ok(Deadlined::new(s, deadline));
        }
    }
    Err("the mail server did not answer (try again)".into())
}

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, Deadlined>;

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "the secure connection could not be set up".to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn wrap_tls(host: &str, tcp: Deadlined) -> Result<TlsStream, String> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "the mail server's name is not valid".to_string())?;
    let conn = rustls::ClientConnection::new(tls_config()?, name)
        .map_err(|_| "the secure connection could not be set up".to_string())?;
    Ok(rustls::StreamOwned::new(conn, tcp))
}

/// A stream that is plain until STARTTLS, then encrypted.
enum Conn {
    Plain(Deadlined),
    Tls(Box<TlsStream>),
}

impl Read for Conn {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(b),
            Conn::Tls(s) => s.read(b),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(b),
            Conn::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// Connect, encrypt and deliver, all within [`TOTAL`]. Errors never carry the host, the user name or the password.
pub fn send_over_network(host: &str, port: u16, plan: &Plan<'_>) -> SendResult {
    let deadline = Instant::now() + TOTAL;
    let tcp = connect_guarded(host, port, deadline)?;
    send_over_connection(host, tcp, plan)
}

/// The rest of [`send_over_network`], on a connection that is already open (a test can hand it a local one).
pub fn send_over_connection(host: &str, tcp: Deadlined, plan: &Plan<'_>) -> SendResult {
    let first = match plan.security {
        SmtpSecurity::Tls => Conn::Tls(Box::new(wrap_tls(host, tcp)?)),
        SmtpSecurity::Starttls => Conn::Plain(tcp),
    };
    deliver(first, plan, |c| match c {
        Conn::Plain(t) => Ok(Conn::Tls(Box::new(wrap_tls(host, t)?))),
        already @ Conn::Tls(_) => Ok(already),
    })
    .map_err(|e| {
        if e.contains("certificate") {
            "the mail server's certificate could not be verified".to_string()
        } else {
            e
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A scripted server: reads what the client writes into `sent`, answers from `script`.
    struct Wire {
        input: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl Read for Wire {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Wire {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn wire(script: &str) -> Wire {
        Wire {
            input: Cursor::new(script.replace('\n', "\r\n").into_bytes()),
            sent: Vec::new(),
        }
    }

    fn plan<'a>(security: SmtpSecurity, to: &'a [String], message: &'a str) -> Plan<'a> {
        Plan {
            security,
            helo: "ozbox.example.com",
            username: "alerts",
            password: "SENTINELPASSWORD",
            from: "alerts@example.com",
            to,
            message,
        }
    }

    #[test]
    fn implicit_tls_session_authenticates_and_sends() {
        let w = wire("220 hi\n250-smtp.example.com\n250-AUTH PLAIN LOGIN\n250 8BITMIME\n235 ok\n250 ok\n250 ok\n354 go\n250 queued\n221 bye\n");
        let to = ["me@example.com".to_string()];
        let r = deliver(
            w,
            &plan(SmtpSecurity::Tls, &to, "Subject: x\r\n\r\nbody"),
            Ok,
        );
        assert_eq!(r, Ok("sent".to_string()));
    }

    #[test]
    fn the_conversation_is_in_the_right_order() {
        let mut w = wire("220 hi\n250-smtp.example.com\n250 AUTH PLAIN\n235 ok\n250 ok\n250 ok\n250 ok\n354 go\n250 queued\n");
        let to = ["me@example.com".to_string(), "you@example.com".to_string()];
        // Run against a stream we can inspect afterwards.
        struct Share<'a>(&'a mut Wire);
        impl Read for Share<'_> {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(b)
            }
        }
        impl Write for Share<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        deliver(
            Share(&mut w),
            &plan(SmtpSecurity::Tls, &to, "Subject: x\r\n\r\nbody"),
            Ok,
        )
        .unwrap();
        let sent = String::from_utf8(w.sent).unwrap();
        let order: Vec<&str> = sent.split("\r\n").collect();
        assert_eq!(order[0], "EHLO ozbox.example.com");
        assert!(order[1].starts_with("AUTH PLAIN "));
        assert_eq!(order[2], "MAIL FROM:<alerts@example.com>");
        assert_eq!(order[3], "RCPT TO:<me@example.com>");
        assert_eq!(order[4], "RCPT TO:<you@example.com>");
        assert_eq!(order[5], "DATA");
        assert!(sent.contains("Subject: x\r\n\r\nbody\r\n.\r\n"));
    }

    #[test]
    fn starttls_is_required_and_the_password_is_never_sent_before_it() {
        // A server that does not offer STARTTLS: nothing is sent, and no password.
        let w = wire("220 hi\n250 smtp.example.com\n");
        let to = ["me@example.com".to_string()];
        let e = deliver(w, &plan(SmtpSecurity::Starttls, &to, "m"), Ok).unwrap_err();
        assert!(e.contains("STARTTLS"));
        // With STARTTLS the upgrade is called before AUTH, and EHLO is repeated after it.
        let w = wire("220 hi\n250-smtp.example.com\n250 STARTTLS\n220 ready\n250-smtp.example.com\n250 AUTH PLAIN\n235 ok\n250 ok\n250 ok\n354 go\n250 queued\n");
        let mut upgraded = false;
        let r = deliver(w, &plan(SmtpSecurity::Starttls, &to, "m"), |s| {
            upgraded = true;
            Ok(s)
        });
        assert!(r.is_ok() && upgraded);
    }

    #[test]
    fn refusals_are_explained_and_a_temporary_failure_is_retried() {
        let to = ["me@example.com".to_string()];
        let w = wire("220 hi\n250 AUTH PLAIN\n535 nope\n");
        let e = deliver(w, &plan(SmtpSecurity::Tls, &to, "m"), Ok).unwrap_err();
        assert!(
            e.contains("user name or password") && !e.contains("SENTINEL") && !e.contains("535")
        );
        assert!(!crate::channels::retryable(&e));
        let w = wire("220 hi\n250 AUTH PLAIN\n235 ok\n250 ok\n451 try later\n");
        let e = deliver(w, &plan(SmtpSecurity::Tls, &to, "m"), Ok).unwrap_err();
        assert!(crate::channels::retryable(&e));
        let w = wire("554 no service\n");
        assert!(deliver(w, &plan(SmtpSecurity::Tls, &to, "m"), Ok).is_err());
    }

    #[test]
    fn the_message_has_clean_headers_and_an_encoded_body() {
        let to = ["me@example.com".to_string()];
        let m = build_message(&Message {
            from: "alerts@example.com",
            reply_to: "help@example.com",
            to: &to,
            subject: "[Oz Box] Disk\r\nBcc: evil@example.com",
            text: "line one\n.\nline \u{e9}",
            now_secs: 1_136_214_245,
            id_seed: "abc123",
            domain: "ozbox.example.com",
        });
        assert!(m.contains("Subject: [Oz Box] Disk Bcc: evil@example.com\r\n"));
        assert!(!m.contains("\r\nBcc:"));
        assert!(m.contains("Date: Mon, 02 Jan 2006 15:04:05 +0000\r\n"));
        assert!(m.contains("Reply-To: <help@example.com>\r\n"));
        assert!(m.contains("Content-Transfer-Encoding: base64\r\n\r\n"));
        assert!(!m.contains("line one"));
        let uni = build_message(&Message {
            from: "a@example.com",
            reply_to: "",
            to: &to,
            subject: "\u{e9}",
            text: "x",
            now_secs: 0,
            id_seed: "i",
            domain: "d.example",
        });
        assert!(uni.contains("Subject: =?UTF-8?B?w6k=?="));
    }

    #[test]
    fn the_date_is_right_across_leap_years() {
        assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(rfc5322_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 +0000");
        assert_eq!(
            rfc5322_date(1_794_182_400),
            "Mon, 09 Nov 2026 00:00:00 +0000"
        );
    }

    #[test]
    fn private_and_loopback_mail_servers_are_refused_before_any_connection() {
        for h in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "169.254.169.254",
            "localhost",
            "::1",
        ] {
            assert_eq!(
                connect_guarded(h, 587, Instant::now() + TOTAL).unwrap_err(),
                REFUSED,
                "{h}"
            );
        }
    }

    #[test]
    fn a_server_that_trickles_bytes_is_cut_off_at_the_deadline_and_the_failure_is_retried() {
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            // One byte every 100 ms, never a line end: every single read succeeds in time.
            for _ in 0..100 {
                if c.write_all(b"2").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let tcp = TcpStream::connect(addr).unwrap();
        let to = vec!["a@example.com".to_string()];
        let p = plan(SmtpSecurity::Starttls, &to, "x");
        let started = Instant::now();
        let r = send_over_connection(
            "mail.example.com",
            Deadlined::new(tcp, Instant::now() + Duration::from_millis(600)),
            &p,
        );
        let took = started.elapsed();
        let e = r.unwrap_err();
        assert_eq!(e, "the mail server was too slow to answer (try again)");
        assert!(crate::channels::retryable(&e));
        assert!(took < Duration::from_secs(3), "took {took:?}");
        drop(t);
    }
}
