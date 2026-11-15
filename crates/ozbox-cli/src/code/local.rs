//! The IDE or desktop on `http://localhost:<free port>` of this computer.
//!
//! A listener on `127.0.0.1` accepts the browser's connections and hands each one to the box through the dialer (the
//! SSH forward over the provider's own route, nothing opened on the box). Dialing again for every connection is what makes
//! a dropped forward (Session Manager does that now and then) cost nothing: the next connection builds a new one. A
//! second thread dials every few seconds even when nobody is using it, so the forward is rebuilt before the browser needs
//! it, and says so when the state changes.
//!
//! The service's own sign-in stays on. To get the person past it without a password in a URL or a command line, the
//! first request for `/__ozbox/go/<one-time nonce>` is answered by this program itself, once: a page that signs in
//! (code-server) or a redirect that carries KasmVNC's login. Any later request for it is refused.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::serve::agent::Conn;

pub type Dialer = Arc<dyn Fn() -> Result<Conn, String> + Send + Sync>;

/// How the person gets past the service's own sign-in.
#[derive(Clone)]
pub enum Login {
    /// code-server: a form posted to `/login`.
    Form { password: String },
    /// KasmVNC: HTTP basic credentials.
    Basic { user: String, password: String },
}

/// The current one-time sign-in path and whether it was used.
type Go = Arc<std::sync::Mutex<(String, bool)>>;

pub struct Local {
    pub addr: SocketAddr,
    go: Go,
    stop: Arc<AtomicBool>,
}

impl Local {
    /// `http://localhost:<port>` and the one-time sign-in address on it.
    pub fn base_url(&self) -> String {
        format!("http://localhost:{}", self.addr.port())
    }

    /// The current one-time sign-in address.
    pub fn go_url(&self) -> String {
        format!("{}{}", self.base_url(), self.go_path())
    }

    pub fn go_path(&self) -> String {
        self.go.lock().map(|g| g.0.clone()).unwrap_or_default()
    }

    /// A new one-time sign-in address (the old one stops working). The connection itself stays open, so a tab already
    /// signed in keeps working.
    pub fn issue_go(&self, nonce: &str) -> String {
        if let Ok(mut g) = self.go.lock() {
            *g = (format!("/__ozbox/go/{nonce}"), false);
        }
        self.go_url()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // wake the accept loop
        let _ = TcpStream::connect(self.addr);
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct Options {
    /// `None` picks a free port.
    pub port: Option<u16>,
    pub nonce: String,
    pub warm_every: Option<Duration>,
    /// Told when the forward goes down (`false`) and comes back (`true`).
    pub on_state: Arc<dyn Fn(bool) + Send + Sync>,
}

pub fn start(dial: Dialer, login: Login, o: Options) -> std::io::Result<Local> {
    let listener = TcpListener::bind(("127.0.0.1", o.port.unwrap_or(0)))?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let go: Go = Arc::new(std::sync::Mutex::new((
        format!("/__ozbox/go/{}", o.nonce),
        false,
    )));
    {
        let (dial, stop, go, login) =
            (Arc::clone(&dial), Arc::clone(&stop), Arc::clone(&go), login);
        std::thread::spawn(move || {
            for s in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(s) = s else { continue };
                let (dial, go, login) = (Arc::clone(&dial), Arc::clone(&go), login.clone());
                std::thread::spawn(move || handle(s, &dial, &go, &login, addr.port()));
            }
        });
    }
    if let Some(every) = o.warm_every {
        let (dial, stop, on) = (
            Arc::clone(&dial),
            Arc::clone(&stop),
            Arc::clone(&o.on_state),
        );
        std::thread::spawn(move || {
            let mut up: Option<bool> = None;
            while !stop.load(Ordering::SeqCst) {
                let now = dial().is_ok();
                if up != Some(now) {
                    up = Some(now);
                    on(now);
                }
                let until = Instant::now() + every;
                while Instant::now() < until && !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        });
    }
    Ok(Local { addr, go, stop })
}

/// The request head without consuming it, once it is complete (or a second has passed).
fn peek_head(s: &TcpStream) -> Vec<u8> {
    let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buf = vec![0u8; 4096];
    let start = Instant::now();
    let mut got = 0;
    while start.elapsed() < Duration::from_secs(1) {
        match s.peek(&mut buf) {
            Ok(n) => {
                got = n;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
                    break;
                }
                // not complete yet: only wait if more could still come
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let _ = s.set_read_timeout(None);
    buf.truncate(got);
    buf
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn respond(s: &mut TcpStream, status: &str, extra: &[(&str, String)], body: &str) {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    let _ = s.write_all(out.as_bytes());
    let _ = s.shutdown(Shutdown::Both);
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn handle(mut s: TcpStream, dial: &Dialer, go: &Go, login: &Login, port: u16) {
    let raw = peek_head(&s);
    let head = String::from_utf8_lossy(&raw).into_owned();
    let first = head.lines().next().unwrap_or("");
    let is_go = first
        .strip_prefix("GET ")
        .and_then(|r| r.split(' ').next())
        .is_some_and(|p| p.starts_with("/__ozbox/go/"));
    if !is_go {
        return pipe(s, dial);
    }
    // Only this address may ask: a page on another site (or a rebinding name) cannot.
    let host_ok = header(&head, "host")
        .is_some_and(|h| h == format!("localhost:{port}") || h == format!("127.0.0.1:{port}"));
    let path = first.split(' ').nth(1).unwrap_or("");
    if !host_ok {
        return respond(&mut s, "403 Forbidden", &[], "not available");
    }
    // A wrong path is refused without saying whether a sign-in address exists.
    let already = {
        let Ok(mut g) = go.lock() else { return };
        if path != g.0 {
            None
        } else {
            let was = g.1;
            g.1 = true;
            Some(was)
        }
    };
    let Some(already) = already else {
        return respond(&mut s, "403 Forbidden", &[], "not available");
    };
    if already {
        return respond(
            &mut s,
            "410 Gone",
            &[],
            "This sign-in address was already used. Run the command again for a new one.",
        );
    }
    match login {
        Login::Basic { user, password } => respond(
            &mut s,
            "302 Found",
            &[(
                "Location",
                format!("http://{user}:{password}@localhost:{port}/"),
            )],
            "",
        ),
        Login::Form { password } => {
            let (page, csp) = form_login_page(password);
            respond(
                &mut s,
                "200 OK",
                &[
                    ("Content-Type", "text/html; charset=utf-8".into()),
                    ("Content-Security-Policy", csp),
                ],
                &page,
            );
        }
    }
}

/// The page that signs in to code-server by posting its login form, and the policy that lets only its own script run.
/// The password is in the page and nowhere else: not in a URL, a header or a log.
pub fn form_login_page(password: &str) -> (String, String) {
    let mut n = [0u8; 12];
    let _ = getrandom::getrandom(&mut n);
    let nonce: String = n.iter().map(|b| format!("{b:02x}")).collect();
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Signing in</title></head><body>\
         <form id=\"f\" method=\"post\" action=\"/login\"><input type=\"hidden\" name=\"password\" value=\"{}\">\
         <noscript><button type=\"submit\">Continue</button></noscript></form>\
         <script nonce=\"{nonce}\">document.getElementById('f').submit();</script></body></html>",
        html_escape(password)
    );
    (
        page,
        format!("default-src 'none'; script-src 'nonce-{nonce}'; form-action 'self'"),
    )
}

fn pipe(client: TcpStream, dial: &Dialer) {
    let Ok(conn) = dial() else {
        let mut c = client;
        return respond(
            &mut c,
            "502 Bad Gateway",
            &[("Content-Type", "text/plain".into())],
            "The box could not be reached just now. Reload in a moment; the connection is being rebuilt.",
        );
    };
    let Conn {
        read: mut up_read,
        write: mut up_write,
        keep,
    } = conn;
    let Ok(mut c_read) = client.try_clone() else {
        return;
    };
    let mut c_write = client;
    let a = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c_read, &mut up_write);
        let _ = up_write.flush();
    });
    let mut buf = [0u8; 16 * 1024];
    loop {
        match up_read.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if c_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = c_write.shutdown(Shutdown::Both);
    let _ = a.join();
    drop(keep);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    fn echo_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = Arc::clone(&n);
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                n2.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    let mut r = s.try_clone().unwrap();
                    let mut w = s;
                    let mut b = [0u8; 1024];
                    while let Ok(n) = r.read(&mut b) {
                        if n == 0 || w.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (addr, n)
    }

    fn dialer(addr: SocketAddr, fail: Arc<AtomicBool>) -> Dialer {
        Arc::new(move || {
            if fail.load(Ordering::SeqCst) {
                return Err("down".into());
            }
            Conn::from_tcp(TcpStream::connect(addr).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())
        })
    }

    fn opts(nonce: &str) -> Options {
        Options {
            port: None,
            nonce: nonce.into(),
            warm_every: None,
            on_state: Arc::new(|_| {}),
        }
    }

    fn get(addr: SocketAddr, path: &str, host: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(800)))
            .unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn a_connection_is_piped_to_the_box_both_ways_on_loopback_only() {
        let (up, _) = echo_upstream();
        let l = start(
            dialer(up, Arc::new(AtomicBool::new(false))),
            Login::Form {
                password: "p".repeat(32),
            },
            opts("n1"),
        )
        .unwrap();
        assert!(l.addr.ip().is_loopback());
        let mut s = TcpStream::connect(l.addr).unwrap();
        s.write_all(b"hello box").unwrap();
        let mut b = [0u8; 9];
        s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hello box");
    }

    #[test]
    fn the_sign_in_address_works_once_for_the_right_host_and_never_reaches_the_box() {
        let (up, seen) = echo_upstream();
        let pw = "abcdef0123456789abcdef0123456789".to_string();
        let l = start(
            dialer(up, Arc::new(AtomicBool::new(false))),
            Login::Form {
                password: pw.clone(),
            },
            opts("nonce1"),
        )
        .unwrap();
        let host = format!("localhost:{}", l.addr.port());
        // a page elsewhere, or a rebinding name, gets nothing
        assert!(get(l.addr, &l.go_path(), "evil.example.com").starts_with("HTTP/1.1 403"));
        assert!(get(l.addr, "/__ozbox/go/wrong", &host).starts_with("HTTP/1.1 403"));
        let first = get(l.addr, &l.go_path(), &host);
        assert!(first.starts_with("HTTP/1.1 200"), "{first}");
        assert!(first.contains("name=\"password\"") && first.contains(&pw));
        assert!(first.contains("Content-Security-Policy"));
        let second = get(l.addr, &l.go_path(), &host);
        assert!(second.starts_with("HTTP/1.1 410"), "{second}");
        assert!(!second.contains(&pw));
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "nothing was sent to the box"
        );
        // an ordinary request does not carry the password
        let other = get(l.addr, "/", &host);
        assert!(!other.contains(&pw));
    }

    #[test]
    fn the_desktop_gets_a_one_time_redirect_that_carries_its_login() {
        let (up, _) = echo_upstream();
        let l = start(
            dialer(up, Arc::new(AtomicBool::new(false))),
            Login::Basic {
                user: "ozbox".into(),
                password: "pw0123456789abcdef".into(),
            },
            opts("nonce2"),
        )
        .unwrap();
        let host = format!("127.0.0.1:{}", l.addr.port());
        let r = get(l.addr, &l.go_path(), &host);
        assert!(r.starts_with("HTTP/1.1 302"), "{r}");
        assert!(r.contains(&format!(
            "Location: http://ozbox:pw0123456789abcdef@localhost:{}/",
            l.addr.port()
        )));
        assert!(
            r.contains("Cache-Control: no-store") && r.contains("Referrer-Policy: no-referrer")
        );
        assert!(get(l.addr, &l.go_path(), &host).starts_with("HTTP/1.1 410"));
    }

    #[test]
    fn a_box_that_cannot_be_reached_answers_the_browser_instead_of_hanging() {
        let (up, _) = echo_upstream();
        let l = start(
            dialer(up, Arc::new(AtomicBool::new(true))),
            Login::Form {
                password: "p".repeat(32),
            },
            opts("n3"),
        )
        .unwrap();
        let r = get(l.addr, "/", &format!("localhost:{}", l.addr.port()));
        assert!(r.starts_with("HTTP/1.1 502"), "{r}");
    }

    #[test]
    fn a_dropped_forward_is_noticed_and_rebuilt_without_anyone_asking() {
        let (up, _) = echo_upstream();
        let fail = Arc::new(AtomicBool::new(false));
        let log: Arc<Mutex<Vec<bool>>> = Arc::default();
        let l2 = Arc::clone(&log);
        let l = start(
            dialer(up, Arc::clone(&fail)),
            Login::Form {
                password: "p".repeat(32),
            },
            Options {
                warm_every: Some(Duration::from_millis(30)),
                on_state: Arc::new(move |up| l2.lock().unwrap().push(up)),
                ..opts("n4")
            },
        )
        .unwrap();
        let wait = |want: usize| {
            for _ in 0..200 {
                if log.lock().unwrap().len() >= want {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        wait(1);
        fail.store(true, Ordering::SeqCst);
        wait(2);
        fail.store(false, Ordering::SeqCst);
        wait(3);
        assert_eq!(*log.lock().unwrap(), vec![true, false, true]);
        drop(l);
    }
}
