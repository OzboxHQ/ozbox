//! The actions, over the DevTools protocol. One [`Driver`] owns one Chromium and its tabs.
//!
//! Pages are read by scripts that return plain data; every judgement about that data is in `detect`, `mask` and `schema`.
//! What reaches the model is only what `snapshot` renders: structure and text with secrets and sensitive patterns masked.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::cdp::{self, Cdp, HookOut, LaunchOpts, Setup};
use crate::detect::{self, Assessment, Page, Risk, Target};
use crate::gatekeep::{self, Block, GateState, ReqFacts};
use crate::mask;
use crate::policy::{self, BrowserPolicy, Device, Download};
use crate::protocol::{Action, Start};
use crate::record;
use crate::robots::{self, RateLimiter, Robots};
use crate::schema;

#[derive(Debug, Clone)]
pub struct DErr {
    pub code: &'static str,
    pub msg: String,
}

impl From<String> for DErr {
    fn from(msg: String) -> Self {
        Self {
            code: "failed",
            msg,
        }
    }
}

fn bad(code: &'static str, msg: impl Into<String>) -> DErr {
    DErr {
        code,
        msg: msg.into(),
    }
}

type R<T> = Result<T, DErr>;

// ---- the scripts the page runs -----------------------------------------------------------------------------------------

const FACTS_JS: &str = r#"(function(){
 var i=0;
 var forms=[].map.call(document.forms,function(f){
  return {action:f.action||'',method:f.method||'get',fields:[].map.call(f.elements,function(el){
   if(!el.name&&!el.id)return null;
   var k=el.tagName==='SELECT'?'select':el.tagName==='TEXTAREA'?'textarea':(el.type||'text');
   var ac=el.getAttribute('autocomplete')||'';
   var o={idx:i++,name:el.name||el.id,type:k,autocomplete:ac,
    label:(el.labels&&el.labels[0]?el.labels[0].innerText:'')||el.getAttribute('aria-label')||'',
    secret_mark:el.hasAttribute('data-secret'),value:''};
   el.setAttribute('data-ozi',String(o.idx));
   if(k!=='password'&&k!=='file'&&!/^cc-|one-time-code/.test(ac))o.value=String(el.value||'').slice(0,300);
   return o;}).filter(Boolean)};});
 var frames=[].map.call(document.querySelectorAll('iframe'),function(f){return f.src||''});
 var markers=[].map.call(document.querySelectorAll('.g-recaptcha,.h-captcha,.cf-turnstile,[data-sitekey],[id*=captcha],[class*=captcha]'),
  function(e){return (e.id||'')+' '+(typeof e.className==='string'?e.className:'')}).slice(0,20);
 return {url:location.href,title:document.title,text:(document.body?document.body.innerText:'').toLowerCase().slice(0,4000),
  frames:frames,markers:markers,forms:forms};
})()"#;

const TARGET_JS: &str = r#"(function(ref){
 var e=document.querySelector('[data-ozref="'+ref+'"]');if(!e)return null;
 var f=e.form||e.closest('form');var idx=f?[].indexOf.call(document.forms,f):-1;
 var tag=e.tagName.toLowerCase();var type=(e.getAttribute('type')||'').toLowerCase();
 var sub=(tag==='button'&&(type===''||type==='submit')&&!!f)||(tag==='input'&&(type==='submit'||type==='image'));
 return {tag:tag,type:sub?'submit':type,text:String(e.innerText||e.value||e.getAttribute('aria-label')||'').slice(0,100),
  name:e.name||e.id||'',href:tag==='a'?(e.href||''):'',form:idx>=0?idx:null,secret:false};
})"#;

const ACTIVE_JS: &str = r#"(function(){
 var e=document.activeElement;if(!e||e===document.body)return null;
 var f=e.form||e.closest('form');var idx=f?[].indexOf.call(document.forms,f):-1;
 var tag=e.tagName.toLowerCase();var type=(e.getAttribute('type')||'').toLowerCase();
 return {tag:tag,type:type,text:'',name:e.name||e.id||'',href:tag==='iframe'?(e.src||''):'',form:idx>=0?idx:null,secret:false,
  textarea:tag==='textarea'};
})()"#;

const POINT_JS: &str = r#"(function(ref){
 var e=document.querySelector('[data-ozref="'+ref+'"]');if(!e)return {error:'there is no element '+ref+' on the page now: take a new snapshot'};
 if(e.disabled)return {error:'that element is disabled'};
 e.scrollIntoView({block:'center',inline:'center'});
 var r=e.getBoundingClientRect();if(!r.width&&!r.height)return {error:'that element is not visible'};
 return {x:r.left+r.width/2,y:r.top+r.height/2};
})"#;

const FOCUS_JS: &str = r#"(function(ref,clear){
 var e=document.querySelector('[data-ozref="'+ref+'"]');if(!e)return 'there is no element '+ref+' on the page now: take a new snapshot';
 if(e.disabled||e.readOnly)return 'that field cannot be typed into';
 e.scrollIntoView({block:'center'});e.focus();
 if(clear){if(e.select)e.select();else if(e.isContentEditable){document.execCommand('selectAll');}}
 return '';
})"#;

const SELECT_JS: &str = r#"(function(ref,val){
 var e=document.querySelector('[data-ozref="'+ref+'"]');if(!e||e.tagName!=='SELECT')return 'that is not a drop-down list';
 var o=[].find.call(e.options,function(o){return o.value===val||o.text.trim()===val});
 if(!o)return 'that list has no option "'+val.slice(0,40)+'"';
 e.value=o.value;e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return '';
})"#;

const SCROLL_JS: &str = r#"(function(ref,dy){
 if(ref){var e=document.querySelector('[data-ozref="'+ref+'"]');if(!e)return false;e.scrollIntoView({block:'center'});return true;}
 window.scrollBy(0,dy);return true;
})"#;

const WAIT_JS: &str = r#"(function(text,sel){
 if(text&&!(document.body&&document.body.innerText.indexOf(text)>=0))return false;
 if(sel&&!document.querySelector(sel))return false;return true;
})"#;

const FILE_JS: &str = r#"(function(ref){var e=document.querySelector('[data-ozref="'+ref+'"]');return e&&e.tagName==='INPUT'&&e.type==='file'?e:null;})"#;

const SNAPSHOT_JS: &str = r#"(function(){
 document.querySelectorAll('[data-ozref]').forEach(function(e){e.removeAttribute('data-ozref')});
 var n=0,out=[],INTER='a[href],button,input,select,textarea,summary,[role=button],[role=link],[role=checkbox],[role=tab],[role=menuitem],[onclick],[contenteditable=true]';
 function vis(e){if(!e.getClientRects().length)return false;var s=getComputedStyle(e);return s.visibility!=='hidden'&&s.display!=='none';}
 function nm(e){return String((e.labels&&e.labels[0]?e.labels[0].innerText:'')||e.getAttribute('aria-label')||e.innerText||e.placeholder||e.title||e.alt||e.value||'').replace(/\s+/g,' ').trim().slice(0,120);}
 function walk(e){
  if(out.length>700)return;
  if(e.nodeType===3){var t=e.textContent.replace(/\s+/g,' ').trim();if(t)out.push({k:'t',text:t.slice(0,300)});return;}
  if(e.nodeType!==1)return;
  var tag=e.tagName.toLowerCase();
  if(['script','style','noscript','template','svg','head'].indexOf(tag)>=0)return;
  if(!vis(e)&&tag!=='option')return;
  if(/^h[1-6]$/.test(tag)){out.push({k:'h',level:+tag[1],text:nm(e)});return;}
  if(e.matches&&e.matches(INTER)){
   var ref='e'+(++n);e.setAttribute('data-ozref',ref);
   var type=(e.getAttribute('type')||'').toLowerCase();
   var it={k:'el',ref:ref,tag:tag,type:type,name:nm(e),field:e.name||e.id||'',ac:e.getAttribute('autocomplete')||'',
    mark:e.hasAttribute('data-secret'),href:tag==='a'?(e.getAttribute('href')||''):'',disabled:!!e.disabled,checked:!!e.checked};
   if(tag==='select'){it.value=e.selectedOptions&&e.selectedOptions[0]?e.selectedOptions[0].text:'';it.options=[].map.call(e.options,function(o){return o.text.trim()}).slice(0,30);}
   else if(['input','textarea'].indexOf(tag)>=0&&type!=='password'&&type!=='file'&&!/^cc-|one-time-code/.test(it.ac)&&['checkbox','radio','submit','button'].indexOf(type)<0)it.value=String(e.value||'').slice(0,200);
   out.push(it);return;}
  if(tag==='iframe'){out.push({k:'t',text:'[frame '+(e.getAttribute('src')||'').slice(0,100)+']'});return;}
  e.childNodes.forEach(walk);
 }
 if(document.body)walk(document.body);
 return {url:location.href,title:document.title,items:out,more:out.length>700};
})()"#;

const EXTRACT_JS: &str = r#"(function(plan){
 function text(e,attr){var v=attr?e.getAttribute(attr):(e.innerText!==undefined?e.innerText:e.textContent);return String(v===null||v===undefined?'':v).trim();}
 function run(p,root){
  if(p.type==='object'){var o={};for(var k in (p.properties||{})){var sub=p.properties[k];
    if(sub['x-selector']||sub.type==='object'||sub.type==='array'){var r=run(sub,root);if(r!==undefined)o[k]=r;}}return o;}
  if(p.type==='array'){var it=p.items||{};var sel=p['x-selector'];if(!sel)return [];
    var els=[].slice.call(root.querySelectorAll(sel)).slice(0,200);
    if(it.type==='object'){return els.map(function(el){return run(it,el)});}
    return els.map(function(el){return text(el,it['x-attr']||p['x-attr'])});}
  var s=p['x-selector'];if(!s)return undefined;var el=root.querySelector(s);if(!el)return null;return text(el,p['x-attr']);
 }
 return run(plan,document);
})"#;

const BLUR_ID: &str = "ozbox-mask";

// ---- keys ---------------------------------------------------------------------------------------------------------------

/// A key name such as `Enter`, `a` or `Control+a`, as the events that press and release it.
pub fn key_events(key: &str) -> Result<Vec<Value>, String> {
    let parts: Vec<&str> = key.split('+').collect();
    let (mods, base) = parts.split_at(parts.len() - 1);
    let mut m = 0u32;
    for p in mods {
        m |= match p.to_ascii_lowercase().as_str() {
            "alt" | "option" => 1,
            "control" | "ctrl" => 2,
            "meta" | "cmd" | "command" => 4,
            "shift" => 8,
            _ => return Err(format!("{p} is not a modifier key")),
        };
    }
    let base = base[0];
    let (name, code, vk, text): (String, String, u32, Option<String>) = match base {
        "Enter" => ("Enter".into(), "Enter".into(), 13, Some("\r".into())),
        "Tab" => ("Tab".into(), "Tab".into(), 9, None),
        "Escape" | "Esc" => ("Escape".into(), "Escape".into(), 27, None),
        "Backspace" => ("Backspace".into(), "Backspace".into(), 8, None),
        "Delete" => ("Delete".into(), "Delete".into(), 46, None),
        "ArrowUp" => ("ArrowUp".into(), "ArrowUp".into(), 38, None),
        "ArrowDown" => ("ArrowDown".into(), "ArrowDown".into(), 40, None),
        "ArrowLeft" => ("ArrowLeft".into(), "ArrowLeft".into(), 37, None),
        "ArrowRight" => ("ArrowRight".into(), "ArrowRight".into(), 39, None),
        "Home" => ("Home".into(), "Home".into(), 36, None),
        "End" => ("End".into(), "End".into(), 35, None),
        "PageUp" => ("PageUp".into(), "PageUp".into(), 33, None),
        "PageDown" => ("PageDown".into(), "PageDown".into(), 34, None),
        "Space" | " " => (" ".into(), "Space".into(), 32, Some(" ".into())),
        c if c.chars().count() == 1 => {
            let ch = c.chars().next().unwrap_or(' ');
            let up = ch.to_ascii_uppercase();
            (
                c.to_string(),
                format!("Key{up}"),
                u32::from(up),
                Some(c.to_string()),
            )
        }
        other => return Err(format!("{other} is not a key name Oz Box knows")),
    };
    let typed = if m & (1 | 2 | 4) == 0 {
        text.clone()
    } else {
        None
    };
    let mut down = json!({ "type": if typed.is_some() { "keyDown" } else { "rawKeyDown" }, "modifiers": m, "key": name, "code": code, "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk });
    if let Some(t) = &typed {
        down["text"] = json!(t);
    }
    let up = json!({ "type": "keyUp", "modifiers": m, "key": name, "code": code, "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk });
    Ok(vec![down, up])
}

// ---- the snapshot, as text ------------------------------------------------------------------------------------------

/// Render what the snapshot script found as the text a model reads. Secrets and sensitive patterns are masked here, in
/// one place, so a recording, a result and a snapshot can never disagree about what was hidden.
pub fn render_snapshot(raw: &Value) -> String {
    let url = raw["url"].as_str().unwrap_or("");
    let mut out = format!(
        "Page: {} ({})\n",
        mask::mask_text(raw["title"].as_str().unwrap_or("")),
        crate::record::page_of(url)
    );
    let s = |v: &Value, k: &str| v[k].as_str().unwrap_or("").to_string();
    for it in raw["items"].as_array().into_iter().flatten() {
        match it["k"].as_str() {
            Some("h") => {
                let n = it["level"].as_u64().unwrap_or(1).clamp(1, 6) as usize;
                out.push_str(&format!(
                    "{} {}\n",
                    "#".repeat(n),
                    mask::mask_text(&s(it, "text"))
                ));
            }
            Some("t") => {
                out.push_str(&mask::mask_text(&s(it, "text")));
                out.push('\n');
            }
            Some("el") => {
                let tag = s(it, "tag");
                let ty = s(it, "type");
                let secret = mask::is_secret_field(
                    &ty,
                    &s(it, "field"),
                    &s(it, "ac"),
                    it["mark"].as_bool().unwrap_or(false),
                );
                let role = match (tag.as_str(), ty.as_str()) {
                    ("a", _) => "link",
                    ("button", _) | ("input", "submit" | "button" | "image") => "button",
                    ("input", "checkbox") => "checkbox",
                    ("input", "radio") => "radio",
                    ("input", "file") => "file-input",
                    ("input", "password") => "password",
                    ("select", _) => "select",
                    ("textarea", _) => "textbox",
                    ("input", _) => "textbox",
                    _ => "control",
                };
                let mut line = format!(
                    "[{} {} \"{}\"",
                    s(it, "ref"),
                    role,
                    mask::mask_text(&s(it, "name"))
                );
                if tag == "a" {
                    let h = s(it, "href");
                    if !h.is_empty() {
                        line.push_str(&format!(
                            " -> {}",
                            mask::mask_text(&h.chars().take(150).collect::<String>())
                        ));
                    }
                }
                if let Some(v) = it["value"].as_str() {
                    let shown = mask::show_value(secret, v);
                    if !shown.is_empty() {
                        line.push_str(&format!(" value=\"{shown}\""));
                    }
                } else if secret {
                    line.push_str(&format!(" value=\"{}\"", mask::MASKED));
                }
                if let Some(o) = it["options"].as_array() {
                    let names: Vec<String> = o
                        .iter()
                        .filter_map(|x| x.as_str().map(mask::mask_text))
                        .collect();
                    line.push_str(&format!(" options=[{}]", names.join(" | ")));
                }
                if it["checked"].as_bool() == Some(true) {
                    line.push_str(" checked");
                }
                if it["disabled"].as_bool() == Some(true) {
                    line.push_str(" disabled");
                }
                line.push_str("]\n");
                out.push_str(&line);
            }
            _ => {}
        }
    }
    if raw["more"].as_bool() == Some(true) {
        out.push_str("[the page is longer than this snapshot: scroll and take another]\n");
    }
    out
}

// ---- the driver ----------------------------------------------------------------------------------------------------------

/// A DevTools session the worker knows: a tab, a frame from another site (in its own process), or a worker.
#[derive(Debug, Clone)]
enum SessKind {
    Page {
        target: String,
    },
    Frame {
        parent: Option<String>,
    },
    Worker {
        parent: Option<String>,
        host: String,
    },
}

/// What the hook on the browser's messages shares with the driver. The hook answers paused requests and sets up new tabs and
/// frames the moment they appear, so nothing a page asks for waits on the driver or slips past it.
#[derive(Default)]
struct Shared {
    st: GateState,
    sessions: HashMap<String, SessKind>,
    /// The host each tab shows now, as the browser committed it (never a request header).
    tops: HashMap<String, String>,
    blocked: Vec<(String, &'static str)>,
    /// Origins a page went on to whose robots.txt has not been read yet.
    robots_wanted: Vec<String>,
    /// Tabs that appeared: (target, session, opened by a page).
    new_pages: Vec<(String, String, bool)>,
    /// The worker's own tabs for reading robots.txt: never shown as tabs, and they may read nothing else.
    robots_targets: HashSet<String>,
    /// A dialog a page opened while a person holds the session, waiting for them.
    dialog: Option<Value>,
    ua: String,
    metrics: Option<crate::policy::Metrics>,
}

fn lock_shared(sh: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    sh.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether a session (a frame or worker) sits inside a tab's session.
fn within(g: &Shared, session: &str, tab: &str) -> bool {
    let mut at = Some(session.to_string());
    for _ in 0..8 {
        let Some(s) = at.clone() else { return false };
        if s == tab {
            return true;
        }
        at = match g.sessions.get(&s) {
            Some(SessKind::Frame { parent }) | Some(SessKind::Worker { parent, .. }) => {
                parent.clone()
            }
            _ => None,
        };
    }
    false
}

/// The page's own site for a session: a tab's committed host, or for a frame or a worker, its tab's.
fn top_of(g: &Shared, session: Option<&str>) -> (bool, String, Option<String>) {
    let mut at = session.map(String::from);
    for _ in 0..8 {
        let Some(s) = at.clone() else { break };
        match g.sessions.get(&s) {
            Some(SessKind::Page { target }) => {
                return (
                    true,
                    g.tops.get(&s).cloned().unwrap_or_default(),
                    Some(target.clone()),
                )
            }
            Some(SessKind::Frame { parent }) => at.clone_from(parent),
            Some(SessKind::Worker { parent, host }) => match parent {
                Some(p) => at = Some(p.clone()),
                None => return (false, host.clone(), None),
            },
            None => break,
        }
    }
    (false, String::new(), None)
}

fn origin_of(url: &str) -> String {
    let scheme = url.split("://").next().unwrap_or("https");
    let auth = url
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    format!("{scheme}://{}", auth.rsplit('@').next().unwrap_or(auth))
}

/// The hook: every message from the browser passes here first, on the thread that reads them.
fn on_wire(sh: &Mutex<Shared>, ev: &Value) -> HookOut {
    let m = ev["method"].as_str().unwrap_or("");
    let parent = ev["sessionId"].as_str().map(String::from);
    let p = &ev["params"];
    let mut g = lock_shared(sh);
    match m {
        "Target.attachedToTarget" => {
            let sess = p["sessionId"].as_str().unwrap_or("").to_string();
            let info = &p["targetInfo"];
            let target = info["targetId"].as_str().unwrap_or("").to_string();
            let url = info["url"].as_str().unwrap_or("");
            let s = Some(sess.clone());
            let auto =
                json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true });
            let fetch = json!({ "patterns": [{ "urlPattern": "*", "requestStage": "Request" }] });
            let ua = json!({ "userAgent": g.ua });
            let mut send: Vec<(Option<String>, String, Value)> = Vec::new();
            match info["type"].as_str().unwrap_or("") {
                "page" => {
                    g.sessions.insert(
                        sess.clone(),
                        SessKind::Page {
                            target: target.clone(),
                        },
                    );
                    g.tops.insert(sess.clone(), detect::host_of(url));
                    for c in ["Page.enable", "Runtime.enable", "DOM.enable"] {
                        send.push((s.clone(), c.into(), json!({})));
                    }
                    if let Some(mt) = g.metrics {
                        send.push((
                            s.clone(),
                            "Emulation.setDeviceMetricsOverride".into(),
                            json!({ "width": mt.width, "height": mt.height, "deviceScaleFactor": mt.scale, "mobile": mt.mobile }),
                        ));
                        if mt.mobile {
                            send.push((
                                s.clone(),
                                "Emulation.setTouchEmulationEnabled".into(),
                                json!({ "enabled": true }),
                            ));
                        }
                    }
                    send.push((s.clone(), "Network.setUserAgentOverride".into(), ua));
                    send.push((s.clone(), "Fetch.enable".into(), fetch));
                    send.push((s.clone(), "Target.setAutoAttach".into(), auto));
                    let opener = info["openerId"].as_str().is_some_and(|o| !o.is_empty());
                    g.new_pages.push((target, sess.clone(), opener));
                }
                "iframe" => {
                    g.sessions.insert(
                        sess.clone(),
                        SessKind::Frame {
                            parent: parent.clone(),
                        },
                    );
                    send.push((s.clone(), "Network.setUserAgentOverride".into(), ua));
                    send.push((s.clone(), "Fetch.enable".into(), fetch));
                    send.push((s.clone(), "Target.setAutoAttach".into(), auto));
                }
                "worker" | "shared_worker" | "service_worker" => {
                    g.sessions.insert(
                        sess.clone(),
                        SessKind::Worker {
                            parent: parent.clone(),
                            host: detect::host_of(url),
                        },
                    );
                    send.push((s.clone(), "Fetch.enable".into(), fetch));
                }
                _ => {}
            }
            // nothing in it has run yet: it starts only once the browser has done all of the above, so every request it
            // makes is judged; a target whose setup the browser refused is never let run
            HookOut {
                send,
                keep: false,
                setup: true,
                release: Some((sess, "Runtime.runIfWaitingForDebugger".into(), json!({}))),
            }
        }
        "Target.detachedFromTarget" => {
            if let Some(s) = p["sessionId"].as_str() {
                g.sessions.remove(s);
                g.tops.remove(s);
            }
            HookOut::keep()
        }
        "Page.frameNavigated" => {
            let f = &p["frame"];
            if f.get("parentId").is_none_or(Value::is_null) {
                if let Some(ps) = &parent {
                    let host = detect::host_of(f["url"].as_str().unwrap_or(""));
                    g.tops.insert(ps.clone(), host);
                }
            }
            HookOut::keep()
        }
        "Page.windowOpen" => {
            // the browser opens no window for a page (it is started with --block-new-web-contents): what the page tried
            // is reported where it would have gone, judged like a page load there
            let url = p["url"].as_str().unwrap_or("").to_string();
            let (_, top, _) = top_of(&g, parent.as_deref());
            let facts = ReqFacts {
                method: "GET".into(),
                url: url.clone(),
                resource_type: "Document".into(),
                main_frame: true,
                top_host: top,
            };
            let held = match gatekeep::judge(&g.st, &facts) {
                Some(b) if !matches!(b, Block::RobotsUnknown(_)) => {
                    (b.host().to_string(), b.word())
                }
                _ => (detect::host_of(&url), "new_window"),
            };
            if g.blocked.len() < 200 {
                g.blocked.push(held);
            }
            HookOut::keep()
        }
        "Page.javascriptDialogOpening" => {
            if g.st.person {
                // the person answers it from the live view; nothing is answered on their behalf
                g.dialog = Some(json!({
                    "type": p["type"].as_str().unwrap_or("alert"),
                    "message": mask::mask_text(&p["message"].as_str().unwrap_or("").chars().take(200).collect::<String>()),
                }));
                HookOut::default()
            } else {
                // a dialog is not answered on a person's behalf: for the agent it is dismissed
                HookOut::answer(
                    parent,
                    "Page.handleJavaScriptDialog",
                    json!({ "accept": false }),
                )
            }
        }
        "Page.javascriptDialogClosed" => {
            g.dialog = None;
            HookOut::keep()
        }
        "Fetch.requestPaused" => {
            let id = p["requestId"].as_str().unwrap_or("").to_string();
            let url = p["request"]["url"].as_str().unwrap_or("").to_string();
            let method = p["request"]["method"].as_str().unwrap_or("GET").to_string();
            let (is_page, top, target) = top_of(&g, parent.as_deref());
            let tab_page = is_page
                && target.as_deref() == p["frameId"].as_str()
                && p["frameId"].is_string()
                && p["resourceType"] == "Document";
            let robots_tab = target
                .as_ref()
                .is_some_and(|t| g.robots_targets.contains(t));
            let verdict = if robots_tab {
                // the worker's robots reader reads robots.txt, with GET, and nothing else
                (method != "GET" || crate::robots::path_of(&url) != "/robots.txt")
                    .then_some(Block::Scheme)
            } else {
                let facts = ReqFacts {
                    method,
                    url: url.clone(),
                    resource_type: p["resourceType"].as_str().unwrap_or("").to_string(),
                    main_frame: is_page
                        && target.as_deref() == p["frameId"].as_str()
                        && p["frameId"].is_string(),
                    top_host: top,
                };
                gatekeep::judge(&g.st, &facts)
            };
            match verdict {
                None => {
                    HookOut::answer(parent, "Fetch.continueRequest", json!({ "requestId": id }))
                }
                Some(b) => {
                    if matches!(b, Block::RobotsUnknown(_)) {
                        let o = origin_of(&url);
                        if !g.robots_wanted.contains(&o) {
                            g.robots_wanted.push(o);
                        }
                    }
                    if g.blocked.len() < 200 {
                        g.blocked.push((b.host().to_string(), b.word()));
                    }
                    // a page load refused for the tab itself stops there and the tab keeps the page it shows (an error page
                    // would replace it); anything else is failed as blocked
                    let reason = if tab_page {
                        "Aborted"
                    } else {
                        "BlockedByClient"
                    };
                    HookOut::answer(
                        parent,
                        "Fetch.failRequest",
                        json!({ "requestId": id, "errorReason": reason }),
                    )
                }
            }
        }
        _ => HookOut::keep(),
    }
}

struct Tab {
    target: String,
    session: String,
}

#[derive(Debug, Clone)]
pub struct DownloadInfo {
    pub name: String,
    pub bytes: u64,
    pub class: Download,
}

/// A request the page made that was held back, for the agent: where it went and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub host: String,
    pub why: &'static str,
}

pub struct Driver {
    cdp: Cdp,
    child: Child,
    tabs: Vec<Tab>,
    active: usize,
    pub policy: BrowserPolicy,
    pub device: Device,
    allowed: Vec<String>,
    work: PathBuf,
    dl_dir: PathBuf,
    quarantine: PathBuf,
    /// The downloads folder is read by the box's group (the worker has a private root of its own), so a document released
    /// into it is made readable by the group too. A held-back file is never.
    shared_downloads: bool,
    /// The worker's own private folder, when it has one: never a place a file is uploaded from.
    private_root: Option<PathBuf>,
    limiter: RateLimiter,
    epoch: Instant,
    sh: Arc<Mutex<Shared>>,
    inflight: HashMap<String, String>,
    pub downloads: Vec<DownloadInfo>,
    agent: String,
    /// Tabs a page opened since the last action: reported, never switched to for the agent.
    opened: u32,
    /// What an action without an approval tried to send, by its fingerprint: the next preview of it asks.
    learned: HashMap<String, Vec<String>>,
    last_frame: Option<(Vec<u8>, String)>,
    /// How many files this session has staged for upload (each gets a folder of its own).
    upload_n: u32,
}

/// Whether Chromium is told to run without its own sandbox: only when `OZBOX_BROWSER_NO_SANDBOX=1` is set. The launcher never
/// sets it, so on the box the sandbox stays on.
fn chromium_sandbox_disabled_by_env() -> bool {
    std::env::var("OZBOX_BROWSER_NO_SANDBOX").is_ok_and(|v| v == "1")
}

/// A folder only the box user can open (profiles, downloads): made, then narrowed to 0700.
pub fn private_dir(p: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A folder the box's group may read and no one else (the recording and the documents a session released), made, then set
/// to 0750.
pub fn shared_dir(p: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // A folder made inside the shared root is already `0750` with the group of that root (its setgid bit is inherited and
        // the umask is 0027). A `chmod` would clear that bit, so every file made in the folder afterwards would get the
        // browser's own group, which the dashboard and the agent are not in. Change the mode only when it is not right, and
        // keep the bit if it is there.
        let cur = std::fs::metadata(p)?.permissions().mode();
        if cur & 0o777 != 0o750 {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o750 | (cur & 0o2000)))?;
        }
    }
    Ok(())
}

/// Held while a browser launches and answers its first call.
static START_GATE: Mutex<()> = Mutex::new(());

impl Driver {
    /// `quarantine` is where downloads wait until they have been looked at: a folder only the worker's user can open.
    pub fn launch(start: &Start, profile: &Path, dl_dir: &Path, quarantine: &Path) -> R<Self> {
        let binary = cdp::find_chromium().ok_or_else(|| {
            bad(
                "failed",
                "no Chromium is installed on this box (set OZBOX_CHROMIUM, or install chromium)",
            )
        })?;
        private_dir(profile).map_err(|e| bad("failed", e.to_string()))?;
        let m = start.device.metrics();
        let opts = LaunchOpts {
            binary,
            profile_dir: profile.to_string_lossy().into_owned(),
            width: m.width,
            height: m.height,
            proxy: start.policy.proxy.clone(),
            no_sandbox: chromium_sandbox_disabled_by_env(),
            max_old_space_mb: 512,
        };
        // one browser starts at a time in this process: several starting together starve each other on a small machine
        let _starting = START_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let l = cdp::launch(&opts)?;
        let quarantine = quarantine.to_path_buf();
        let mut d = Self {
            cdp: l.cdp,
            child: l.child,
            tabs: Vec::new(),
            active: 0,
            policy: start.policy.clone(),
            device: start.device,
            allowed: start.allowed_hosts.clone(),
            work: PathBuf::from(&start.work),
            dl_dir: dl_dir.to_path_buf(),
            quarantine,
            shared_downloads: start.private_root.is_some(),
            private_root: start.private_root.as_deref().map(PathBuf::from),
            limiter: RateLimiter::default(),
            epoch: Instant::now(),
            sh: Arc::new(Mutex::new(Shared::default())),
            inflight: HashMap::new(),
            downloads: Vec::new(),
            agent: String::new(),
            opened: 0,
            learned: HashMap::new(),
            last_frame: None,
            upload_n: 0,
        };
        d.boot()?;
        drop(_starting);
        Ok(d)
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn shared(&self) -> std::sync::MutexGuard<'_, Shared> {
        lock_shared(&self.sh)
    }

    fn boot(&mut self) -> R<()> {
        let v = self.cdp.await_ready(cdp::START_WINDOW)?;
        let real = v["userAgent"].as_str().unwrap_or("Chromium").to_string();
        self.agent = self.device.user_agent(&real);
        {
            let mut g = self.shared();
            g.st = GateState {
                allowed: self.allowed.clone(),
                safe_sites: self.policy.safe_sites.clone(),
                exempt_sites: self.policy.exempt_sites.clone(),
                respect_robots: self.policy.respect_robots,
                agent: self.agent.clone(),
                ..GateState::default()
            };
            g.ua = self.agent.clone();
            g.metrics = Some(self.device.metrics());
        }
        let sh = self.sh.clone();
        self.cdp.set_hook(Box::new(move |ev| on_wire(&sh, ev)));
        private_dir(&self.quarantine).map_err(|e| bad("failed", e.to_string()))?;
        // the downloads folder is the group's to read when the worker has a private root; otherwise it is private too
        let _ = if self.shared_downloads {
            shared_dir(&self.dl_dir)
        } else {
            private_dir(&self.dl_dir)
        };
        self.cdp.call(
            None,
            "Browser.setDownloadBehavior",
            json!({ "behavior": "allow", "downloadPath": self.quarantine.to_string_lossy(), "eventsEnabled": true }),
        )?;
        self.cdp.call(
            None,
            "Target.setDiscoverTargets",
            json!({ "discover": true }),
        )?;
        // every tab, popup, frame and worker is attached paused, set up (requests judged), then let run: the first page too
        self.cdp.call(
            None,
            "Target.setAutoAttach",
            json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true }),
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.tabs.is_empty() && Instant::now() < deadline {
            self.cdp.pump(Duration::from_millis(50));
            self.service();
        }
        if self.tabs.is_empty() {
            let t = self.new_target()?;
            self.active = t;
        }
        self.active = 0;
        Ok(())
    }

    /// Take in the tabs that appeared. A tab a page opened is not switched to: the agent is told, and a switch is judged.
    fn adopt(&mut self) {
        let (pages, skip) = {
            let mut g = self.shared();
            (std::mem::take(&mut g.new_pages), g.robots_targets.clone())
        };
        for (target, session, opener) in pages {
            if skip.contains(&target) || self.tabs.iter().any(|t| t.target == target) {
                continue;
            }
            self.tabs.push(Tab { target, session });
            if opener {
                self.opened += 1;
            }
        }
    }

    /// A new blank tab, once the hook has set it up. Returns its index.
    fn new_target(&mut self) -> R<usize> {
        let r = self
            .cdp
            .call(None, "Target.createTarget", json!({ "url": "about:blank" }))?;
        let t = r["targetId"].as_str().unwrap_or("").to_string();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.adopt();
            if let Some(i) = self.tabs.iter().position(|x| x.target == t) {
                return Ok(i);
            }
            if Instant::now() >= deadline {
                return Err(bad("failed", "the new tab did not open in time"));
            }
            self.cdp.pump(Duration::from_millis(50));
        }
    }

    fn session(&self) -> R<String> {
        self.tabs
            .get(self.active)
            .map(|t| t.session.clone())
            .ok_or_else(|| bad("failed", "there is no open tab"))
    }

    fn send(&mut self, method: &str, params: Value) -> R<Value> {
        let s = self.session()?;
        self.ready(&s)?;
        Ok(self.cdp.call(Some(&s), method, params)?)
    }

    /// A tab is driven only once the browser has done every command that set it up. A tab that was already open when the
    /// worker attached (the first one) is not held paused like a new one, so on a loaded machine the agent's first
    /// navigation could otherwise commit before the page's events are on: the tab's committed site is then never learnt,
    /// and a safe site's own post is held. A tab whose setup the browser refused (its requests might not be judged) is
    /// never driven.
    fn ready(&mut self, s: &str) -> R<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // a frame or worker in the tab that could not be set up stays paused; the tab is not driven either
            let inside = {
                let g = self.shared();
                g.sessions
                    .keys()
                    .filter(|k| k.as_str() != s && within(&g, k, s))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if inside
                .iter()
                .any(|k| self.cdp.setup_state(k) == Setup::Failed)
            {
                return Err(bad(
                    "failed",
                    "the browser could not put a frame or worker in this tab under judgement, so the tab is not used: \
                     navigate to open another page",
                ));
            }
            match self.cdp.setup_state(s) {
                Setup::Ready => return Ok(()),
                Setup::Failed => {
                    return Err(bad(
                        "failed",
                        "the browser could not set this tab up, so it is not used",
                    ))
                }
                Setup::Pending if Instant::now() >= deadline => {
                    return Err(bad("failed", "the tab did not finish setting up in time"))
                }
                Setup::Pending => {
                    self.cdp.pump(Duration::from_millis(20));
                }
            }
        }
    }

    /// Run a script in the page and return its value.
    pub fn eval(&mut self, expr: &str) -> R<Value> {
        let r = self.send(
            "Runtime.evaluate",
            json!({ "expression": expr, "returnByValue": true, "awaitPromise": true }),
        )?;
        if let Some(e) = r.get("exceptionDetails") {
            let t = e["exception"]["description"]
                .as_str()
                .or(e["text"].as_str())
                .unwrap_or("the page script failed");
            return Err(bad(
                "failed",
                t.lines()
                    .next()
                    .unwrap_or("the page script failed")
                    .to_string(),
            ));
        }
        Ok(r["result"]["value"].clone())
    }

    fn call_fn(&mut self, f: &str, args: &[Value]) -> R<Value> {
        let a: Vec<String> = args.iter().map(Value::to_string).collect();
        self.eval(&format!("({f})({})", a.join(",")))
    }

    // ---- who holds it, and what a person approved ----------------------------------------------------------------

    /// A person holds the session: their browsing is not judged, and a dialog waits for them.
    pub fn set_person(&mut self, person: bool) {
        let mut g = self.shared();
        g.st.person = person;
        if !person {
            g.dialog = None;
        }
    }

    /// A person approved this host for the rest of the session.
    pub fn approve_host(&mut self, host: &str) {
        let h = detect::normal_host(host);
        let mut g = self.shared();
        if !h.is_empty() && !g.st.approved.contains(&h) {
            g.st.approved.push(h);
        }
    }

    fn known_hosts(&self) -> Vec<String> {
        let mut v = self.allowed.clone();
        v.extend(self.shared().st.approved.iter().cloned());
        v
    }

    /// What the page made that was held back since the last call, deduplicated.
    pub fn take_blocked(&mut self) -> Vec<Held> {
        let raw = std::mem::take(&mut self.shared().blocked);
        let mut out: Vec<Held> = Vec::new();
        for (host, why) in raw {
            if !out.iter().any(|h| h.host == host && h.why == why) {
                out.push(Held { host, why });
            }
        }
        out
    }

    /// Tabs a page opened since the last call.
    pub fn take_opened(&mut self) -> u32 {
        std::mem::take(&mut self.opened)
    }

    /// Remember what an action without an approval tried to send, so the next preview of it asks a person.
    pub fn learn(&mut self, fingerprint: &str, held: &[Held]) {
        if fingerprint.is_empty() {
            return;
        }
        let hosts: Vec<String> = held
            .iter()
            .filter(|h| h.why == "submit" && !h.host.is_empty())
            .map(|h| h.host.clone())
            .collect();
        if !hosts.is_empty() && self.learned.len() < 500 {
            self.learned
                .entry(fingerprint.to_string())
                .or_default()
                .extend(hosts);
        }
    }

    fn apply_learned(&self, a: &mut Assessment) {
        if a.risk >= Risk::Submit {
            return;
        }
        if let Some(hosts) = self.learned.get(&a.fingerprint) {
            a.risk = Risk::Submit;
            a.reason = format!("the last time, this sent data to {}", hosts.join(", "));
            a.dest = hosts.join(",");
        }
    }

    /// Read robots.txt for the sites a page went on to whose robots.txt was not read yet. Returns the hosts read.
    pub fn read_wanted_robots(&mut self) -> Vec<String> {
        let wanted = std::mem::take(&mut self.shared().robots_wanted);
        let mut read = Vec::new();
        for o in wanted.into_iter().take(5) {
            let host = detect::host_of(&o);
            if !self.shared().st.robots.contains_key(&host) {
                let r = self.fetch_robots(&o);
                self.shared().st.robots.insert(host.clone(), r);
                read.push(host);
            }
        }
        read
    }

    // ---- events ---------------------------------------------------------------------------------------------------

    /// Answer what the browser asked: downloads, tabs that closed or appeared. Called between actions as well.
    pub fn service(&mut self) {
        self.cdp.pump(Duration::from_millis(1));
        for ev in self.cdp.take_events() {
            self.on_event(&ev);
        }
        self.adopt();
    }

    fn on_event(&mut self, ev: &Value) {
        let m = ev["method"].as_str().unwrap_or("");
        let p = &ev["params"];
        match m {
            "Target.targetDestroyed" => {
                if let Some(t) = p["targetId"].as_str() {
                    if let Some(i) = self.tabs.iter().position(|x| x.target == t) {
                        self.tabs.remove(i);
                        if self.active >= self.tabs.len() {
                            self.active = self.tabs.len().saturating_sub(1);
                        } else if i < self.active {
                            self.active -= 1;
                        }
                    }
                }
            }
            "Browser.downloadWillBegin" => {
                if let (Some(g), Some(n)) = (p["guid"].as_str(), p["suggestedFilename"].as_str()) {
                    self.inflight.insert(g.to_string(), sanitize_name(n));
                }
            }
            "Browser.downloadProgress" => {
                let g = p["guid"].as_str().unwrap_or("").to_string();
                let total = p["totalBytes"].as_u64().unwrap_or(0);
                let recv = p["receivedBytes"].as_u64().unwrap_or(0);
                if (total > self.policy.max_download_bytes || recv > self.policy.max_download_bytes)
                    && p["state"] == "inProgress"
                {
                    let _ = self
                        .cdp
                        .call(None, "Browser.cancelDownload", json!({ "guid": g }));
                    self.inflight.remove(&g);
                    self.downloads.push(DownloadInfo {
                        name: "(cancelled)".into(),
                        bytes: recv,
                        class: Download::TooLarge,
                    });
                } else if p["state"] == "completed" {
                    if let Some(name) = self.inflight.remove(&g) {
                        let saved = p["filePath"]
                            .as_str()
                            .map(PathBuf::from)
                            .unwrap_or_else(|| self.quarantine.join(&name));
                        self.finish_download(&saved, &name);
                    }
                }
            }
            _ => {}
        }
    }

    fn finish_download(&mut self, src: &Path, name: &str) {
        let src = src.to_path_buf();
        let Ok(meta) = std::fs::metadata(&src) else {
            return;
        };
        // an office document is looked inside (the names of its parts), so read it whole when it is small enough
        let class = if meta.len() <= 64 * 1024 * 1024 {
            match std::fs::read(&src) {
                Ok(data) => policy::classify_file(name, &data, &self.policy),
                Err(_) => Download::Quarantine("it could not be read".into()),
            }
        } else {
            let mut head = vec![0u8; 512];
            let n = std::fs::File::open(&src)
                .and_then(|mut f| std::io::Read::read(&mut f, &mut head))
                .unwrap_or(0);
            head.truncate(n);
            match policy::classify_download(name, meta.len(), &head, &self.policy) {
                Download::Document if name.contains(".docx") || name.contains(".xlsx") => {
                    Download::Quarantine("too large to look inside".into())
                }
                c => c,
            }
        };
        match class {
            Download::Document => {
                let _ = self.release(&src, &self.dl_dir.join(name));
            }
            // held back: it stays in the quarantine folder, under a name that cannot escape it
            _ => {
                let d = self.quarantine.join(name);
                if d != src {
                    let _ = std::fs::rename(&src, &d);
                }
            }
        }
        self.downloads.push(DownloadInfo {
            name: name.to_string(),
            bytes: meta.len(),
            class,
        });
    }

    /// Move a file into the downloads folder, and, where that folder is shared with the box's group, make the file readable by
    /// it (a browser writes a download for its own user only).
    fn release(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        if !self.shared_downloads {
            return std::fs::rename(from, to);
        }
        // A rename keeps the file's own group (the browser's), which the box's group cannot read. A copy is a new file, which
        // takes the group of the shared folder it is made in (its setgid bit); the held file is then removed.
        std::fs::copy(from, to)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o640))?;
        }
        let _ = std::fs::remove_file(from);
        Ok(())
    }

    // ---- reading the page ------------------------------------------------------------------------------------------

    pub fn page_facts(&mut self) -> R<Page> {
        let v = self.eval(FACTS_JS)?;
        serde_json::from_value(v)
            .map_err(|e| bad("failed", format!("the page could not be read: {e}")))
    }

    pub fn url(&mut self) -> String {
        self.eval("location.href")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    }

    fn target_facts(&mut self, target: &str) -> R<Target> {
        if !valid_ref(target) {
            return Err(bad(
                "invalid",
                "a target is an element name from the last snapshot, such as e12",
            ));
        }
        let v = self.call_fn(TARGET_JS, &[json!(target)])?;
        if v.is_null() {
            return Err(bad(
                "failed",
                format!("there is no element {target} on the page now: take a new snapshot"),
            ));
        }
        serde_json::from_value(v).map_err(|e| bad("failed", e.to_string()))
    }

    pub fn snapshot(&mut self) -> R<String> {
        self.service();
        let raw = self.eval(SNAPSHOT_JS)?;
        Ok(render_snapshot(&raw))
    }

    /// The field name an action touches, for the audit chain and the recording. Never its value.
    pub fn field_name(&mut self, a: &Action) -> Option<String> {
        let t = a.target()?;
        self.target_facts(t)
            .ok()
            .map(|f| if f.name.is_empty() { f.tag } else { f.name })
            .map(|n| detect::clean_name(&n))
    }

    // ---- judging ---------------------------------------------------------------------------------------------------

    /// A page that is not a web address (`data:`, `blob:`, `about:`) has no site to judge: the agent does not act on it.
    fn web_page(page: &Page) -> R<()> {
        if detect::host_of(&page.url).is_empty() {
            return Err(bad(
                "refused",
                "this tab shows a page that is not a web address (data:, blob: or about:), which Oz Box does not act on for an agent: open a web address first",
            ));
        }
        Ok(())
    }

    pub fn preview(&mut self, a: &Action) -> R<Assessment> {
        a.validate().map_err(|m| bad("invalid", m))?;
        self.service();
        let safe = self.policy.safe_sites.clone();
        match a {
            Action::Navigate { url } | Action::TabNew { url: Some(url) } => {
                check_scheme(url)?;
                Ok(detect::assess_navigation(url, &self.known_hosts()))
            }
            Action::Click { target } => {
                let page = self.page_facts()?;
                Self::web_page(&page)?;
                let t = self.target_facts(target)?;
                let submit = t.kind == "submit";
                let mut a = detect::assess_activation(&page, &t, submit, &safe);
                if a.risk == Risk::None
                    && (t.href.starts_with("http://") || t.href.starts_with("https://"))
                {
                    // a link is judged as the site it opens, and stays tied to this element
                    let element = a.fingerprint.clone();
                    a = detect::assess_navigation(&t.href, &self.known_hosts());
                    a.fingerprint = detect::fingerprint(&["link", &element, &a.fingerprint]);
                }
                self.apply_learned(&mut a);
                Ok(a)
            }
            Action::Type {
                target,
                submit: true,
                ..
            } => {
                let page = self.page_facts()?;
                Self::web_page(&page)?;
                let t = self.target_facts(target)?;
                let mut a = detect::assess_activation(&page, &t, t.form.is_some(), &safe);
                self.apply_learned(&mut a);
                Ok(a)
            }
            Action::Press { key } if key.eq_ignore_ascii_case("enter") => {
                let page = self.page_facts()?;
                Self::web_page(&page)?;
                let v = self.eval(ACTIVE_JS)?;
                let t: Target = serde_json::from_value(v).unwrap_or_default();
                if t.tag == "iframe" {
                    // the key goes into a frame this page holds; what it does there is not read, so a person decides
                    let mut a = Assessment::with(
                        Risk::Submit,
                        &detect::host_of(&page.url),
                        "the key would go into a frame inside the page, which may send something",
                    );
                    a.dest = record::page_of(&t.href);
                    a.fingerprint =
                        detect::fingerprint(&["enter-frame", &record::page_of(&page.url), &t.href]);
                    return Ok(a);
                }
                let in_form = t.form.is_some() && v_is_not_textarea(&t);
                let mut a = detect::assess_activation(&page, &t, in_form, &safe);
                self.apply_learned(&mut a);
                Ok(a)
            }
            Action::Upload { target, path } => {
                let (_, shown) = policy::upload_allowed(
                    Path::new(path),
                    &self.work,
                    &self.policy.upload_dirs,
                    &self.dl_dir,
                    self.private_root.as_deref(),
                )
                .map_err(|m| bad("refused", m))?;
                let page = self.page_facts()?;
                Self::web_page(&page)?;
                let t = self.target_facts(target)?;
                let host = detect::host_of(&page.url);
                let mut a = Assessment::with(
                    Risk::Upload,
                    &host,
                    "this would give a file from the box to this page",
                );
                a.fields = vec![("file".into(), shown.clone())];
                a.fingerprint = detect::fingerprint(&[
                    "upload",
                    &record::page_of(&page.url),
                    &shown,
                    &t.name,
                    &t.tag,
                ]);
                a.dest = shown;
                Ok(a)
            }
            Action::OpenDownload { name } => {
                let d = self.downloads.iter().find(|d| &d.name == name);
                let mut a = match d {
                    Some(DownloadInfo {
                        class: Download::Quarantine(why),
                        ..
                    }) => {
                        let mut a = Assessment::with(
                            Risk::Program,
                            "",
                            &format!("this file is held back: {why}"),
                        );
                        a.fields = vec![("file".into(), name.clone())];
                        a
                    }
                    _ => Assessment::none(""),
                };
                a.fingerprint = detect::fingerprint(&["open", name]);
                Ok(a)
            }
            // a page the agent merely reads can still be a challenge: tell the caller
            _ => {
                let page = self.page_facts()?;
                match detect::captcha(&page) {
                    Some(why) if !a.reads() => Ok(Assessment::with(
                        Risk::Captcha,
                        &detect::host_of(&page.url),
                        &why,
                    )),
                    _ => Ok(Assessment::none(&detect::host_of(&page.url))),
                }
            }
        }
    }

    pub fn challenge(&mut self) -> Option<String> {
        self.page_facts().ok().and_then(|p| detect::captcha(&p))
    }

    // ---- doing -----------------------------------------------------------------------------------------------------

    /// Wait for a navigation the last input started, if one did.
    fn settle(&mut self) {
        let sess = self.session().unwrap_or_default();
        let main = self
            .tabs
            .get(self.active)
            .map(|t| t.target.clone())
            .unwrap_or_default();
        // the tab's page finished: its load event, or its main frame stopping (a jump within the page, or a page restored
        // from the back-forward cache, fires no load event)
        let finished = |e: &Value| {
            e["sessionId"] == sess.as_str()
                && (e["method"] == "Page.loadEventFired"
                    || (e["method"] == "Page.frameStoppedLoading"
                        && e["params"]["frameId"] == main.as_str()))
        };
        self.cdp.pump(Duration::from_millis(200));
        let started = self.cdp.take_events();
        // a navigation is on its way from the moment the page asks for one: a form post may start loading only later, and
        // the approval it was given lasts until it has finished
        let navigating = started.iter().any(|ev| {
            matches!(
                ev["method"].as_str(),
                Some(
                    "Page.frameRequestedNavigation"
                        | "Page.frameScheduledNavigation"
                        | "Page.frameStartedNavigating"
                        | "Page.frameStartedLoading"
                        | "Page.frameNavigated"
                )
            ) && ev["sessionId"] == sess.as_str()
        });
        let mut done = started.iter().any(&finished);
        for ev in started {
            self.on_event(&ev);
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while navigating && !done && Instant::now() < deadline {
            if self
                .cdp
                .wait_event(Duration::from_millis(100), finished)
                .is_some()
            {
                break;
            }
            // what arrives between two waits is looked at too: an event taken here is not seen by the next wait
            self.cdp.pump(Duration::from_millis(1));
            let evs = self.cdp.take_events();
            done = evs.iter().any(&finished);
            for ev in evs {
                self.on_event(&ev);
            }
            self.adopt();
        }
        self.service();
        std::thread::sleep(Duration::from_millis(80));
        self.service();
    }

    fn polite(&mut self, url: &str) -> R<()> {
        let host = detect::host_of(url);
        let exempt =
            detect::is_loopback(&host) || detect::host_in(&self.policy.exempt_sites, &host);
        if exempt {
            return Ok(());
        }
        let mut gap = self.policy.min_gap_ms;
        if self.policy.respect_robots {
            let known = self.shared().st.robots.get(&host).cloned();
            let r = match known {
                Some(r) => r,
                None => {
                    let r = self.fetch_robots(&origin_of(url));
                    self.shared().st.robots.insert(host.clone(), r.clone());
                    r
                }
            };
            if !r.allowed(&self.agent, &robots::path_of(url)) {
                return Err(bad("robots", format!("{host} asks automated browsers not to open that page (robots.txt), and Oz Box respects that. If it is your own site, add it to the project's exempt sites.")));
            }
            if let Some(d) = r.crawl_delay_ms(&self.agent) {
                gap = gap.max(d);
            }
        }
        let wait = self.limiter.reserve(&host, self.now_ms(), gap);
        if wait > 0 {
            std::thread::sleep(Duration::from_millis(wait.min(60_000)));
        }
        Ok(())
    }

    /// robots.txt for a site, read in a tab of the worker's own that may read nothing else.
    fn fetch_robots(&mut self, origin: &str) -> Robots {
        let res = (|| -> R<String> {
            let r = self
                .cdp
                .call(None, "Target.createTarget", json!({ "url": "about:blank" }))?;
            let tid = r["targetId"].as_str().unwrap_or("").to_string();
            self.shared().robots_targets.insert(tid.clone());
            let deadline = Instant::now() + Duration::from_secs(5);
            let s = loop {
                let found = self.shared().sessions.iter().find_map(|(s, k)| match k {
                    SessKind::Page { target } if *target == tid => Some(s.clone()),
                    _ => None,
                });
                if let Some(s) = found {
                    break s;
                }
                if Instant::now() >= deadline {
                    let _ = self
                        .cdp
                        .call(None, "Target.closeTarget", json!({ "targetId": tid }));
                    return Err(bad("failed", "the robots reader did not start"));
                }
                self.cdp.pump(Duration::from_millis(30));
            };
            let nav = self.cdp.call(
                Some(&s),
                "Page.navigate",
                json!({ "url": format!("{origin}/robots.txt") }),
            );
            let mut text = String::new();
            if nav.is_ok() {
                let s2 = s.clone();
                let _ = self.cdp.wait_event(Duration::from_secs(10), |e| {
                    e["method"] == "Page.loadEventFired" && e["sessionId"] == s2.as_str()
                });
                let v = self.cdp.call(Some(&s), "Runtime.evaluate", json!({ "expression": "document.contentType==='text/plain'?document.body.innerText:''", "returnByValue": true }))?;
                text = v["result"]["value"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(100_000)
                    .collect();
            }
            let _ = self
                .cdp
                .call(None, "Target.closeTarget", json!({ "targetId": tid }));
            Ok(text)
        })();
        Robots::parse(&res.unwrap_or_default())
    }

    /// Do an action. `grant` is the destinations a person approved for it: while it runs, the page may send data there and
    /// nowhere else.
    pub fn perform(&mut self, a: &Action, grant: Option<Vec<String>>) -> R<Value> {
        a.validate().map_err(|m| bad("invalid", m))?;
        self.service();
        self.shared().st.grant = grant;
        let r = self.perform_inner(a);
        self.settle();
        self.shared().st.grant = None;
        r
    }

    fn click_at(&mut self, x: f64, y: f64) -> R<()> {
        for (t, cb) in [("mouseMoved", 0), ("mousePressed", 1), ("mouseReleased", 1)] {
            let mut p = json!({ "type": t, "x": x, "y": y, "button": "left", "clickCount": cb });
            if t == "mouseMoved" {
                p["button"] = json!("none");
            }
            self.send("Input.dispatchMouseEvent", p)?;
        }
        Ok(())
    }

    fn point(&mut self, target: &str) -> R<(f64, f64)> {
        if !valid_ref(target) {
            return Err(bad(
                "invalid",
                "a target is an element name from the last snapshot, such as e12",
            ));
        }
        let v = self.call_fn(POINT_JS, &[json!(target)])?;
        if let Some(e) = v["error"].as_str() {
            return Err(bad("failed", e));
        }
        Ok((
            v["x"].as_f64().unwrap_or(0.0),
            v["y"].as_f64().unwrap_or(0.0),
        ))
    }

    fn press_key(&mut self, key: &str) -> R<()> {
        for e in key_events(key).map_err(|m| bad("invalid", m))? {
            self.send("Input.dispatchKeyEvent", e)?;
        }
        Ok(())
    }

    /// A navigation the browser refused: say why, from what the hook held back.
    fn nav_error(&mut self, err: &str) -> DErr {
        let held = self.shared().blocked.last().cloned();
        match held {
            Some((h, "new_domain")) => bad("refused", format!("{h} is not on the project's browser allow-list, and no person approved it for this session")),
            Some((h, "robots")) => bad("robots", format!("{h} asks automated browsers not to open that page (robots.txt), and Oz Box respects that")),
            Some((h, "robots_unread")) => bad("refused", format!("the page went on to {h}, whose robots.txt had not been read; it is read now, so try the same action again")),
            Some((h, "internal")) => bad("refused", format!("{h} is inside the box's network, and is not opened by an agent")),
            Some((_, "not_a_web_address")) => bad("refused", "the page tried to open something that is not a web address"),
            _ => bad("failed", format!("the page could not be opened ({err})")),
        }
    }

    fn perform_inner(&mut self, a: &Action) -> R<Value> {
        match a {
            Action::Navigate { url } => {
                check_scheme(url)?;
                self.polite(url)?;
                let r = self.send("Page.navigate", json!({ "url": url }))?;
                if let Some(e) = r["errorText"].as_str() {
                    return Err(self.nav_error(e));
                }
                Ok(json!({ "navigated": true }))
            }
            Action::Back | Action::Forward => {
                let h = self.send("Page.getNavigationHistory", json!({}))?;
                let cur = h["currentIndex"].as_i64().unwrap_or(0);
                let want = if matches!(a, Action::Back) {
                    cur - 1
                } else {
                    cur + 1
                };
                let entry = h["entries"]
                    .as_array()
                    .and_then(|e| e.get(want.max(0) as usize))
                    .cloned();
                match (want >= 0, entry) {
                    (true, Some(e)) => {
                        if let Some(u) = e["url"].as_str().filter(|u| u.starts_with("http")) {
                            self.polite(u)?;
                        }
                        self.send(
                            "Page.navigateToHistoryEntry",
                            json!({ "entryId": e["id"].as_i64().unwrap_or(0) }),
                        )?;
                        Ok(json!({ "moved": true }))
                    }
                    _ => Err(bad("failed", "there is nowhere to go")),
                }
            }
            Action::Reload => {
                let u = self.url();
                if u.starts_with("http") {
                    self.polite(&u)?;
                }
                self.send("Page.reload", json!({}))?;
                Ok(json!({ "reloaded": true }))
            }
            Action::Click { target } => {
                // a link is a page load like any other: robots.txt and the pace apply
                if let Ok(t) = self.target_facts(target) {
                    if t.href.starts_with("http://") || t.href.starts_with("https://") {
                        self.polite(&t.href)?;
                    }
                }
                let (x, y) = self.point(target)?;
                self.click_at(x, y)?;
                Ok(json!({ "clicked": target }))
            }
            Action::Hover { target } => {
                let (x, y) = self.point(target)?;
                self.send(
                    "Input.dispatchMouseEvent",
                    json!({ "type": "mouseMoved", "x": x, "y": y }),
                )?;
                Ok(json!({ "hovered": target }))
            }
            Action::Type {
                target,
                text,
                submit,
                clear,
            } => {
                let e = self.call_fn(FOCUS_JS, &[json!(target), json!(clear)])?;
                if let Some(m) = e.as_str().filter(|m| !m.is_empty()) {
                    return Err(bad("failed", m));
                }
                if *clear {
                    self.send("Input.dispatchKeyEvent", json!({ "type": "rawKeyDown", "key": "Delete", "code": "Delete", "windowsVirtualKeyCode": 46 }))?;
                    self.send("Input.dispatchKeyEvent", json!({ "type": "keyUp", "key": "Delete", "code": "Delete", "windowsVirtualKeyCode": 46 }))?;
                }
                self.send("Input.insertText", json!({ "text": text }))?;
                if *submit {
                    self.press_key("Enter")?;
                }
                Ok(json!({ "typed": target, "chars": text.chars().count() }))
            }
            Action::Select { target, value } => {
                let e = self.call_fn(SELECT_JS, &[json!(target), json!(value)])?;
                match e.as_str().filter(|m| !m.is_empty()) {
                    Some(m) => Err(bad("failed", m)),
                    None => Ok(json!({ "selected": target })),
                }
            }
            Action::Scroll { target, dy } => {
                let ok = self.call_fn(SCROLL_JS, &[json!(target), json!(dy)])?;
                if ok == json!(false) {
                    return Err(bad(
                        "failed",
                        "there is no such element on the page now: take a new snapshot",
                    ));
                }
                Ok(json!({ "scrolled": true }))
            }
            Action::Press { key } => {
                self.press_key(key)?;
                Ok(json!({ "pressed": key }))
            }
            Action::TabNew { url } => {
                if let Some(u) = url {
                    check_scheme(u)?;
                    self.polite(u)?;
                }
                let i = self.new_target()?;
                self.active = i;
                if let Some(u) = url {
                    let r = self.send("Page.navigate", json!({ "url": u }))?;
                    if let Some(e) = r["errorText"].as_str() {
                        return Err(self.nav_error(e));
                    }
                }
                Ok(json!({ "tab": i }))
            }
            Action::TabSwitch { index } => {
                let t = self
                    .tabs
                    .get(*index)
                    .ok_or_else(|| bad("failed", "there is no such tab"))?
                    .target
                    .clone();
                self.cdp
                    .call(None, "Target.activateTarget", json!({ "targetId": t }))?;
                self.active = *index;
                Ok(json!({ "tab": index }))
            }
            Action::TabClose { index } => {
                let i = index.unwrap_or(self.active);
                if self.tabs.len() <= 1 {
                    return Err(bad("failed", "the last tab stays open"));
                }
                let t = self
                    .tabs
                    .get(i)
                    .ok_or_else(|| bad("failed", "there is no such tab"))?
                    .target
                    .clone();
                self.cdp
                    .call(None, "Target.closeTarget", json!({ "targetId": t }))?;
                self.tabs.remove(i);
                self.active = self.active.min(self.tabs.len() - 1);
                Ok(json!({ "closed": i }))
            }
            Action::TabList => self.tab_list(),
            Action::Wait {
                ms,
                text,
                selector,
                timeout_ms,
            } => {
                if text.is_none() && selector.is_none() {
                    // the browser is answered all the while: a request a page makes, or a popup it opens, waits paused
                    // for the worker, and an opener stays frozen until its popup is let run
                    let until =
                        Instant::now() + Duration::from_millis(ms.unwrap_or(1000).min(30_000));
                    while Instant::now() < until {
                        let left = until.saturating_duration_since(Instant::now());
                        self.cdp.pump(left.min(Duration::from_millis(50)));
                        self.service();
                    }
                    return Ok(json!({ "waited": true }));
                }
                let deadline = Instant::now()
                    + Duration::from_millis(timeout_ms.unwrap_or(10_000).min(60_000));
                loop {
                    let ok = self.call_fn(
                        WAIT_JS,
                        &[
                            json!(text.clone().unwrap_or_default()),
                            json!(selector.clone().unwrap_or_default()),
                        ],
                    )?;
                    if ok == json!(true) {
                        return Ok(json!({ "found": true }));
                    }
                    if Instant::now() >= deadline {
                        return Err(bad("failed", "what was waited for did not appear in time"));
                    }
                    self.service();
                    std::thread::sleep(Duration::from_millis(150));
                }
            }
            Action::Upload { target, path } => {
                // Judged again here, on what is OPEN: the file is opened without following a link, where it really is is judged
                // again, and a copy only this worker owns is what Chromium is given (a folder swapped for a link since the
                // preview cannot reach the private folder, and the copy is what the person approved).
                self.upload_n += 1;
                let (real, shown) = crate::upload_stage::stage(
                    Path::new(path),
                    &crate::upload_stage::Where {
                        work: &self.work,
                        dirs: &self.policy.upload_dirs,
                        session_downloads: &self.dl_dir,
                        private_root: self.private_root.as_deref(),
                    },
                    &self.upload_stage_dir(),
                    self.upload_n,
                )
                .map_err(|m| bad("refused", m))?;
                let r = self.send(
                    "Runtime.evaluate",
                    json!({ "expression": format!("({})({})", FILE_JS, json!(target)) }),
                )?;
                let oid = r["result"]["objectId"]
                    .as_str()
                    .ok_or_else(|| bad("failed", "that is not a file input"))?
                    .to_string();
                self.send(
                    "DOM.setFileInputFiles",
                    json!({ "files": [real.to_string_lossy()], "objectId": oid }),
                )?;
                Ok(json!({ "uploaded": target, "file": shown }))
            }
            Action::Downloads => Ok(self.list_downloads()),
            Action::OpenDownload { name } => {
                let i = self
                    .downloads
                    .iter()
                    .position(|d| &d.name == name)
                    .ok_or_else(|| bad("failed", "there is no such download"))?;
                let held = matches!(self.downloads[i].class, Download::Quarantine(_));
                if held {
                    // only reached with a person's approval (the preview asks): the file leaves the held-back folder
                    // for the downloads folder, as a recorded step. The held-back folder's path is never handed out.
                    let from = self.quarantine.join(name);
                    let to = self.dl_dir.join(name);
                    self.release(&from, &to)
                        .map_err(|_| bad("failed", "the held-back file could not be released"))?;
                    self.downloads[i].class = Download::Document;
                }
                let d = &self.downloads[i];
                Ok(json!({
                    "file": self.rel_to_work(&self.dl_dir.join(name)),
                    "bytes": d.bytes,
                    "released": held,
                    "class": serde_json::to_value(&d.class).unwrap_or(Value::Null),
                }))
            }
            Action::Snapshot => Ok(json!({ "snapshot": self.snapshot()? })),
            Action::Screenshot { full_page } => {
                let b = self.screenshot(*full_page, true)?;
                Ok(json!({ "bytes": b.len() }))
            }
            Action::Extract { schema: s } => {
                let plan = schema::extraction_plan(s);
                let raw = self.call_fn(EXTRACT_JS, &[plan])?;
                let data = schema::coerce(s, &raw);
                let errs = schema::validate(s, &data);
                if errs.is_empty() {
                    Ok(json!({ "data": data }))
                } else {
                    Err(bad(
                        "schema",
                        format!(
                            "the page does not fit the schema: {}",
                            errs.into_iter().take(8).collect::<Vec<_>>().join("; ")
                        ),
                    ))
                }
            }
        }
    }

    /// A path as the files tools name it: relative to `/work`.
    fn rel_to_work(&self, p: &Path) -> String {
        let work = std::fs::canonicalize(&self.work).unwrap_or_else(|_| self.work.clone());
        let full = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        full.strip_prefix(&work)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
    }

    fn tab_list(&mut self) -> R<Value> {
        let t = self.cdp.call(None, "Target.getTargets", json!({}))?;
        let infos = t["targetInfos"].as_array().cloned().unwrap_or_default();
        let tabs: Vec<Value> = self
            .tabs
            .iter()
            .enumerate()
            .map(|(i, tab)| {
                let info = infos.iter().find(|x| x["targetId"] == tab.target.as_str());
                json!({
                    "index": i,
                    "active": i == self.active,
                    "page": crate::record::page_of(info.and_then(|x| x["url"].as_str()).unwrap_or("")),
                    "title": mask::mask_text(info.and_then(|x| x["title"].as_str()).unwrap_or("")),
                })
            })
            .collect();
        Ok(json!({ "tabs": tabs }))
    }

    /// The tabs' web addresses, without a query or a fragment: where a paused task picks up again.
    pub fn tab_addresses(&mut self) -> Vec<String> {
        let Ok(t) = self.cdp.call(None, "Target.getTargets", json!({})) else {
            return Vec::new();
        };
        let infos = t["targetInfos"].as_array().cloned().unwrap_or_default();
        self.tabs
            .iter()
            .filter_map(|tab| {
                infos
                    .iter()
                    .find(|x| x["targetId"] == tab.target.as_str())
                    .and_then(|x| x["url"].as_str())
                    .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
                    .map(|u| {
                        u.split(['?', '#'])
                            .next()
                            .unwrap_or(u)
                            .chars()
                            .take(2000)
                            .collect()
                    })
            })
            .collect()
    }

    pub fn list_downloads(&self) -> Value {
        json!({ "downloads": self.downloads.iter().map(|d| json!({
            "name": d.name, "bytes": d.bytes, "class": serde_json::to_value(&d.class).unwrap_or(Value::Null),
        })).collect::<Vec<_>>() })
    }

    /// A screenshot as JPEG bytes. With `blur`, every field that is secret is blurred first, so what is kept is safe to
    /// keep; the blur is taken off again before anything else happens.
    pub fn screenshot(&mut self, full_page: bool, blur: bool) -> R<Vec<u8>> {
        if blur {
            self.blur_secrets()?;
        }
        let r = self.capture(
            json!({ "format": "jpeg", "quality": 55, "captureBeyondViewport": full_page }),
        );
        if blur {
            let _ = self.eval(&format!(
                "(function(){{var s=document.getElementById('{BLUR_ID}');if(s)s.remove();}})()"
            ));
        }
        let r = r?;
        crate::b64::decode(r["data"].as_str().unwrap_or("")).map_err(|e| bad("failed", e))
    }

    fn blur_secrets(&mut self) -> R<()> {
        let page = self.page_facts()?;
        let idxs: Vec<u32> = page
            .forms
            .iter()
            .flat_map(|f| f.fields.iter())
            .filter(|f| f.is_secret() || f.is_payment())
            .map(|f| f.idx)
            .collect();
        let sel: Vec<String> = idxs
            .iter()
            .map(|i| format!("[data-ozi=\"{i}\"]"))
            .chain([
                "input[type=password]".to_string(),
                "[data-secret]".to_string(),
            ])
            .collect();
        let css = format!("{} {{ filter: blur(9px) !important; }}", sel.join(","));
        self.eval(&format!(
            "(function(c){{var s=document.getElementById('{BLUR_ID}')||document.head.appendChild(document.createElement('style'));s.id='{BLUR_ID}';s.textContent=c;}})({})",
            json!(css)
        ))?;
        Ok(())
    }

    /// A dialog the page opened that waits for the person who holds the session.
    pub fn dialog(&self) -> Option<Value> {
        self.shared().dialog.clone()
    }

    /// A picture of the active tab. The tab is brought to the front first: a page that opened a window of its own may have
    /// put that one in front, and a tab that is not in front draws no new frames, so the picture would never come.
    fn capture(&mut self, params: Value) -> R<Value> {
        self.send("Page.bringToFront", json!({}))?;
        self.send("Page.captureScreenshot", params)
    }

    /// The live view: a small JPEG of the active tab, and where the page is. While a dialog waits for the person, the last
    /// picture is shown with it (the page cannot be drawn under a dialog).
    pub fn frame(&mut self) -> R<(Vec<u8>, String)> {
        self.service();
        if self.dialog().is_some() {
            if let Some(f) = &self.last_frame {
                return Ok(f.clone());
            }
        }
        let m = self.device.metrics();
        let scale = if m.width > 700 { 0.7 } else { 1.0 };
        let r = self.capture(
            json!({ "format": "jpeg", "quality": 45, "clip": { "x": 0, "y": 0, "width": m.width, "height": m.height, "scale": scale } }),
        )?;
        let bytes =
            crate::b64::decode(r["data"].as_str().unwrap_or("")).map_err(|e| bad("failed", e))?;
        let page = crate::record::page_of(&self.url());
        self.last_frame = Some((bytes.clone(), page.clone()));
        Ok((bytes, page))
    }

    /// A person's input from the live view, in page coordinates.
    pub fn input(&mut self, ev: &Value) -> R<()> {
        let num = |k: &str| {
            ev[k]
                .as_f64()
                .filter(|v| v.is_finite() && v.abs() < 20000.0)
        };
        match ev["t"].as_str() {
            Some("dialog") => {
                let accept = ev["accept"].as_bool().unwrap_or(false);
                self.send("Page.handleJavaScriptDialog", json!({ "accept": accept }))?;
                self.shared().dialog = None;
            }
            Some("mouse") => {
                let kind = ev["kind"].as_str().unwrap_or("move");
                let (x, y) = (num("x").unwrap_or(0.0), num("y").unwrap_or(0.0));
                let ty = match kind {
                    "down" => "mousePressed",
                    "up" => "mouseReleased",
                    "wheel" => "mouseWheel",
                    _ => "mouseMoved",
                };
                let mut p = json!({ "type": ty, "x": x, "y": y, "button": if kind == "move" || kind == "wheel" { "none" } else { "left" }, "clickCount": u32::from(kind == "down" || kind == "up") });
                if kind == "wheel" {
                    p["deltaX"] = json!(num("dx").unwrap_or(0.0));
                    p["deltaY"] = json!(num("dy").unwrap_or(0.0));
                }
                self.send("Input.dispatchMouseEvent", p)?;
            }
            Some("key") => {
                let key = ev["key"].as_str().unwrap_or("");
                let evs = key_events(key).map_err(|m| bad("invalid", m))?;
                match ev["kind"].as_str() {
                    Some("down") => {
                        self.send("Input.dispatchKeyEvent", evs[0].clone())?;
                    }
                    Some("up") => {
                        self.send("Input.dispatchKeyEvent", evs[1].clone())?;
                    }
                    _ => {
                        for e in evs {
                            self.send("Input.dispatchKeyEvent", e)?;
                        }
                    }
                }
            }
            Some("text") => {
                let t = ev["text"].as_str().unwrap_or("");
                if t.len() <= 2000 {
                    self.send("Input.insertText", json!({ "text": t }))?;
                }
            }
            _ => return Err(bad("invalid", "that input is not understood")),
        }
        Ok(())
    }

    /// Where an upload's copy is made: inside the held-back folder, which only the worker's user can open.
    fn upload_stage_dir(&self) -> PathBuf {
        self.quarantine.join(".upload")
    }

    pub fn close(&mut self) {
        let _ = std::fs::remove_dir_all(self.upload_stage_dir());
        let _ = self.cdp.call(None, "Browser.close", json!({}));
        std::thread::sleep(Duration::from_millis(100));
        crate::cdp::kill_browser(&mut self.child);
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.quarantine.join(".upload"));
        crate::cdp::kill_browser(&mut self.child);
    }
}

fn v_is_not_textarea(t: &Target) -> bool {
    t.tag != "textarea"
}

pub fn valid_ref(r: &str) -> bool {
    r.len() <= 8 && r.starts_with('e') && r.len() > 1 && r[1..].chars().all(|c| c.is_ascii_digit())
}

fn check_scheme(url: &str) -> R<()> {
    if url.starts_with("http://") || url.starts_with("https://") {
        if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(bad("invalid", "that is not a usable address"));
        }
        if url
            .split("://")
            .nth(1)
            .unwrap_or("")
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .contains('@')
        {
            return Err(bad(
                "invalid",
                "an address with a name and password in it cannot be opened",
            ));
        }
        if detect::classify_host(&detect::host_of(url)) == detect::HostClass::Invalid {
            return Err(bad(
                "invalid",
                "that address has no usable host: write a name that is not in Latin letters in its xn-- form",
            ));
        }
        Ok(())
    } else {
        Err(bad(
            "invalid",
            "only http and https addresses can be opened",
        ))
    }
}

pub fn sanitize_name(n: &str) -> String {
    let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
    let s: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_matches('.').trim().to_string();
    if s.is_empty() {
        return "download".into();
    }
    let s: String = s.chars().take(120).collect();
    // names some systems keep for devices are given a prefix, so the file can be copied anywhere
    let stem = s.split('.').next().unwrap_or("").to_ascii_lowercase();
    let reserved = matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        format!("_{s}")
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_become_press_and_release_events() {
        let e = key_events("Enter").unwrap();
        assert_eq!(e[0]["type"], "keyDown");
        assert_eq!(e[0]["text"], "\r");
        assert_eq!(e[1]["type"], "keyUp");
        let c = key_events("Control+a").unwrap();
        assert_eq!(c[0]["modifiers"], 2);
        assert_eq!(c[0]["type"], "rawKeyDown");
        assert!(c[0].get("text").is_none());
        assert_eq!(key_events("a").unwrap()[0]["text"], "a");
        assert!(key_events("Hyper+x").is_err());
        assert!(key_events("F99").is_err());
    }

    #[test]
    fn element_names_are_checked() {
        assert!(valid_ref("e1") && valid_ref("e120"));
        assert!(
            !valid_ref("e")
                && !valid_ref("x1")
                && !valid_ref("e1;alert(1)")
                && !valid_ref("e123456789")
        );
    }

    #[test]
    fn only_web_addresses_without_credentials_open() {
        assert!(check_scheme("https://example.com/a").is_ok());
        assert!(check_scheme("file:///etc/passwd").is_err());
        assert!(check_scheme("javascript:alert(1)").is_err());
        assert!(check_scheme("https://u:p@example.com/").is_err());
        assert!(check_scheme("https://a b/").is_err());
        assert!(check_scheme("https://ex\u{0430}mple.com/").is_err());
        assert!(check_scheme("data:text/html,x").is_err());
    }

    #[test]
    fn download_names_lose_their_paths() {
        assert_eq!(sanitize_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_name("a b?.pdf"), "a b_.pdf");
        assert_eq!(sanitize_name("..."), "download");
        assert_eq!(sanitize_name(".bashrc"), "bashrc");
        assert_eq!(sanitize_name("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_name("COM1"), "_COM1");
        assert_eq!(sanitize_name("console.log"), "console.log");
        assert_eq!(sanitize_name(&"é".repeat(300)).chars().count(), 120);
    }

    #[test]
    fn the_snapshot_masks_secrets_and_patterns_and_names_every_element() {
        let raw = json!({
            "url": "https://a.example/login?token=SENTINEL-url", "title": "Sign in",
            "items": [
                { "k": "h", "level": 1, "text": "Welcome" },
                { "k": "t", "text": "Pay with 4111 1111 1111 1111 or call" },
                { "k": "el", "ref": "e1", "tag": "input", "type": "text", "name": "Email", "field": "email", "ac": "", "mark": false, "value": "ada@example.com" },
                { "k": "el", "ref": "e2", "tag": "input", "type": "password", "name": "Password", "field": "password", "ac": "", "mark": false },
                { "k": "el", "ref": "e3", "tag": "input", "type": "text", "name": "Token", "field": "api_token", "ac": "", "mark": false, "value": "SENTINEL-abc" },
                { "k": "el", "ref": "e4", "tag": "button", "type": "submit", "name": "Sign in", "field": "", "ac": "", "mark": false },
                { "k": "el", "ref": "e5", "tag": "a", "type": "", "name": "Help", "field": "", "ac": "", "mark": false, "href": "/help" },
                { "k": "el", "ref": "e6", "tag": "select", "type": "", "name": "Plan", "field": "plan", "ac": "", "mark": false, "value": "Free", "options": ["Free", "Pro"] }
            ]
        });
        let t = render_snapshot(&raw);
        assert!(!t.contains("SENTINEL"), "{t}");
        assert!(!t.contains("4111"), "{t}");
        assert!(t.contains("Page: Sign in (a.example/login)"), "{t}");
        assert!(t.contains("# Welcome"));
        assert!(
            t.contains("[e1 textbox \"Email\" value=\"ada@example.com\"]"),
            "{t}"
        );
        assert!(
            t.contains("[e2 password \"Password\" value=\"[masked]\"]"),
            "{t}"
        );
        assert!(
            t.contains("[e3 textbox \"Token\" value=\"[masked]\"]"),
            "{t}"
        );
        assert!(t.contains("[e4 button \"Sign in\"]"));
        assert!(t.contains("[e5 link \"Help\" -> /help]"));
        assert!(t.contains("options=[Free | Pro]"));
    }
}
