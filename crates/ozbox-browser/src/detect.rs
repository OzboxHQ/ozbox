//! Judging an action before it happens. The page is read into plain facts by a script in the page; the
//! decisions here are pure so they are tested on fixtures and behave the same on every box.
//!
//! The order of seriousness: a CAPTCHA or bot check (a person must do it, always), a purchase or payment (refused for the
//! agent unless the owner allows it, then approved every time), sending or posting (approved), submitting a form on a site not
//! marked safe (approved), a domain not on the allow-list (asked about first).

use serde::{Deserialize, Serialize};

use crate::mask;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub autocomplete: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub idx: u32,
    #[serde(default)]
    pub secret_mark: bool,
    /// The current value, as read from the page. Masked before it leaves the worker: see [`Field::shown`].
    #[serde(default)]
    pub value: String,
}

impl Field {
    pub fn is_secret(&self) -> bool {
        mask::is_secret_field(&self.kind, &self.name, &self.autocomplete, self.secret_mark)
    }
    /// What a person is shown for this field. A secret field is always shown as masked: the page script does not even read it.
    pub fn shown(&self) -> String {
        if self.is_secret() {
            mask::MASKED.to_string()
        } else {
            mask::mask_text(&self.value)
        }
    }
    pub fn is_payment(&self) -> bool {
        let ac = self.autocomplete.to_ascii_lowercase();
        let n = self.name.to_ascii_lowercase();
        ac.starts_with("cc-")
            || [
                "cardnumber",
                "card_number",
                "card-number",
                "cvv",
                "cvc",
                "ccnum",
                "cc_number",
                "cc-number",
                "expiry",
                "card_exp",
            ]
            .iter()
            .any(|k| n.contains(k))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Form {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub fields: Vec<Field>,
}

/// What the page script reports about the page as a whole.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub url: String,
    #[serde(default)]
    pub title: String,
    /// The visible text, lower-cased and cut short: enough to recognise a challenge or a checkout.
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub frames: Vec<String>,
    /// Class names and ids that mark challenge widgets.
    #[serde(default)]
    pub markers: Vec<String>,
    #[serde(default)]
    pub forms: Vec<Form>,
}

/// What the page script reports about the element an action is aimed at.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    #[serde(default)]
    pub tag: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub href: String,
    /// Index into [`Page::forms`] of the form this element would submit, if any.
    #[serde(default)]
    pub form: Option<usize>,
    #[serde(default)]
    pub secret: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    None,
    NewDomain,
    Submit,
    /// Putting a local file into a page: it leaves the box for the page's site.
    Upload,
    /// Opening a downloaded program or script.
    Program,
    Send,
    Payment,
    /// An address inside the box's own network that is not its loopback (a private range, link-local, the cloud metadata
    /// address): refused for the agent.
    Internal,
    Captcha,
}

impl Risk {
    pub fn word(self) -> &'static str {
        match self {
            Risk::None => "none",
            Risk::NewDomain => "new_domain",
            Risk::Submit => "submit",
            Risk::Upload => "upload",
            Risk::Program => "program",
            Risk::Send => "send",
            Risk::Payment => "payment",
            Risk::Internal => "internal",
            Risk::Captcha => "captcha",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    pub risk: Risk,
    pub host: String,
    pub reason: String,
    /// Fields that would be sent, with values masked where the field is secret or the value looks sensitive.
    #[serde(default)]
    pub fields: Vec<(String, String)>,
    /// Where it would go: the host and path a form is sent to, a link's host, a file's place. Shown on the approval, so a
    /// page that changes where a form goes changes what a person approves.
    #[serde(default)]
    pub dest: String,
    /// What the action was aimed at when it was judged (see [`fingerprint`]). The worker judges again before it acts and
    /// refuses an approval whose fingerprint no longer matches.
    #[serde(default)]
    pub fingerprint: String,
}

impl Assessment {
    pub fn none(host: &str) -> Self {
        Self {
            risk: Risk::None,
            host: host.to_string(),
            reason: String::new(),
            fields: Vec::new(),
            dest: String::new(),
            fingerprint: String::new(),
        }
    }

    pub fn with(risk: Risk, host: &str, reason: &str) -> Self {
        Self {
            risk,
            reason: reason.to_string(),
            ..Self::none(host)
        }
    }
}

/// A short, stable digest of what an action is aimed at. Any change to a part changes it.
pub fn fingerprint(parts: &[&str]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for p in parts {
        ctx.update(&(p.len() as u64).to_be_bytes());
        ctx.update(p.as_bytes());
    }
    ctx.finish().as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A field name as it may appear on an approval: no separators a reader could mistake for structure, and short.
pub fn clean_name(n: &str) -> String {
    let s: String = n
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| {
            if matches!(c, '=' | ',' | '[' | ']' | '{' | '}') {
                '_'
            } else {
                c
            }
        })
        .take(40)
        .collect();
    s.trim().to_string()
}

/// The host of an address, normalised: lower case, without a trailing dot, without a name and password, without brackets.
/// A `data:`, `blob:` or `about:` address has no host (an empty string): it is never on a list.
pub fn host_of(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return String::new();
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return String::new();
    }
    let auth = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or(auth);
    let h = if let Some(v6) = auth.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        auth.split(':').next().unwrap_or("")
    };
    normal_host(h)
}

/// Lower case and no trailing dot, so `Example.COM.` and `example.com` are the same site.
pub fn normal_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// What kind of place a host is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostClass {
    /// This box itself: `localhost`, `127.0.0.0/8`, `::1`.
    Loopback,
    /// Inside a private network but not this box: refused for the agent.
    Internal,
    /// A name or address on the internet.
    Public,
    /// Not usable: empty, not ASCII, or with characters a host never has.
    Invalid,
}

/// IPv4 the way browsers read a host: up to four parts, each decimal, `0x` hex or `0`-led octal, so `2130706433`,
/// `0x7f.1` and `0177.0.0.1` are all `127.0.0.1`.
fn legacy_ipv4(h: &str) -> Option<std::net::Ipv4Addr> {
    let parts: Vec<&str> = h.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let mut nums = Vec::new();
    for p in &parts {
        let v = if let Some(x) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if x.is_empty() {
                0
            } else {
                u64::from_str_radix(x, 16).ok()?
            }
        } else if p.len() > 1 && p.starts_with('0') {
            u64::from_str_radix(&p[1..], 8).ok()?
        } else {
            p.parse::<u64>().ok()?
        };
        nums.push(v);
    }
    let last = *nums.last()?;
    let lead = &nums[..nums.len() - 1];
    if lead.iter().any(|v| *v > 255) || last >= 1u64 << (8 * (5 - nums.len())) {
        return None;
    }
    let mut n: u64 = last;
    for (i, v) in lead.iter().enumerate() {
        n |= v << (8 * (3 - i));
    }
    u32::try_from(n).ok().map(std::net::Ipv4Addr::from)
}

fn class_v4(ip: std::net::Ipv4Addr) -> HostClass {
    let o = ip.octets();
    if o[0] == 127 {
        HostClass::Loopback
    } else if o[0] == 0
        || o[0] == 10
        || (o[0] == 172 && (16..32).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || o[0] >= 224
    {
        HostClass::Internal
    } else {
        HostClass::Public
    }
}

/// Sort a (normalised) host into [`HostClass`]. Names that a resolver might point at a private address are `Public` here:
/// they ask as a new domain, like any other site not on the list.
pub fn classify_host(host: &str) -> HostClass {
    let h = normal_host(host);
    if h.is_empty()
        || !h.is_ascii()
        || h.chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '%' | '\\' | '@' | '/'))
    {
        return HostClass::Invalid;
    }
    if h == "localhost" {
        return HostClass::Loopback;
    }
    if let Ok(v6) = h.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() {
            return HostClass::Loopback;
        }
        if let Some(v4) = v6.to_ipv4_mapped() {
            return class_v4(v4);
        }
        let s = v6.segments();
        return if v6.is_unspecified()
            || (s[0] & 0xfe00) == 0xfc00
            || (s[0] & 0xffc0) == 0xfe80
            || (s[0] & 0xff00) == 0xff00
        {
            HostClass::Internal
        } else {
            HostClass::Public
        };
    }
    if h.chars()
        .all(|c| c.is_ascii_hexdigit() || c == '.' || c == 'x' || c == 'X')
    {
        if let Some(v4) = legacy_ipv4(&h) {
            return class_v4(v4);
        }
    }
    HostClass::Public
}

pub fn is_loopback(host: &str) -> bool {
    classify_host(host) == HostClass::Loopback
}

/// `example.com` matches itself; `*.example.com` matches its subdomains and itself. Both sides are normalised first.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let p = normal_host(pattern);
    let host = normal_host(host);
    if let Some(base) = p.strip_prefix("*.") {
        host == base || host.ends_with(&format!(".{base}"))
    } else {
        host == p
    }
}

pub fn host_in(list: &[String], host: &str) -> bool {
    list.iter().any(|p| host_matches(p, host))
}

const CAPTCHA_FRAMES: [&str; 8] = [
    "recaptcha",
    "hcaptcha",
    "challenges.cloudflare.com",
    "turnstile",
    "arkoselabs",
    "funcaptcha",
    "geetest",
    "captcha-delivery",
];
const CAPTCHA_MARKERS: [&str; 7] = [
    "g-recaptcha",
    "h-captcha",
    "cf-turnstile",
    "captcha",
    "px-captcha",
    "challenge-form",
    "arkose",
];
const CAPTCHA_TEXT: [&str; 9] = [
    "verify you are human",
    "verify you're human",
    "i'm not a robot",
    "i am not a robot",
    "are you a robot",
    "unusual traffic",
    "checking your browser before accessing",
    "confirm you are human",
    "press and hold to verify",
];

/// A CAPTCHA or a bot check: never solved, always handed to a person.
pub fn captcha(page: &Page) -> Option<String> {
    let text = page.text.to_ascii_lowercase();
    if let Some(f) = page.frames.iter().find(|f| {
        let l = f.to_ascii_lowercase();
        CAPTCHA_FRAMES.iter().any(|k| l.contains(k))
    }) {
        return Some(format!("a challenge widget from {}", host_of(f)));
    }
    if page.markers.iter().any(|m| {
        let l = m.to_ascii_lowercase();
        CAPTCHA_MARKERS.iter().any(|k| l.contains(k))
    }) {
        return Some("a challenge widget on the page".into());
    }
    if CAPTCHA_TEXT.iter().any(|t| text.contains(t)) {
        return Some("the page asks to prove you are human".into());
    }
    None
}

const PAY_WORDS: [&str; 10] = [
    "place order",
    "pay now",
    "complete purchase",
    "complete order",
    "buy now",
    "confirm payment",
    "confirm order",
    "purchase",
    "subscribe and pay",
    "checkout",
];
const SEND_WORDS: [&str; 14] = [
    "send",
    "post",
    "publish",
    "tweet",
    "reply",
    "share",
    "comment",
    "submit message",
    "send message",
    "message",
    "email",
    "dm",
    "broadcast",
    "announce",
];

fn has_word(text: &str, words: &[&str]) -> bool {
    let t = text.to_ascii_lowercase();
    t.split(|c: char| !c.is_ascii_alphanumeric() && c != '\'')
        .any(|w| words.iter().any(|x| !x.contains(' ') && *x == w))
        || words.iter().any(|x| x.contains(' ') && t.contains(x))
}

/// The page is a checkout: a path that says so, card fields, or payment wording on a form.
pub fn payment_page(page: &Page) -> bool {
    let path = page
        .url
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let path_hit = [
        "/checkout",
        "/payment",
        "/pay/",
        "/pay",
        "/billing/pay",
        "/purchase",
        "/order/confirm",
    ]
    .iter()
    .any(|k| path.contains(k));
    let card_fields = page
        .forms
        .iter()
        .any(|f| f.fields.iter().any(Field::is_payment));
    path_hit || card_fields
}

/// Known apps whose compose or reply screens send mail or post publicly, by path.
fn known_send_surface(url: &str) -> bool {
    let h = host_of(url);
    let p = url.to_ascii_lowercase();
    (h.ends_with("mail.google.com") && p.contains("compose"))
        || h.ends_with("outlook.office.com")
        || h.ends_with("outlook.live.com")
        || h.ends_with("linkedin.com") && p.contains("/feed")
        || h == "x.com"
        || h.ends_with("twitter.com")
        || h.ends_with("facebook.com")
        || h.ends_with("web.whatsapp.com")
        || h.ends_with("slack.com")
}

fn form_fields(page: &Page, idx: Option<usize>) -> Vec<(String, String)> {
    idx.and_then(|i| page.forms.get(i))
        .map(|f| {
            f.fields
                .iter()
                .filter(|x| {
                    !x.name.is_empty()
                        && x.kind != "hidden"
                        && x.kind != "submit"
                        && x.kind != "button"
                })
                .map(|x| (x.name.clone(), x.shown()))
                .collect()
        })
        .unwrap_or_default()
}

/// Is this click or key press about to send something? `submit` is true when the action itself submits a form (a submit
/// button, Enter in a field).
pub fn assess_activation(
    page: &Page,
    target: &Target,
    submit: bool,
    safe_sites: &[String],
) -> Assessment {
    let host = host_of(&page.url);
    let label = format!("{} {}", target.text, target.name);
    let on_payment_page = payment_page(page);
    let form = target.form.and_then(|i| page.forms.get(i));
    let form_has_card = form.is_some_and(|f| f.fields.iter().any(Field::is_payment));
    let pay_label = has_word(&label, &PAY_WORDS);
    // where a submit goes: the form's action (an empty action posts back to the page itself)
    let dest_url = form
        .map(|f| f.action.clone())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| page.url.clone());
    let dest = crate::record::page_of(&dest_url);
    let dest_host = host_of(&dest_url);
    let fp = fingerprint(&[
        &crate::record::page_of(&page.url),
        &target.tag,
        &target.kind,
        &target.text,
        &target.name,
        &target.href,
        &dest,
        &form
            .map(|f| f.method.to_ascii_lowercase())
            .unwrap_or_default(),
        &form
            .map(|f| {
                f.fields
                    .iter()
                    .map(|x| format!("{}:{}", x.name, x.kind))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default(),
    ]);
    let mk = |risk: Risk, why: &str| Assessment {
        risk,
        host: host.clone(),
        reason: why.to_string(),
        fields: form_fields(page, target.form),
        dest: dest.clone(),
        fingerprint: fp.clone(),
    };
    let none = || Assessment {
        fingerprint: fp.clone(),
        ..Assessment::none(&host)
    };
    if let Some(why) = captcha(page) {
        return mk(Risk::Captcha, &why);
    }
    // a payment: a card form, or a pay-worded button on a checkout; a bare link to a checkout is only navigation
    if (submit || target.tag == "button" || target.kind == "submit")
        && (form_has_card
            || (on_payment_page && (pay_label || submit))
            || (pay_label && on_payment_page))
    {
        return mk(Risk::Payment, "this would pay or place an order");
    }
    if (submit || target.kind == "submit" || target.tag == "button")
        && has_word(&label, &SEND_WORDS)
    {
        return mk(Risk::Send, "this would send a message or post something");
    }
    if submit && known_send_surface(&page.url) {
        return mk(Risk::Send, "this would send or post in a messaging app");
    }
    if submit {
        // a page that is not a web address (data:, blob:, about:) has no site to be safe, and a form that goes to another
        // site than the page's is never covered by the page's site being safe
        if !host.is_empty() && dest_host == host && host_in(safe_sites, &host) {
            return none();
        }
        if !dest_host.is_empty() && dest_host != host {
            return mk(Risk::Submit, "this would send a form to another site");
        }
        return mk(Risk::Submit, "this would submit a form");
    }
    none()
}

/// Going to an address: a host that is not this box's own loopback and not on the project's allow-list asks first; an address
/// inside the box's network that is not its loopback is refused.
pub fn assess_navigation(url: &str, allowed: &[String]) -> Assessment {
    let host = host_of(url);
    let mut a = match classify_host(&host) {
        HostClass::Loopback => Assessment::none(&host),
        HostClass::Internal => Assessment::with(
            Risk::Internal,
            &host,
            "this address is inside the box's network, not on the internet",
        ),
        _ if host_in(allowed, &host) => Assessment::none(&host),
        _ => Assessment::with(
            Risk::NewDomain,
            &host,
            "this site is not on the project's browser allow-list",
        ),
    };
    a.dest = host.clone();
    a.fingerprint = fingerprint(&["navigate", &host]);
    a
}

/// Whether a method only reads.
pub fn reads_only(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET")
        || method.eq_ignore_ascii_case("HEAD")
        || method.eq_ignore_ascii_case("OPTIONS")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payments {
    Refuse,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Allow,
    /// Wait for a person's approval before it runs.
    Ask,
    Refuse(String),
    /// A person must do this themselves: pause and hand over.
    Handoff(String),
}

/// What to do about a risk. The safe-site rule has already been applied by the assessment.
pub fn gate(risk: Risk, payments: Payments) -> Gate {
    match risk {
        Risk::None => Gate::Allow,
        Risk::NewDomain | Risk::Submit | Risk::Upload | Risk::Program | Risk::Send => Gate::Ask,
        Risk::Internal => Gate::Refuse(
            "Addresses inside the box's network (other than the box itself) are not opened by an agent.".into(),
        ),
        Risk::Payment => match payments {
            Payments::Refuse => Gate::Refuse(
                "Payments and purchases are not made by an agent. Ask the person to take over the browser and pay themselves."
                    .into(),
            ),
            Payments::Ask => Gate::Ask,
        },
        Risk::Captcha => Gate::Handoff(
            "This page asks to prove you are human. Oz Box never solves these: a person has to take over the browser, then hand it back."
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, kind: &str, value: &str) -> Field {
        Field {
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
            ..Field::default()
        }
    }

    fn page(url: &str, text: &str, forms: Vec<Form>) -> Page {
        Page {
            url: url.into(),
            text: text.into(),
            forms,
            ..Page::default()
        }
    }

    fn submit_btn(text: &str, form: usize) -> Target {
        Target {
            tag: "button".into(),
            kind: "submit".into(),
            text: text.into(),
            form: Some(form),
            ..Target::default()
        }
    }

    #[test]
    fn hosts_are_read_from_urls() {
        assert_eq!(
            host_of("https://User:pw@Example.COM:8443/a?b#c"),
            "example.com"
        );
        assert_eq!(host_of("http://[::1]:3000/x"), "::1");
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "badexample.com"));
        assert!(!host_matches("example.com", "evil-example.com"));
    }

    #[test]
    fn a_challenge_is_recognised_by_frame_marker_or_words() {
        let mut p = page("https://x.example/", "welcome", vec![]);
        assert!(captcha(&p).is_none());
        p.frames = vec!["https://www.google.com/recaptcha/api2/anchor".into()];
        assert!(captcha(&p).unwrap().contains("google.com"));
        let mut p = page("https://x.example/", "welcome", vec![]);
        p.markers = vec!["cf-turnstile".into()];
        assert!(captcha(&p).is_some());
        let p = page(
            "https://x.example/",
            "please verify you are human to continue",
            vec![],
        );
        assert!(captcha(&p).is_some());
        let p = page("https://x.example/", "I'm not a robot", vec![]);
        assert!(captcha(&p).is_some());
    }

    #[test]
    fn a_captcha_page_hands_off_even_for_a_plain_click() {
        let p = page("https://x.example/", "verify you are human", vec![]);
        let a = assess_activation(
            &p,
            &Target {
                tag: "a".into(),
                text: "continue".into(),
                ..Target::default()
            },
            false,
            &[],
        );
        // the challenge outranks everything: any action on the page is handed to a person
        assert_eq!(a.risk, Risk::Captcha);
        let a = assess_activation(&p, &submit_btn("Continue", 0), true, &[]);
        assert_eq!(a.risk, Risk::Captcha);
        assert!(matches!(
            gate(Risk::Captcha, Payments::Ask),
            Gate::Handoff(_)
        ));
    }

    #[test]
    fn a_checkout_is_a_payment_by_path_by_card_field_or_by_button() {
        let card = Form {
            fields: vec![
                field("cardnumber", "text", "4111111111111111"),
                field("name", "text", "A B"),
            ],
            ..Form::default()
        };
        let p = page("https://shop.example/cart", "your cart", vec![card.clone()]);
        assert!(payment_page(&p));
        let a = assess_activation(&p, &submit_btn("Continue", 0), true, &[]);
        assert_eq!(a.risk, Risk::Payment);
        // the card number is masked in what a person is shown, and shown as masked because the field is a card field
        let shown: Vec<_> = a.fields.iter().filter(|(n, _)| n == "cardnumber").collect();
        assert_eq!(shown[0].1, mask::MASKED);
        let p = page(
            "https://shop.example/checkout",
            "order summary",
            vec![Form {
                fields: vec![field("note", "text", "")],
                ..Form::default()
            }],
        );
        let a = assess_activation(&p, &submit_btn("Place order", 0), true, &[]);
        assert_eq!(a.risk, Risk::Payment);
        // a safe site does not exempt a payment
        let a = assess_activation(
            &p,
            &submit_btn("Place order", 0),
            true,
            &["shop.example".into()],
        );
        assert_eq!(a.risk, Risk::Payment);
        assert!(matches!(
            gate(Risk::Payment, Payments::Refuse),
            Gate::Refuse(_)
        ));
        assert_eq!(gate(Risk::Payment, Payments::Ask), Gate::Ask);
    }

    #[test]
    fn sending_and_posting_is_found_by_the_button_and_by_known_apps() {
        let f = Form {
            fields: vec![field("body", "textarea", "hello")],
            ..Form::default()
        };
        let p = page("https://forum.example/thread/1", "reply", vec![f.clone()]);
        assert_eq!(
            assess_activation(&p, &submit_btn("Post reply", 0), true, &[]).risk,
            Risk::Send
        );
        assert_eq!(
            assess_activation(&p, &submit_btn("Send message", 0), false, &[]).risk,
            Risk::Send
        );
        // sending is not exempted by a safe site
        assert_eq!(
            assess_activation(&p, &submit_btn("Send", 0), true, &["forum.example".into()]).risk,
            Risk::Send
        );
        let p = page(
            "https://mail.google.com/mail/u/0/#compose",
            "new message",
            vec![f],
        );
        let plain = Target {
            tag: "div".into(),
            text: "Go".into(),
            form: Some(0),
            ..Target::default()
        };
        assert_eq!(assess_activation(&p, &plain, true, &[]).risk, Risk::Send);
        // a word inside another word is not a send
        let p = page("https://x.example/", "", vec![Form::default()]);
        assert_eq!(
            assess_activation(&p, &submit_btn("Sender details", 0), true, &[]).risk,
            Risk::Submit
        );
    }

    #[test]
    fn a_form_submit_asks_unless_the_site_is_safe_and_shows_masked_values() {
        let f = Form {
            fields: vec![
                field("name", "text", "Ada"),
                field("password", "password", "SENTINEL-abc"),
                field("csrf", "hidden", "zzz"),
                field("note", "text", "card 4111 1111 1111 1111"),
            ],
            ..Form::default()
        };
        let p = page("https://app.example/profile", "profile", vec![f]);
        let a = assess_activation(&p, &submit_btn("Save", 0), true, &[]);
        assert_eq!(a.risk, Risk::Submit);
        let flat = format!("{:?}", a.fields);
        assert!(!flat.contains("SENTINEL"));
        assert!(!flat.contains("4111"));
        assert!(a.fields.contains(&("password".into(), mask::MASKED.into())));
        assert!(a.fields.contains(&("name".into(), "Ada".into())));
        assert!(!a.fields.iter().any(|(n, _)| n == "csrf"));
        let a = assess_activation(&p, &submit_btn("Save", 0), true, &["app.example".into()]);
        assert_eq!(a.risk, Risk::None);
        // a click that does not submit is free
        let link = Target {
            tag: "a".into(),
            text: "Help".into(),
            href: "/help".into(),
            ..Target::default()
        };
        assert_eq!(assess_activation(&p, &link, false, &[]).risk, Risk::None);
    }

    #[test]
    fn a_new_domain_asks_but_loopback_and_listed_hosts_do_not() {
        let allowed = vec!["example.com".to_string(), "*.docs.example.org".to_string()];
        assert_eq!(
            assess_navigation("http://localhost:8000/x", &allowed).risk,
            Risk::None
        );
        assert_eq!(
            assess_navigation("https://example.com/x", &allowed).risk,
            Risk::None
        );
        assert_eq!(
            assess_navigation("https://a.docs.example.org/", &allowed).risk,
            Risk::None
        );
        let a = assess_navigation("https://evil.test/", &allowed);
        assert_eq!(a.risk, Risk::NewDomain);
        assert_eq!(a.host, "evil.test");
        assert_eq!(gate(Risk::NewDomain, Payments::Refuse), Gate::Ask);
        assert_eq!(gate(Risk::None, Payments::Refuse), Gate::Allow);
    }

    #[test]
    fn hosts_are_normalised_and_box_internal_addresses_are_found_in_every_spelling() {
        assert_eq!(host_of("https://Example.COM./a"), "example.com");
        assert_eq!(host_of("data:text/html,<form>"), "");
        assert_eq!(host_of("blob:https://a.example/123"), "");
        assert_eq!(host_of("javascript:alert(1)"), "");
        assert!(host_matches("example.com", "EXAMPLE.com."));
        for h in [
            "localhost",
            "127.0.0.1",
            "127.0.0.2",
            "::1",
            "2130706433",
            "0x7f.1",
            "0177.0.0.1",
        ] {
            assert_eq!(classify_host(h), HostClass::Loopback, "{h}");
        }
        for h in [
            "10.0.0.1",
            "172.16.4.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::ffff:169.254.169.254",
            "fd00:ec2::254",
            "fe80::1",
            "::",
            "0xa9fea9fe",
        ] {
            assert_eq!(classify_host(h), HostClass::Internal, "{h}");
        }
        for h in ["example.com", "8.8.8.8", "a.localhost", "cafe.face"] {
            assert_eq!(classify_host(h), HostClass::Public, "{h}");
        }
        for h in ["", "exa mple.com", "ex\u{0430}mple.com", "a%2fb", "a\tb"] {
            assert_eq!(classify_host(h), HostClass::Invalid, "{h:?}");
        }
        let a = assess_navigation("http://169.254.169.254/latest/meta-data/", &[]);
        assert_eq!(a.risk, Risk::Internal);
        assert!(matches!(gate(a.risk, Payments::Ask), Gate::Refuse(_)));
        // a decimal loopback is the box itself, like 127.0.0.1
        assert_eq!(
            assess_navigation("http://2130706433:3000/", &[]).risk,
            Risk::None
        );
    }

    #[test]
    fn a_form_that_goes_to_another_site_is_never_covered_by_a_safe_site() {
        let f = Form {
            action: "https://collector.example/x".into(),
            method: "post".into(),
            fields: vec![field("q", "text", "hi")],
        };
        let p = page("https://app.example/search", "", vec![f]);
        let a = assess_activation(&p, &submit_btn("Go", 0), true, &["app.example".into()]);
        assert_eq!(a.risk, Risk::Submit);
        assert_eq!(a.dest, "collector.example/x");
        // the same form going back to its own safe site is free
        let mut own = p.clone();
        own.forms[0].action = "https://app.example/search".into();
        let b = assess_activation(&own, &submit_btn("Go", 0), true, &["app.example".into()]);
        assert_eq!(b.risk, Risk::None);
        // a page that is not a web address is never a safe site
        let mut blob = own.clone();
        blob.url = "about:blank".into();
        blob.forms[0].action = String::new();
        assert_eq!(
            assess_activation(&blob, &submit_btn("Go", 0), true, &["app.example".into()]).risk,
            Risk::Submit
        );
    }

    #[test]
    fn the_fingerprint_changes_when_the_target_or_where_it_goes_changes() {
        let f = Form {
            action: "https://app.example/save".into(),
            method: "post".into(),
            fields: vec![field("name", "text", "Ada")],
        };
        let p = page("https://app.example/profile", "", vec![f]);
        let a = assess_activation(&p, &submit_btn("Save", 0), true, &[]);
        assert_eq!(a.fingerprint.len(), 16);
        // the value typed does not change it: an approval covers the fields shown, which are on the approval
        let mut typed = p.clone();
        typed.forms[0].fields[0].value = "Bea".into();
        assert_eq!(
            assess_activation(&typed, &submit_btn("Save", 0), true, &[]).fingerprint,
            a.fingerprint
        );
        let mut moved = p.clone();
        moved.forms[0].action = "https://app.example/delete".into();
        assert_ne!(
            assess_activation(&moved, &submit_btn("Save", 0), true, &[]).fingerprint,
            a.fingerprint
        );
        assert_ne!(
            assess_activation(&p, &submit_btn("Delete", 0), true, &[]).fingerprint,
            a.fingerprint
        );
        assert_eq!(clean_name("a=b, [c]"), "a_b_ _c_");
    }

    #[test]
    fn risks_order_by_seriousness() {
        assert!(
            Risk::Captcha > Risk::Internal
                && Risk::Internal > Risk::Payment
                && Risk::Payment > Risk::Send
                && Risk::Send > Risk::Submit
                && Risk::Submit > Risk::NewDomain
        );
    }
}
