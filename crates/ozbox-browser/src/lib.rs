//! The browser on the box (ADR 0037).
//!
//! A browsing session is one Chromium, started with `--remote-debugging-pipe` (so there is no listening port for anything to
//! find), owned by one long-lived worker process that speaks a one-line-in, one-line-out protocol on its standard input and
//! output. The tool host (`ozbox-cli`) is the only caller: every line after the first is sealed with a key only the two of
//! them hold ([`channel`]). It asks the worker to *preview* an action (what would it do, what kind of risk is it), decides it
//! through the permission engine, then tells the worker to *act*, with a person's grant when the action is risky. What the
//! page itself asks the browser to load or send is judged at its destination ([`gatekeep`]).
//!
//! Everything that is a judgement lives in pure modules that are tested on fixture text, on any OS: [`mask`] (what the model
//! may see), [`detect`] (forms, payments, sends, new domains, CAPTCHAs), [`gatekeep`] (the page's own requests), [`schema`] (structured extraction), [`robots`]
//! (site manners), [`policy`] (limits, devices, downloads), [`record`] (recording and retention). [`cdp`], [`driver`] and
//! [`worker`] are the parts that need a real Chromium.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod b64;
pub mod cdp;
pub mod channel;
pub mod detect;
pub mod driver;
pub mod gatekeep;
pub mod mask;
pub mod policy;
pub mod protocol;
pub mod record;
pub mod robots;
pub mod schema;
pub mod testsite;
pub mod upload_stage;
pub mod worker;
