//! Metrics: pure parsers ([`parse`]) and the sampler that turns `/proc` + cgroup readings into [`ozbox_core::MetricsSample`].

pub mod parse;
pub mod sampler;

pub use sampler::Sampler;
