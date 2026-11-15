use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The provider-neutral size catalogue. Each provider adapter maps a size to its nearest machine type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Size {
    /// 4 vCPU / 8 GiB: the shape the hpc-sandbox-benchmarks leaderboard measures, and a lighter box for small projects. S
    /// (4 vCPU / 16 GiB) stays what it was, sized for building a large app.
    XS,
    S,
    M,
    L,
    XL,
    XXL,
    /// A GPU box. The GPU model is chosen per provider from [`GpuKind`].
    Gpu(GpuKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GpuKind {
    /// One inference-class GPU (~24 GB VRAM).
    Small,
    /// One large GPU (~80 GB VRAM).
    Large,
}

/// What a size promises. Adapters must pick a machine with AT LEAST these resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeSpec {
    pub vcpus: u32,
    pub memory_gb: u32,
    pub gpus: u32,
    pub gpu_memory_gb: u32,
}

impl Size {
    pub const STANDARD: [Size; 6] = [Size::XS, Size::S, Size::M, Size::L, Size::XL, Size::XXL];

    pub fn spec(self) -> SizeSpec {
        let (vcpus, memory_gb, gpus, gpu_memory_gb) = match self {
            Size::XS => (4, 8, 0, 0),
            Size::S => (4, 16, 0, 0),
            Size::M => (8, 32, 0, 0),
            Size::L => (8, 64, 0, 0),
            Size::XL => (16, 64, 0, 0),
            Size::XXL => (32, 128, 0, 0),
            Size::Gpu(GpuKind::Small) => (8, 32, 1, 24),
            Size::Gpu(GpuKind::Large) => (16, 128, 1, 80),
        };
        SizeSpec {
            vcpus,
            memory_gb,
            gpus,
            gpu_memory_gb,
        }
    }

    /// The next size up, used when a provider is out of capacity for the requested one.
    pub fn next_up(self) -> Option<Size> {
        match self {
            Size::XS => Some(Size::S),
            Size::S => Some(Size::M),
            Size::M => Some(Size::L),
            Size::L => Some(Size::XL),
            Size::XL => Some(Size::XXL),
            Size::XXL => None,
            Size::Gpu(GpuKind::Small) => Some(Size::Gpu(GpuKind::Large)),
            Size::Gpu(GpuKind::Large) => None,
        }
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Size::XS => f.write_str("XS"),
            Size::S => f.write_str("S"),
            Size::M => f.write_str("M"),
            Size::L => f.write_str("L"),
            Size::XL => f.write_str("XL"),
            Size::XXL => f.write_str("XXL"),
            Size::Gpu(GpuKind::Small) => f.write_str("GPU-S"),
            Size::Gpu(GpuKind::Large) => f.write_str("GPU-L"),
        }
    }
}

impl std::str::FromStr for Size {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "XS" => Ok(Size::XS),
            "S" => Ok(Size::S),
            "M" => Ok(Size::M),
            "L" => Ok(Size::L),
            "XL" => Ok(Size::XL),
            "XXL" => Ok(Size::XXL),
            "GPU-S" => Ok(Size::Gpu(GpuKind::Small)),
            "GPU-L" => Ok(Size::Gpu(GpuKind::Large)),
            _ => Err(Error::Config(format!(
                "unknown size {s:?}: use XS, XS, S, M, L, XL, XXL, GPU-S or GPU-L"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_matches_the_published_sizes() {
        assert_eq!(Size::S.spec().vcpus, 4);
        // XS is the benchmark shape, and S did not shrink to make room for it.
        assert_eq!((Size::XS.spec().vcpus, Size::XS.spec().memory_gb), (4, 8));
        assert_eq!((Size::S.spec().vcpus, Size::S.spec().memory_gb), (4, 16));
        assert_eq!(Size::L.spec().memory_gb, 64);
        assert_eq!(Size::XXL.spec().memory_gb, 128);
    }

    #[test]
    fn standard_sizes_never_shrink_going_up() {
        for w in Size::STANDARD.windows(2) {
            let (a, b) = (w[0].spec(), w[1].spec());
            assert!(
                b.vcpus >= a.vcpus && b.memory_gb >= a.memory_gb,
                "{} -> {}",
                w[0],
                w[1]
            );
            assert_eq!(w[0].next_up(), Some(w[1]));
        }
    }

    #[test]
    fn parses_round_trip() {
        for s in [Size::XS, Size::S, Size::XXL, Size::Gpu(GpuKind::Small)] {
            assert_eq!(s.to_string().parse::<Size>().ok(), Some(s));
        }
        assert!("huge".parse::<Size>().is_err());
    }
}
