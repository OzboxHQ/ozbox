//! The skills that ship inside Oz Box (the `skills/` folder of the repository), compiled in so they are there on every
//! computer. They are in the catalog like any other skill and are just as unusable until a person approves them.

use crate::skills::SkillPack;
use std::collections::BTreeMap;

macro_rules! skill {
    ($name:literal $(, $file:literal)*) => {
        (
            $name,
            &[
                ("SKILL.md", include_str!(concat!("../../../skills/", $name, "/SKILL.md"))),
                $(($file, include_str!(concat!("../../../skills/", $name, "/", $file))),)*
            ] as &[(&str, &str)],
        )
    };
}

const SKILLS: &[(&str, &[(&str, &str)])] = &[
    skill!("ci-failure-triage"),
    skill!("eval-runner"),
    skill!("keep-memory"),
    skill!("orchestrate-features"),
    skill!("release-runner"),
    skill!("reply-drafter"),
];

/// Every skill that ships with Oz Box.
pub fn bundled() -> Vec<SkillPack> {
    SKILLS
        .iter()
        .filter_map(|(_, files)| {
            let map: BTreeMap<String, Vec<u8>> = files
                .iter()
                .map(|(p, t)| ((*p).to_string(), t.as_bytes().to_vec()))
                .collect();
            SkillPack::from_files(map).ok()
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_skill_folder_in_the_repository_is_bundled_and_valid() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills");
        let mut on_disk: Vec<String> = std::fs::read_dir(repo)
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        on_disk.sort();
        let mut shipped: Vec<String> = bundled().into_iter().map(|p| p.name).collect();
        shipped.sort();
        assert_eq!(on_disk, shipped, "add the folder to SKILLS in bundled.rs");
        assert_eq!(SKILLS.len(), shipped.len(), "every shipped skill parses");
    }

    #[test]
    fn the_shipped_files_match_the_folders_byte_for_byte() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills");
        for p in bundled() {
            let from_disk = SkillPack::from_dir(&repo.join(&p.name)).unwrap();
            assert_eq!(
                from_disk.hash(),
                p.hash(),
                "{} has files the bundle does not list",
                p.name
            );
        }
    }
}
