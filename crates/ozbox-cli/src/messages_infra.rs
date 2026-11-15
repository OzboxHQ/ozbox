//! Messages about the box modules and first-boot configuration the program renders (English first), looked up by
//! `messages::t`.

pub const EN: &[(&str, &str)] = &[
    ("infra.ignored_module_dir", "warning: {dir} (module_dir under [{section}]) is not this program's copy of the box modules (its files differ: first boot {theirs}, this program {ours}). It is not used: this program renders its own copy, {used}, so a box gets the first-boot configuration of version {version}. Remove module_dir from the config; to use that folder on purpose while developing, set dev_modules = true under [{section}] or pass --dev-modules."),
    ("infra.missing_module_dir", "warning: {dir} (module_dir under [{section}]) is not a box module folder ({why}). It is not used: this program renders its own copy, {used}. Remove module_dir from the config."),
    ("infra.dev_note", "DEVELOPER MODULES: boxes are rendered from {dir} (first boot {theirs}), not from this program's own copy (first boot {ours}, version {version}). Set by --dev-modules or dev_modules = true."),
    ("infra.dev_warning", "warning: using the developer modules at {dir} (first boot {theirs}) instead of this program's own (first boot {ours})."),
    ("infra.extract_failed", "This program's copy of the box modules could not be written to {dir}: {why}. Set OZBOX_INFRA_DIR to a folder you can write, and run the command again."),
    ("infra.no_home", "There is no folder to keep this program's box modules in: set OZBOX_INFRA_DIR (or HOME)."),
    ("infra.legacy_failed", "The box state kept inside {dir} could not be moved out of it before that folder stopped being used ({why}). Nothing was changed. Move it with an older ozbox, or set dev_modules = true to keep using that folder."),
    ("infra.dev_needs_dir", "--dev-modules needs module_dir under [{section}] in the config: the folder of the box module to use."),
    ("upgrade.first_boot_match", "First boot: the image's signed release was built with the same first-boot configuration as this program ({hash})."),
    ("upgrade.first_boot_unrecorded", "First boot: the image's release does not record which first-boot configuration it was built with (releases before 0.1.1 do not), so it cannot be compared with this program's ({hash})."),
    ("upgrade.err_first_boot_mismatch", "Refusing to use image {image}: its release {release} was built with a different first-boot configuration ({theirs}) than this program renders ({ours}). The program and the image must come from the same release: use the image of this program's release, or the program of the image's. Nothing was changed. Pass --allow-first-boot-mismatch to go ahead anyway."),
    ("upgrade.first_boot_overridden", "WARNING: image {image} (release {release}) was built with a different first-boot configuration ({theirs}) than this program renders ({ours}). Going ahead because --allow-first-boot-mismatch was given."),
    ("upgrade.stale_box", "{box} is on image {image} already, but its machine was made with another first-boot configuration ({theirs}, as the provider records it) than this program renders ({ours}). This replaces its machine from the same image so it boots with this program's configuration; /work is kept."),
    ("upgrade.stale_unrecorded", "{box} is on image {image} already, but the provider has no record of which first-boot configuration its machine was made with (machines made before ozbox 0.1.1 have none). This replaces its machine from the same image so it boots with this program's configuration ({ours}); /work is kept."),
    ("upgrade.stale_disagrees", "{box} is on image {image} already, but what the box itself recorded at its first boot ({theirs}) does not match the provider's record ({ours}). This replaces its machine from the same image so it boots with this program's configuration; /work is kept."),
    ("upgrade.stale_malformed", "{box} is on image {image} already, but its answer about its first boot could not be read (more than one record, or not a hash). This replaces its machine from the same image so it boots with this program's configuration ({ours}); /work is kept."),
    ("upgrade.reprovision_asked", "{box} is on image {image} already; --reprovision replaces its machine from the same image so it boots with this program's first-boot configuration ({ours}); /work is kept."),
    ("upgrade.first_boot_current", "{box} was made with this program's first-boot configuration ({ours}), as the provider records it and the box confirms."),
    ("upgrade.first_boot_current_unconfirmed", "{box} was made with this program's first-boot configuration ({ours}), as the provider records it; the box could not be asked to confirm it ({why}). To replace its machine anyway, run the upgrade again with --reprovision."),
    ("upgrade.reprovision_after_finish", "{box} has an unfinished upgrade to this image: it is finished first, and --reprovision is not done in the same run. Run the upgrade again afterwards with --reprovision if its machine should still be replaced."),
    ("upgrade.first_boot_unrepairable", "{box}: which first-boot configuration it was made with cannot be checked or repaired by `ozbox upgrade` on this provider yet ({why}). Nothing about its first boot is changed by this upgrade."),
    ("upgrade.err_reprovision_unsupported", "Refusing --reprovision for {box}: this provider cannot replace a machine from the image it already runs ({why}). Nothing was changed. Run the upgrade without --reprovision to finish or apply an image upgrade."),
    ("upgrade.unrecorded", "none recorded"),
];
