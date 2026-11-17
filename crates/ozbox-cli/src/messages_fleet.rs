//! Messages for a fleet change made from a box's own dashboard (ADR 0040), English first, looked up by `messages::t`.

pub const EN: &[(&str, &str)] = &[
    ("fleet.this_box", "{box} is the box this dashboard runs on. Resize, pause, snapshot, clone or destroy it from your own computer with the ozbox command line."),
    ("fleet.from_your_computer", "A box's dashboard can create, resize, pause, resume, snapshot, clone and destroy boxes. To {verb} a box, use the ozbox command line on your own computer."),
    ("fleet.plan_spent", "This plan was already applied. Nothing more was changed. Plan again for another change."),
    ("fleet.window_required", "This change needs a change window opened from your own computer for this exact plan. Nothing was changed."),
    ("fleet.window_expired", "The change window for this plan has ended. Nothing was changed. Open a new window from your own computer, then try again."),
    ("fleet.passkey_required", "Confirm this exact plan with your passkey. An authenticator code or a computer's key is not accepted for a fleet change. Nothing was changed."),
    ("fleet.passkey_other_plan", "That passkey confirmation was for a different plan. Nothing was changed. Confirm this plan with your passkey."),
    ("fleet.owner_only", "Only the dashboard's owner can change the fleet. Nothing was changed."),
    ("fleet.sign_in_needed", "A fleet change from a box's dashboard needs a sign-in with a passkey. This dashboard has no sign-in, so it can only read."),
    ("fleet.holder_not_you", "The fleet credential holder does not answer this request."),
    ("fleet.holder_bad_request", "The fleet credential holder could not read that request. Nothing was changed."),
    ("fleet.holder_window_refused", "That change window was refused: it is not the owner's, not for this box and plan, or it was changed on the way. Nothing was changed."),
    ("fleet.holder_approvers_refused", "That list of people who may confirm fleet changes was not signed by your computer for this box. It was not used."),
    ("fleet.holder_approvers_old", "That list of people who may confirm fleet changes is older than the one already in use. It was not used."),
    ("fleet.holder_no_approvers", "No list of people who may confirm fleet changes has been sent from your computer yet. Sign one with `ozbox fleet approvers sign` and send it. Nothing was changed."),
    ("fleet.holder_storage", "The fleet credential holder could not record this plan as used, so it did not change anything."),
    ("fleet.holder_read_failed", "The fleet credential holder could not get a read session from the cloud."),
    ("fleet.holder_apply_failed", "The change did not finish. This plan is used up; plan again to retry. Check the box list for what was done."),
];
