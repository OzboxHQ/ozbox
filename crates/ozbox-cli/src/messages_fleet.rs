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
];
