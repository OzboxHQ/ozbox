//! Messages for `ozbox init`'s robustness checks: sign-in failures told apart, the address and NAT quota preflight, a
//! half-applied step's rollback, the shared provider pin, previews before the state bucket exists, `--only`/`--skip`, and the
//! merged operator policy. English first; looked up through [`crate::messages::t`].

pub const EN: &[(&str, &str)] = &[
    // sign-in: an AWS outage is never reported as a missing login, and each kind names its next step
    ("init.signin_unavailable", "AWS answered the sign-in check with a service error ({why}). This is a problem on AWS's side, not your login. Nothing was changed."),
    ("init.signin_unavailable_fix", "Check the AWS Health Dashboard (https://health.aws.amazon.com/health/status) for {region}, then run `ozbox init` again in a few minutes. You do not need to sign in again."),
    ("init.signin_throttled", "AWS is limiting requests from this account right now ({why}). Your login is fine. Nothing was changed."),
    ("init.signin_throttled_fix", "Wait a minute, then run `ozbox init` again. If it keeps happening, another tool in this account may be making many requests."),
    ("init.signin_unreachable", "This computer could not reach AWS ({why}). Your login was not checked. Nothing was changed."),
    ("init.signin_unreachable_fix", "Check your network connection, proxy or VPN, then run `ozbox init` again."),
    ("init.signin_expired", "Your AWS sign-in for profile {profile} has expired."),
    ("init.signin_expired_fix", "Sign in again with: aws sso login --profile {profile}"),
    ("init.signin_no_profile", "There is no AWS profile named {profile} on this computer."),
    ("init.signin_no_profile_fix", "Create it with `aws configure sso --profile {profile}`, or pass the name of a profile you have with --profile."),
    ("init.signin_bad_keys", "AWS did not accept the credentials for profile {profile} (they are wrong or were revoked)."),
    // quotas: the network needs an Elastic IP address and a NAT gateway
    ("init.quota_eip", "Elastic IP addresses"),
    ("init.quota_nat", "NAT gateways in {zone}"),
    ("init.quota_short", "The network needs {needed} more of \"{what}\" in {region}, but the account's quota is {quota} and {used} are in use ({free} free). Nothing was changed."),
    ("init.quota_short_fix", "Ask AWS for more: aws service-quotas request-service-quota-increase --service-code {service} --quota-code {code} --desired-value {want} --region {region}. Or release ones you no longer use. Then run `ozbox init` again."),
    ("init.quota_ok", "Quota: \"{what}\" in {region}: {needed} needed, {free} free of {quota}."),
    ("init.quota_unknown", "Quota: \"{what}\" in {region} could not be read ({why}). If the apply is refused with AddressLimitExceeded or NatGatewayLimitExceeded, raise the quota and run `ozbox init` again."),
    // rollback of a half-applied step
    ("init.note_rollback", "If this step fails part way, what it made in this run is removed again, so no half-made step is left billing."),
    ("init.rolled_back", "The step failed part way ({why}). What it had made in this run was removed again, so nothing of it is left. Fix the cause and run `ozbox init` again."),
    ("init.rollback_failed", "The step failed part way ({why}), and removing what it had made also failed ({rollback}). Some of it may still exist and bill. Look for resources tagged ozbox-managed=true in the account, or run `ozbox init` again to finish the step."),
    // the provider pin
    ("init.note_provider_pin", "Every step uses the same pinned AWS plugin version ({version}) and one shared lock file, so all steps run the same code."),
    ("init.provider_lock_failed", "The AWS plugin {version} could not be prepared ({why}). Nothing was changed."),
    // previews before the state bucket exists
    ("init.note_preview", "Preview only: the state bucket does not exist yet, so this is everything the step would make in an empty account. It is planned again, against the bucket, when you run without --dry-run."),
    ("init.preview_only", "This plan is a preview and cannot be applied. Run `ozbox init` without --dry-run."),
    // --only and --skip
    ("init.step_unknown", "{step} is not a setup step. The steps are: {steps}."),
    ("init.step_required", "The state bucket cannot be skipped: every other step keeps its state there. It is only made when it does not exist yet."),
    ("init.step_bucket_needed", "The state bucket does not exist yet, and the steps you chose need it. Add state-bucket to --only."),
    ("init.step_operator_policy", "operator policy file"),
    ("init.step_not_chosen", "Not run: {step} (not chosen with --only or --skip). Nothing was planned or changed for it."),
    // the merged operator policy
    ("init.merge_title", "Operator policy: {total} statements, from the template and the adopt step."),
    ("init.merge_added", "  added from the adopt step: {sids}"),
    ("init.merge_replaced", "  replaced by the adopt step's version: {sids}"),
    ("init.merge_unchanged", "  already the same: {sids}"),
    ("init.merge_no_adopt", "  the adopt step's own output is not there yet (not applied in this region), so its statements are the template's."),
    ("init.merge_bad", "The adopt step's policy in {path} could not be read ({why}), so it was not merged; the template's statements are used."),
];
