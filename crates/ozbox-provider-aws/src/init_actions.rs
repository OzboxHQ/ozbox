//! The actions `ozbox init` needs for each resource type of the modules it applies with a dedicated permission set.
//!
//! One table, used twice: the coverage test in this crate checks each module's resource types against the permission set that
//! applies them, and the CLI's own tests check that the pre-flight lists (`KEY_ACTIONS`, `ADOPT_ACTIONS`) are asked from this
//! same table, so what init asks before an apply cannot drift from what the apply calls.

/// The actions applying (create, read back, tag, update, destroy) a resource type calls. `None` for a type the table does not
/// know: a new resource in an init-applied module is a deliberate edit here.
pub fn resource_actions(resource_type: &str) -> Option<&'static [&'static str]> {
    Some(match resource_type {
        "aws_kms_key" => &[
            "kms:CreateKey",
            "kms:PutKeyPolicy",
            "kms:EnableKeyRotation",
            "kms:TagResource",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
            "kms:GetKeyPolicy",
            "kms:ListResourceTags",
            "kms:UpdateKeyDescription",
            "kms:ScheduleKeyDeletion",
        ],
        "aws_kms_alias" => &[
            "kms:CreateAlias",
            "kms:UpdateAlias",
            "kms:DeleteAlias",
            "kms:ListAliases",
        ],
        "aws_iam_policy" => &[
            "iam:CreatePolicy",
            "iam:CreatePolicyVersion",
            "iam:DeletePolicyVersion",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListPolicyVersions",
            "iam:TagPolicy",
            "iam:UntagPolicy",
            "iam:ListPolicyTags",
            "iam:DeletePolicy",
        ],
        "aws_ssm_document" => &[
            "ssm:CreateDocument",
            "ssm:UpdateDocument",
            "ssm:UpdateDocumentDefaultVersion",
            "ssm:DeleteDocument",
            "ssm:DescribeDocument",
            "ssm:GetDocument",
            "ssm:DescribeDocumentPermission",
            "ssm:AddTagsToResource",
            "ssm:RemoveTagsFromResource",
            "ssm:ListTagsForResource",
        ],
        _ => return None,
    })
}

/// Actions in the table that the permission set deliberately does NOT grant, each with the reason. A destroy that needs one of
/// these is done by an administrator, never by `ozbox init`.
pub const DELIBERATELY_NOT_GRANTED: [(&str, &str); 1] = [(
    "iam:DeletePolicy",
    "init never destroys an account's box policies: they are shared by every box of the fleet",
)];
