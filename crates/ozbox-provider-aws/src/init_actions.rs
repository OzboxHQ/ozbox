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
        "aws_vpc" => &[
            "ec2:CreateVpc",
            "ec2:CreateTags",
            "ec2:DeleteTags",
            "ec2:DescribeVpcs",
            "ec2:DescribeVpcAttribute",
            "ec2:ModifyVpcAttribute",
            "ec2:DeleteVpc",
        ],
        "aws_internet_gateway" => &[
            "ec2:CreateInternetGateway",
            "ec2:CreateTags",
            "ec2:DeleteTags",
            "ec2:DescribeInternetGateways",
            "ec2:AttachInternetGateway",
            "ec2:DetachInternetGateway",
            "ec2:DeleteInternetGateway",
        ],
        "aws_subnet" => &[
            "ec2:CreateSubnet",
            "ec2:CreateTags",
            "ec2:DeleteTags",
            "ec2:DescribeSubnets",
            "ec2:ModifySubnetAttribute",
            "ec2:DeleteSubnet",
        ],
        "aws_eip" => &[
            "ec2:AllocateAddress",
            "ec2:CreateTags",
            "ec2:DeleteTags",
            "ec2:DescribeAddresses",
            "ec2:DescribeAddressesAttribute",
            "ec2:ReleaseAddress",
        ],
        "aws_nat_gateway" => &[
            "ec2:CreateNatGateway",
            "ec2:CreateTags",
            "ec2:DeleteTags",
            "ec2:DescribeNatGateways",
            "ec2:DeleteNatGateway",
        ],
        "aws_route_table" => &[
            "ec2:CreateRouteTable",
            "ec2:CreateTags",
            "ec2:DeleteTags",
            "ec2:DescribeRouteTables",
            "ec2:DeleteRouteTable",
        ],
        "aws_route" => &[
            "ec2:CreateRoute",
            "ec2:ReplaceRoute",
            "ec2:DeleteRoute",
            "ec2:DescribeRouteTables",
        ],
        "aws_route_table_association" => &[
            "ec2:AssociateRouteTable",
            "ec2:DisassociateRouteTable",
            "ec2:DescribeRouteTables",
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

/// The IAM action each `aws s3api` subcommand `ozbox init` runs against the state bucket needs (the bucket is made by the CLI
/// itself, not by an OpenTofu module). `None` for a subcommand the table does not know: a new call on the bucket is a
/// deliberate edit here, and in `infra/aws/setup-policy.json`.
pub fn s3api_action(subcommand: &str) -> Option<&'static str> {
    Some(match subcommand {
        "head-bucket" => "s3:ListBucket",
        "create-bucket" => "s3:CreateBucket",
        // only to undo a bucket this run made and left half set up: S3 deletes an empty bucket only, so it cannot remove state
        "delete-bucket" => "s3:DeleteBucket",
        "get-bucket-versioning" => "s3:GetBucketVersioning",
        "put-bucket-versioning" => "s3:PutBucketVersioning",
        "get-bucket-encryption" => "s3:GetEncryptionConfiguration",
        "put-bucket-encryption" => "s3:PutEncryptionConfiguration",
        "get-public-access-block" => "s3:GetBucketPublicAccessBlock",
        "put-public-access-block" => "s3:PutBucketPublicAccessBlock",
        "put-bucket-policy" => "s3:PutBucketPolicy",
        _ => return None,
    })
}

/// What the state bucket is held to beyond the commands above: reading back its policy, tagging it, and (for OpenTofu's S3
/// backend) its location.
pub const STATE_BUCKET_EXTRA_ACTIONS: [&str; 3] = [
    "s3:GetBucketLocation",
    "s3:GetBucketPolicy",
    "s3:PutBucketTagging",
];

/// The actions on the state objects: read and write the state, and take and release the lock (`use_lockfile`, a `.tflock` object).
pub const STATE_OBJECT_ACTIONS: [&str; 3] = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"];

/// The read-only AWS CLI calls `ozbox init` makes to find what a step would create, so it can adopt it instead of making it a
/// second time (ADR 0053): (service, subcommand, the IAM actions the call needs, a sample resource ARN, the permission set of
/// the step that makes the call). A call the code makes that is not here fails the coverage test, so a new lookup is a
/// deliberate edit here and, if the identity cannot make it, in `infra/aws/setup-policy.json` and the step's own set.
pub const ADOPTION_LOOKUPS: [(&str, &str, &[&str], &str, &str); 4] = [
    (
        "kms",
        "list-aliases",
        &["kms:ListAliases"],
        "*",
        "key-admin-policy.json",
    ),
    (
        "kms",
        "list-resource-tags",
        &["kms:ListResourceTags"],
        "arn:aws:kms:us-east-1:123456789012:key/00000000",
        "key-admin-policy.json",
    ),
    (
        "ssm",
        "describe-document",
        &["ssm:DescribeDocument"],
        "arn:aws:ssm:us-east-1:123456789012:document/ozbox-adopt-fleet",
        "adopt-admin-policy.json",
    ),
    (
        "iam",
        "get-policy",
        &["iam:GetPolicy"],
        "arn:aws:iam::123456789012:policy/ozbox-box-session-manager",
        "box-policy-admin-policy.json",
    ),
];
