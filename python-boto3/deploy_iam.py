#!/usr/bin/env python3
"""
stravaco_iam_deploy.py
======================
Idempotent Boto3 script that creates the Stravaco IAM groups, attaches
managed and inline policies, creates users, and adds users to their groups.

Usage:
    python deploy_iam.py [--env Development|Production] [--teardown]

Flags:
    --env       Value for the Environment tag applied to users (default: Development).
                The Developer_Group production deny policy is always created regardless
                of this flag (it guards tagged *resources*, not the deployment context).
    --teardown  Delete all users and groups created by this script (reverse order).
"""

import argparse
import json
import sys
import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Groups: { logical_key: (group_name, [managed_policy_arns]) }
GROUPS: dict[str, tuple[str, list[str]]] = {
    "developer": (
        "Developer_Group",
        [
            "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
            "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            "arn:aws:iam::aws:policy/CloudWatchEventsFullAccess",
        ],
    ),
    "ops": (
        "Ops_Group",
        [
            "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
            "arn:aws:iam::aws:policy/CloudWatchEventsFullAccess",
            "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
            "arn:aws:iam::aws:policy/AmazonRDSFullAccess",
        ],
    ),
    "finance": (
        "Finance_Group",
        [
            "arn:aws:iam::aws:policy/job-function/Billing",
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
        ],
    ),
    "data": (
        "Data_Group",
        [
            "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess",
        ],
    ),
    "admin": (
        "Stravaco_Admin_Group",
        [
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/AmazonS3FullAccess",
            "arn:aws:iam::aws:policy/AWSBillingConductorFullAccess",
            "arn:aws:iam::aws:policy/job-function/Billing",
            "arn:aws:iam::aws:policy/IAMUserChangePassword",
        ],
    ),
}

# Developer inline deny/allow policy document
DEVELOPER_INLINE_POLICY_NAME = "Developer_Group_ProductionDestructiveDeny"
DEVELOPER_INLINE_POLICY: dict = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyEC2DestructiveOnProduction",
            "Effect": "Deny",
            "Action": [
                "ec2:TerminateInstances",
                "ec2:StopInstances",
                "ec2:RebootInstances",
                "ec2:DeleteVolume",
                "ec2:DeleteSnapshot",
                "ec2:DeleteSecurityGroup",
                "ec2:DeleteSubnet",
                "ec2:DeleteVpc",
                "ec2:DeleteInternetGateway",
                "ec2:DeleteRouteTable",
                "ec2:DeleteRoute",
                "ec2:DeleteNetworkAcl",
                "ec2:DeleteKeyPair",
                "ec2:DeleteLaunchTemplate",
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:ResourceTag/Environment": "Production"}
            },
        },
        {
            "Sid": "DenyS3DestructiveOnProduction",
            "Effect": "Deny",
            "Action": [
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:DeleteBucket",
                "s3:DeleteBucketPolicy",
                "s3:DeleteBucketWebsite",
                "s3:PutBucketPolicy",
                "s3:PutLifecycleConfiguration",
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:ResourceTag/Environment": "Production"}
            },
        },
        {
            "Sid": "AllowEC2DestructiveOnDevelopment",
            "Effect": "Allow",
            "Action": [
                "ec2:TerminateInstances",
                "ec2:StopInstances",
                "ec2:RebootInstances",
                "ec2:DeleteVolume",
                "ec2:DeleteSnapshot",
                "ec2:DeleteSecurityGroup",
                "ec2:DeleteSubnet",
                "ec2:DeleteVpc",
                "ec2:DeleteInternetGateway",
                "ec2:DeleteRouteTable",
                "ec2:DeleteRoute",
                "ec2:DeleteNetworkAcl",
                "ec2:DeleteKeyPair",
                "ec2:DeleteLaunchTemplate",
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:ResourceTag/Environment": "Development"}
            },
        },
        {
            "Sid": "AllowS3DestructiveOnDevelopment",
            "Effect": "Allow",
            "Action": [
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:DeleteBucket",
                "s3:DeleteBucketPolicy",
                "s3:DeleteBucketWebsite",
                "s3:PutBucketPolicy",
                "s3:PutLifecycleConfiguration",
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:ResourceTag/Environment": "Development"}
            },
        },
    ],
}

# Users: list of dicts with username, name, title, email, team, group (logical key)
USERS: list[dict] = [
    # Admin
    {"username": "acook",      "name": "Alex Cook",         "title": "Chief Architect",      "email": "acook@stravaco.biz",      "team": "IT",           "group": "admin"},
    # Ops
    {"username": "sbrahamian", "name": "Sidhar Brahamian",  "title": "Devops Lead",          "email": "sbrahamian@stravaco.biz", "team": "Operations",   "group": "ops"},
    {"username": "bstichler",  "name": "Bert Stichler",     "title": "AWS Admin",            "email": "bstichler@stravaco.biz",  "team": "Operations",   "group": "ops"},
    # Developer
    {"username": "ralhamein",  "name": "Rasheed Alhamein",  "title": "Development Manager",  "email": "ralhamein@stravaco.biz",  "team": "Developer",    "group": "developer"},
    {"username": "lmckeown",   "name": "Liam Mckeown",      "title": "Developer",            "email": "lmckeown@stravaco.biz",   "team": "Developer",    "group": "developer"},
    {"username": "abrackett",  "name": "Angela Brackett",   "title": "Jr. Developer",        "email": "abrackett@stravaco.biz",  "team": "Developer",    "group": "developer"},
    {"username": "spalamadu",  "name": "Suri Palamadu",     "title": "Senior Developer",     "email": "spalamadu@stravaco.biz",  "team": "Developer",    "group": "developer"},
    # Finance
    {"username": "gmcevoy",    "name": "Gordon McEvoy",     "title": "Finance Manager",      "email": "gmcevoy@stravaco.biz",    "team": "Finance",      "group": "finance"},
    # Data
    {"username": "asingh",     "name": "Anupam Singh",      "title": "Data Engineer",        "email": "asingh@stravaco.biz",     "team": "Data Analyst", "group": "data"},
    {"username": "bdoans",     "name": "Bethany Doans",     "title": "Jr. Data Analyst",     "email": "bdoans@stravaco.biz",     "team": "Data Analyst", "group": "data"},
    {"username": "fkhuri",     "name": "Farahd Khuri",      "title": "Data Engineer",        "email": "fkhuri@stravaco.biz",     "team": "Data Analyst", "group": "data"},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m  {msg}")


def info(msg: str) -> None:
    print(f"  \033[34m→\033[0m  {msg}")


def err(msg: str) -> None:
    print(f"  \033[31m✗\033[0m  {msg}", file=sys.stderr)


def group_exists(iam, group_name: str) -> bool:
    try:
        iam.get_group(GroupName=group_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def user_exists(iam, username: str) -> bool:
    try:
        iam.get_user(UserName=username)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def policy_attached(iam, group_name: str, policy_arn: str) -> bool:
    paginator = iam.get_paginator("list_attached_group_policies")
    for page in paginator.paginate(GroupName=group_name):
        for p in page["AttachedPolicies"]:
            if p["PolicyArn"] == policy_arn:
                return True
    return False


def inline_policy_exists(iam, group_name: str, policy_name: str) -> bool:
    try:
        iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

def deploy(env_tag: str) -> None:
    iam = boto3.client("iam")

    print("\n=== Stravaco IAM Deploy ===\n")

    # 1. Create groups
    print("── Creating IAM Groups ──────────────────────────")
    group_name_map: dict[str, str] = {}  # logical key → actual group name

    for key, (group_name, policies) in GROUPS.items():
        group_name_map[key] = group_name
        if group_exists(iam, group_name):
            info(f"Group already exists: {group_name}")
        else:
            iam.create_group(GroupName=group_name)
            ok(f"Created group: {group_name}")

        # Attach managed policies
        for arn in policies:
            if policy_attached(iam, group_name, arn):
                info(f"  Policy already attached: {arn.split('/')[-1]}")
            else:
                iam.attach_group_policy(GroupName=group_name, PolicyArn=arn)
                ok(f"  Attached: {arn.split('/')[-1]}")

    # 2. Developer inline deny policy
    print("\n── Applying Developer Deny Inline Policy ────────")
    dev_group = group_name_map["developer"]
    if inline_policy_exists(iam, dev_group, DEVELOPER_INLINE_POLICY_NAME):
        info(f"Inline policy already exists on {dev_group}, updating...")
    iam.put_group_policy(
        GroupName=dev_group,
        PolicyName=DEVELOPER_INLINE_POLICY_NAME,
        PolicyDocument=json.dumps(DEVELOPER_INLINE_POLICY),
    )
    ok(f"Applied inline policy '{DEVELOPER_INLINE_POLICY_NAME}' to {dev_group}")

    # 3. Create users and add to groups
    print("\n── Creating IAM Users ───────────────────────────")
    for u in USERS:
        username = u["username"]
        target_group = group_name_map[u["group"]]
        tags = [
            {"Key": "Name",        "Value": u["name"]},
            {"Key": "Title",       "Value": u["title"]},
            {"Key": "Email",       "Value": u["email"]},
            {"Key": "Team",        "Value": u["team"]},
            {"Key": "Environment", "Value": env_tag},
        ]

        if user_exists(iam, username):
            info(f"User already exists: {username} — updating tags")
            iam.tag_user(UserName=username, Tags=tags)
        else:
            iam.create_user(UserName=username, Path="/", Tags=tags)
            ok(f"Created user: {username} ({u['name']})")

        # Add to group (idempotent — AWS returns success even if already a member)
        iam.add_user_to_group(UserName=username, GroupName=target_group)
        ok(f"  → {username} added to {target_group}")

    # 4. Print ARN outputs
    print("\n── Group ARNs ───────────────────────────────────")
    for key, (group_name, _) in GROUPS.items():
        resp = iam.get_group(GroupName=group_name)
        arn = resp["Group"]["Arn"]
        print(f"  {group_name:<25} {arn}")

    print("\n✅  Deploy complete.\n")


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def teardown() -> None:
    iam = boto3.client("iam")

    print("\n=== Stravaco IAM Teardown ===\n")

    # 1. Remove users from groups and delete users
    print("── Deleting IAM Users ───────────────────────────")
    for u in USERS:
        username = u["username"]
        if not user_exists(iam, username):
            info(f"User not found (skipping): {username}")
            continue
        # Remove from all groups
        resp = iam.list_groups_for_user(UserName=username)
        for g in resp["Groups"]:
            iam.remove_user_from_group(UserName=username, GroupName=g["GroupName"])
            ok(f"  Removed {username} from {g['GroupName']}")
        iam.delete_user(UserName=username)
        ok(f"Deleted user: {username}")

    # 2. Detach policies and delete groups
    print("\n── Deleting IAM Groups ──────────────────────────")
    dev_group = GROUPS["developer"][0]

    for key, (group_name, policies) in GROUPS.items():
        if not group_exists(iam, group_name):
            info(f"Group not found (skipping): {group_name}")
            continue

        # Remove inline policies
        inline_resp = iam.list_group_policies(GroupName=group_name)
        for pname in inline_resp["PolicyNames"]:
            iam.delete_group_policy(GroupName=group_name, PolicyName=pname)
            ok(f"  Deleted inline policy '{pname}' from {group_name}")

        # Detach managed policies
        for arn in policies:
            try:
                iam.detach_group_policy(GroupName=group_name, PolicyArn=arn)
                ok(f"  Detached: {arn.split('/')[-1]}")
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        iam.delete_group(GroupName=group_name)
        ok(f"Deleted group: {group_name}")

    print("\n✅  Teardown complete.\n")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stravaco IAM deploy/teardown")
    parser.add_argument(
        "--env",
        choices=["Development", "Production"],
        default="Development",
        help="Environment tag applied to IAM users (default: Development)",
    )
    parser.add_argument(
        "--teardown",
        action="store_true",
        help="Destroy all resources created by this script",
    )
    args = parser.parse_args()

    if args.teardown:
        teardown()
    else:
        deploy(args.env)

## Commands to run
# python deploy_iam.py
# python deploy_iam.py --teardown 
# python deploy_iam.py --env Production 
