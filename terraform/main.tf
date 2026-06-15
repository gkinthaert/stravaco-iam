provider "aws" {
  region = "us-east-1"
}

#########################################
# IAM GROUPS
#########################################

resource "aws_iam_group" "developer" {
  name = "Developer_Group"
}

resource "aws_iam_group" "ops" {
  name = "Ops_Group"
}

resource "aws_iam_group" "finance" {
  name = "Finance_Group"
}

resource "aws_iam_group" "data" {
  name = "Data_Group"
}

resource "aws_iam_group" "admin" {
  name = "Stravaco_Admin_Group"
}

#########################################
# MANAGED POLICY ATTACHMENTS
#########################################

# Developer
resource "aws_iam_group_policy_attachment" "developer_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/CloudWatchEventsFullAccess"
  ])

  group      = aws_iam_group.developer.name
  policy_arn = each.value
}

# Ops
resource "aws_iam_group_policy_attachment" "ops_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchEventsFullAccess",
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
  ])

  group      = aws_iam_group.ops.name
  policy_arn = each.value
}

# Finance
resource "aws_iam_group_policy_attachment" "finance_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/job-function/Billing",
    "arn:aws:iam::aws:policy/ReadOnlyAccess"
  ])

  group      = aws_iam_group.finance.name
  policy_arn = each.value
}

# Data
resource "aws_iam_group_policy_attachment" "data_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
  ])

  group      = aws_iam_group.data.name
  policy_arn = each.value
}

# Admin
resource "aws_iam_group_policy_attachment" "admin_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AWSBillingConductorFullAccess",
    "arn:aws:iam::aws:policy/job-function/Billing",
    "arn:aws:iam::aws:policy/IAMUserChangePassword"
  ])

  group      = aws_iam_group.admin.name
  policy_arn = each.value
}

#########################################
# INLINE POLICY (Developer Deny)
#########################################

resource "aws_iam_policy" "developer_deny" {
  name = "Developer_Group_ProductionDestructiveDeny"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyEC2DestructiveOnProduction"
        Effect = "Deny"
        Action = [
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
          "ec2:DeleteLaunchTemplate"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = "Production"
          }
        }
      },
      {
        Sid    = "DenyS3DestructiveOnProduction"
        Effect = "Deny"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:DeleteBucket",
          "s3:DeleteBucketPolicy",
          "s3:DeleteBucketWebsite",
          "s3:PutBucketPolicy",
          "s3:PutLifecycleConfiguration"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = "Production"
          }
        }
      },
      {
        Sid    = "AllowEC2DestructiveOnDevelopment"
        Effect = "Allow"
        Action = [
          "ec2:TerminateInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances",
          "ec2:DeleteVolume",
          "ec2:DeleteSnapshot"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = "Development"
          }
        }
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "developer_deny_attach" {
  group      = aws_iam_group.developer.name
  policy_arn = aws_iam_policy.developer_deny.arn
}

#########################################
# USERS (example pattern)
#########################################

locals {
  users = {
    acook = {
      group = aws_iam_group.admin.name
      name  = "Alex Cook"
      title = "Chief Architect"
      team  = "IT"
      email = "acook@stravaco.biz"
    }
    sbrahamian = {
      group = aws_iam_group.ops.name
      name  = "Sidhar Brahamian"
      title = "Devops Lead"
      team  = "Operations"
      email = "sbrahamian@stravaco.biz"
    }
    bstichler = {
      group = aws_iam_group.ops.name
      name  = "Bert Stichler"
      title = "AWS Admin"
      team  = "Operations"
      email = "bstichler@stravaco.biz"
    }
    ralhamein = {
      group = aws_iam_group.developer.name
      name  = "Rasheed Alhamein"
      title = "Development Manager"
      team  = "Developer"
      email = "ralhamein@stravaco.biz"
    }
    lmckeown = {
      group = aws_iam_group.developer.name
      name  = "Liam Mckeown"
      title = "Developer"
      team  = "Developer"
      email = "lmckeown@stravaco.biz"
    }
    abrackett = {
      group = aws_iam_group.developer.name
      name  = "Angela Brackett"
      title = "JuniorDeveloper"
      team  = "Developer"
      email = "abrackett@stravaco.biz"
    }
    spalamadu = {
      group = aws_iam_group.developer.name
      name  = "Suri Palamadu"
      title = "Senior Developer"
      team  = "Developer"
      email = "spalamadu@stravaco.biz"
    }
    gmcEvoy = {
      group = aws_iam_group.finance.name
      name  = "Gordon McEvoy"
      title = "Finance Manager"
      team  = "Finance  "
      email = "gmcevoy@stravaco.biz"
    }
    asingh = {
      group = aws_iam_group.data.name
      name  = "Anupam Singh"
      title = "Data Engineer"
      team  = "Data Analyst"
      email = "asingh@stravaco.biz"
    }
    bdoans = {
      group = aws_iam_group.data.name
      name  = "Bethany Doans"
      title = "Jr. Data Analyst"
      team  = "Data Analyst"
      email = "bdoans@stravaco.biz"
    }
    fkhuri = {
      group = aws_iam_group.data.name
      name  = "Farahd Khuri"
      title = "Data Engineer"
      team  = "Data Analyst"
      email = "fkhuri@stravaco.biz"
    }
  }
}

resource "aws_iam_user" "users" {
  for_each = local.users

  name = each.key
  path = "/"

  tags = {
    Name        = each.value.name
    Title       = each.value.title
    Email       = each.value.email
    Team        = each.value.team
    Environment = var.environment
  }
}

resource "aws_iam_user_group_membership" "membership" {
  for_each = local.users

  user   = aws_iam_user.users[each.key].name
  groups = [each.value.group]
}