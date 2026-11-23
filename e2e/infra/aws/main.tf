terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.81, < 7.0"
    }
  }
}

variable "region" {
  type = string
}

variable "github_repository" {
  type    = string
  default = "basics-only/bae6"
}

variable "bedrock_model_arns" {
  description = "Exact model or inference-profile ARNs the live tests may invoke. No wildcards."
  type        = list(string)
  validation {
    condition     = length(var.bedrock_model_arns) > 0 && alltrue([for a in var.bedrock_model_arns : !strcontains(a, "*")])
    error_message = "List at least one exact Bedrock ARN, without wildcards."
  }
}

variable "create_github_oidc_provider" {
  description = "False when the account already has the token.actions.githubusercontent.com provider."
  type        = bool
  default     = true
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

locals {
  oidc_host         = "token.actions.githubusercontent.com"
  oidc_provider_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.oidc_host}"
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_github_oidc_provider ? 1 : 0
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "live" {
  name                 = "bae6-live-tests"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = local.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_host}:aud" = "sts.amazonaws.com"
          "${local.oidc_host}:sub" = "repo:${var.github_repository}:environment:live"
        }
      }
    }]
  })
  depends_on = [aws_iam_openid_connect_provider.github]
}

resource "aws_s3_bucket" "live" {
  bucket_prefix = "bae6-live-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "live" {
  bucket                  = aws_s3_bucket.live.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "fixtures" {
  for_each = {
    "example/handbook.txt" = "Expense reports are reimbursed within ten business days of approval."
    "other/private.txt"    = "Not part of the example organization."
  }
  bucket  = aws_s3_bucket.live.id
  key     = each.key
  content = each.value
}

resource "aws_iam_role_policy" "live" {
  name = "bae6-live-tests"
  role = aws_iam_role.live.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = var.bedrock_model_arns
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.live.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.live.arn]
      },
    ]
  })
}

output "role_arn" {
  value = aws_iam_role.live.arn
}

output "bucket" {
  value = aws_s3_bucket.live.id
}
