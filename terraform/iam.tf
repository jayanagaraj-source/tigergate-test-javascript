# Deliberately over-privileged IAM fixtures for IaC scanner validation. Do not apply.

# FIX-IAC-045: wildcard actions and resources
resource "aws_iam_policy" "admin_fixture" {
  name = "tigergate-star-star"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
      }, {
      Effect   = "Allow"
      Action   = ["iam:PassRole", "iam:CreateAccessKey", "sts:AssumeRole"]
      Resource = "*"
    }]
  })
}

# FIX-IAC-046: IAM user with inline policy and console password, no MFA
resource "aws_iam_user" "fixture" {
  name = "tigergate-fixture-user"
}

resource "aws_iam_user_policy" "fixture_inline" {
  name   = "inline-admin"
  user   = aws_iam_user.fixture.name
  policy = aws_iam_policy.admin_fixture.policy
}

resource "aws_iam_access_key" "fixture" {
  user = aws_iam_user.fixture.name
}

# FIX-IAC-047: weak account password policy
resource "aws_iam_account_password_policy" "weak_fixture" {
  minimum_password_length        = 6
  require_lowercase_characters   = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0
  password_reuse_prevention      = 0
}

# FIX-IAC-048: role assumable by any AWS principal
resource "aws_iam_role" "public_assume_fixture" {
  name = "tigergate-anyone-can-assume"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}
