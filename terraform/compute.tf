# Deliberately insecure compute / logging fixtures for IaC scanner validation. Do not apply.

# FIX-IAC-056: EC2 — IMDSv1 allowed, public IP, unencrypted root volume, secrets in user_data, no monitoring
resource "aws_instance" "fixture" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public_fixture.id
  vpc_security_group_ids      = [aws_security_group.open_fixture.id]
  associate_public_ip_address = true
  monitoring                  = false
  ebs_optimized               = false
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
  root_block_device {
    encrypted = false
  }
  user_data = <<-EOT
    #!/bin/bash
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    export DB_PASSWORD='SuperSecretP4ssw0rd!'
    curl -sSL http://get.example.com/install.sh | bash
  EOT
}

# FIX-IAC-057: Lambda — secrets in env, no tracing, no DLQ, wildcard role, unsigned code
resource "aws_lambda_function" "fixture" {
  function_name = "tigergate-fixture"
  role          = aws_iam_role.public_assume_fixture.arn
  handler       = "index.handler"
  runtime       = "nodejs12.x"
  filename      = "lambda.zip"
  environment {
    variables = {
      API_KEY     = "sk_live_FIXTUREfixtureFIXTUREfixt"
      DB_PASSWORD = "SuperSecretP4ssw0rd!"
    }
  }
}

# FIX-IAC-058: CloudTrail not multi-region, no log validation, no encryption; CloudWatch log group without retention/KMS
resource "aws_cloudtrail" "fixture" {
  name                          = "tigergate-fixture-trail"
  s3_bucket_name                = aws_s3_bucket.open_fixture.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
}

resource "aws_cloudwatch_log_group" "fixture" {
  name = "/aws/lambda/tigergate-fixture"
}

# FIX-IAC-059: EKS with public endpoint, no control-plane logging, no secrets encryption
resource "aws_eks_cluster" "fixture" {
  name     = "tigergate-fixture"
  role_arn = aws_iam_role.public_assume_fixture.arn
  vpc_config {
    subnet_ids              = [aws_subnet.public_fixture.id]
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }
}

# FIX-IAC-063: Terraform provider configured with static credentials
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# FIX-IAC-064: remote state without encryption or locking
terraform {
  backend "s3" {
    bucket  = "tigergate-fixture-tfstate"
    key     = "state.tfstate"
    region  = "us-east-1"
    encrypt = false
  }
}
