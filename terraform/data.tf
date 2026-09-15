# Deliberately insecure data-store fixtures for IaC scanner validation. Do not apply.

# FIX-IAC-049: RDS publicly accessible, unencrypted, hardcoded password, no backups, no deletion protection
resource "aws_db_instance" "fixture" {
  identifier                          = "tigergate-fixture-db"
  engine                              = "postgres"
  engine_version                      = "9.6"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "admin"
  password                            = "SuperSecretP4ssw0rd!"
  publicly_accessible                 = true
  storage_encrypted                   = false
  backup_retention_period             = 0
  deletion_protection                 = false
  skip_final_snapshot                 = true
  multi_az                            = false
  iam_database_authentication_enabled = false
  vpc_security_group_ids              = [aws_security_group.open_fixture.id]
}

# FIX-IAC-050: S3 bucket — no encryption, versioning, logging; public-read ACL; no MFA delete
resource "aws_s3_bucket" "open_fixture" {
  bucket = "tigergate-test-javascript-open-fixture"
  acl    = "public-read-write"
}

resource "aws_s3_bucket_policy" "open_fixture" {
  bucket = aws_s3_bucket.open_fixture.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:*"
      Resource  = ["${aws_s3_bucket.open_fixture.arn}", "${aws_s3_bucket.open_fixture.arn}/*"]
    }]
  })
}

# FIX-IAC-051: DynamoDB — no point-in-time recovery, no CMK encryption
resource "aws_dynamodb_table" "fixture" {
  name         = "tigergate-fixture"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  point_in_time_recovery { enabled = false }
  server_side_encryption { enabled = false }
}

# FIX-IAC-052: EBS volume unencrypted
resource "aws_ebs_volume" "fixture" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

# FIX-IAC-053: SQS / SNS without encryption, SQS policy open to everyone
resource "aws_sqs_queue" "fixture" {
  name = "tigergate-fixture-queue"
}

resource "aws_sqs_queue_policy" "fixture" {
  queue_url = aws_sqs_queue.fixture.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "sqs:*", Resource = aws_sqs_queue.fixture.arn }]
  })
}

resource "aws_sns_topic" "fixture" {
  name = "tigergate-fixture-topic"
}

# FIX-IAC-054: KMS key without rotation, policy open to the account root of any account
resource "aws_kms_key" "fixture" {
  description         = "fixture"
  enable_key_rotation = false
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "kms:*", Resource = "*" }]
  })
}

# FIX-IAC-055: ElastiCache / Redis without transit or at-rest encryption, no auth token
resource "aws_elasticache_replication_group" "fixture" {
  replication_group_id          = "tigergate-fixture"
  replication_group_description = "fixture"
  node_type                     = "cache.t3.micro"
  number_cache_clusters         = 1
  at_rest_encryption_enabled    = false
  transit_encryption_enabled    = false
}
