# Deliberately insecure network fixtures for IaC scanner validation. Do not apply.

# FIX-IAC-040: SSH and RDP open to the world, all-ports egress
resource "aws_security_group" "open_fixture" {
  name        = "tigergate-open-fixture"
  description = "Open to the world"
  vpc_id      = aws_vpc.fixture.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FIX-IAC-041: VPC with no flow logs; default NACL allows everything
resource "aws_vpc" "fixture" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_network_acl" "fixture" {
  vpc_id = aws_vpc.fixture.id
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

# FIX-IAC-042: subnet auto-assigns public IPs
resource "aws_subnet" "public_fixture" {
  vpc_id                  = aws_vpc.fixture.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

# FIX-IAC-043: classic ELB listener on plain HTTP, no access logs
resource "aws_elb" "fixture" {
  name            = "tigergate-fixture-elb"
  subnets         = [aws_subnet.public_fixture.id]
  security_groups = [aws_security_group.open_fixture.id]
  listener {
    instance_port     = 3000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}

# FIX-IAC-044: ALB listener on HTTP without redirect, drop_invalid_header_fields off
resource "aws_lb" "fixture" {
  name                       = "tigergate-fixture-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.open_fixture.id]
  subnets                    = [aws_subnet.public_fixture.id]
  drop_invalid_header_fields = false
  enable_deletion_protection = false
}

resource "aws_lb_listener" "http_fixture" {
  load_balancer_arn = aws_lb.fixture.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
    }
  }
}
