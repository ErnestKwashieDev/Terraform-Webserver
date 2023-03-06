terraform {
  required_providers {
    aws = {
      version = "~>3.0"
      source  = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region  = "eu-central-1"
  profile = "bulb"
  access_key =  "AKIAULEIG5OHK4QQAXWA"
  secret_key = "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"
}

resource "aws_vpc" "webserver_vpc" {
  cidr_block           = "172.16.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "webserver-test-vpc"
  }
}


resource "aws_subnet" "webserver_subnet" {
  vpc_id            = aws_vpc.webserver_vpc.id
  cidr_block        = cidrsubnet(aws_vpc.webserver_vpc.cidr_block, 3, 1)
  availability_zone = "eu-central-1"

  tags = {
    Name = "webservers-subnets"
  }
}

locals {
  ports_in  = [22, 80, 3000, 8080, 443]
  ports_out = [0]
}

resource "aws_security_group" "webserver_SG" {
  name        = "webservers_SG"
  description = "Allows defined inbound traffic for this webservers"
  vpc_id      = aws_vpc.webserver_vpc.id


  dynamic "ingress" {
    for_each = toset(local.ports_in)
    content {
      description = "TLS from VPC"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  dynamic "egress" {
    for_each = toset(local.ports_out)
    content {
      description = "TLS from VPC"
      from_port   = egress.value
      to_port     = egress.value
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    Name = "allow_traffic"
  }
}

resource "aws_key_pair" "public_key" {
  key_name   = "obogzy-keys.pem"
  public_key = file("${path.module}/public_key")
}

resource "aws_instance" "webserver" {
  ami             = ""
  instance_type   = "t2.micro"
  key_name        = aws_key_pair.public_key.key_name
  security_groups = ["${aws_security_group.webserver_SG.id}"]
  user_data       = file("startup.sh")
  subnet_id       = aws_subnet.webserver_subnet.id
  tags = {
    Name = "webserverVM"
  }
}


resource "aws_eip" "webserver_eip" {
  instance = aws_instance.webserver.id
  vpc      = true
}

resource "aws_internet_gateway" "webserver_gw" {
  vpc_id = aws_vpc.webserver_vpc.id

  tags = {
    Name = "webserver_gw"
  }
}

resource "aws_route_table" "webserver_RTB" {
  vpc_id = aws_vpc.webserver_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.webserver_gw.id
  }


  tags = {
    Name = "webserver_RTB"
  }
}


resource "aws_route_table_association" "webserver_RTB_AS" {
  subnet_id      = aws_subnet.webserver_subnet.id
  route_table_id = aws_route_table.webserver_RTB.id

}

locals {
  public_subnet_ids = aws_subnet.webserver_subnet.*.id
}

resource "aws_lb" "websever_lb" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.webserver_SG.id]
  subnets          = local.public_subnet_ids

  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.webserver_s3.id
    prefix  = "test-lb"
    enabled = true
  }

  tags = {
    Environment = "production"
  }
}
resource "aws_s3_bucket" "webserver_s3" {
  bucket = "my-tf-test-bucket"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.webserver_s3.id
  acl    = "private"
}
resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.websever_lb.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.webserver_TG.arn
  }
}

resource "aws_lb_listener_certificate" "example" {
  listener_arn    = aws_lb_listener.front_end.arn
  certificate_arn = aws_acm_certificate.cert.arn
}

resource "aws_acm_certificate" "cert" {
  domain_name       = "example.com"
  validation_method = "DNS"

  tags = {
    Environment = "test"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_target_group" "webserver_TG" {
  name     = "tf-example-lb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}

resource "aws_lb_target_group_attachment" "test" {
  target_group_arn = aws_lb_target_group.webserver_TG.arn
  target_id        = aws_instance.webserver.id
  port             = 80
}

resource "aws_lb_listener_rule" "redirect_http_to_https" {
  listener_arn = aws_lb_listener.front_end.arn

  action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  condition {
    http_header {
      http_header_name = "X-Forwarded-For"
      values           = ["172.16.8.*"]
    }
  }
}

output "application_security_group_id" {
  value = aws_security_group.webserver_SG.id
}
