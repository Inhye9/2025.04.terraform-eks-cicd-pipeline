# ------------------------------------------------------------------------
# VPC Default Security Group
# ------------------------------------------------------------------------
resource "aws_default_security_group" "aim_default" {
  vpc_id = "${aws_vpc.aim_vpc.id}"

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-default-vpc-sg"
  })
}