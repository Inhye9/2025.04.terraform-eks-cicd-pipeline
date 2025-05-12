resource "aws_vpc" "aim_vpc" {
  cidr_block = "10.54.0.0/16"

  enable_dns_support = true
  enable_dns_hostnames = true
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpc"
  })
}

