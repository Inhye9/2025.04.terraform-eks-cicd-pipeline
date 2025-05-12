# ------------------------------------------------------------------------
# AZ(Available Zone)
# ------------------------------------------------------------------------
data "aws_availability_zones" "available" {}

# ------------------------------------------------------------------------
# Subnets
# ------------------------------------------------------------------------
resource "aws_subnet" "aim_public_subnet_a" {
  vpc_id     = aws_vpc.aim_vpc.id

  cidr_block = "10.54.1.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"
  map_public_ip_on_launch = true  #assigned public ip  

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-public-subnet-a",
    env = "public",
    eks = "true"
  })
}

resource "aws_subnet" "aim_public_subnet_c" {
  vpc_id     = aws_vpc.aim_vpc.id

  cidr_block = "10.54.2.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[1]}"
  map_public_ip_on_launch = true  #assigned public ip

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-public-subnet-c", 
    env = "public",
    eks = "true"
  })
}

resource "aws_subnet" "aim_private_subnet_a" {
  vpc_id     = aws_vpc.aim_vpc.id
  
  cidr_block = "10.54.10.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-private-subnet-a",
    env = "private",
    eks = "true"
  })
}

resource "aws_subnet" "aim_private_subnet_c" {
  vpc_id     = aws_vpc.aim_vpc.id
  
  cidr_block = "10.54.11.0/24"
  availability_zone = "${data.aws_availability_zones.available.names[1]}"
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-private-subnet-c",
    env = "private",
    eks = "true"
  })
}