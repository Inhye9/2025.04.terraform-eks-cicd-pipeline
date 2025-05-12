# ------------------------------------------------------------------------
# Default Route Table
# ------------------------------------------------------------------------
resource "aws_default_route_table" "aim_default_rtb" {
  default_route_table_id = "${aws_vpc.aim_vpc.default_route_table_id}"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-default-rtb"
  })
}

# ------------------------------------------------------------------------
# Public Route Table
# ------------------------------------------------------------------------
resource "aws_route_table" "aim_public_rtb" {
  vpc_id = aws_vpc.aim_vpc.id

  # route rule add 
#   route {
#     cidr_block = "0.0.0.0/0"
#     gateway_id = aws_internet_gateway.aim_igw.id
#   }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-public-rtb"
  })
}

resource "aws_route" "aim_public_route" {
  route_table_id         = aws_route_table.aim_public_rtb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.aim_igw.id
}

resource "aws_route_table_association" "aim_public_rt_assoc_1" {
  subnet_id      = aws_subnet.aim_public_subnet_a.id
  route_table_id = aws_route_table.aim_public_rtb.id
}

resource "aws_route_table_association" "aim_public_rt_assoc_2" {
  subnet_id      = aws_subnet.aim_public_subnet_c.id
  route_table_id = aws_route_table.aim_public_rtb.id
}
# ------------------------------------------------------------------------
# Private Route Table
# ------------------------------------------------------------------------
resource "aws_route_table" "aim_private_rtb" {
  vpc_id = aws_vpc.aim_vpc.id

  # route rule add 
#   route {
#     cidr_block = "0.0.0.0/0"
#     nat_gateway_id = aws_nat_gateway.aim_nat.id
#   }

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-private-rtb"
  })
}

resource "aws_route" "aim_private_route" {
  route_table_id         = aws_route_table.aim_private_rtb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_nat_gateway.aim_nat.id
}

resource "aws_route_table_association" "aim_private_rt_assoc_1" {
  subnet_id      = aws_subnet.aim_private_subnet_a.id
  route_table_id = aws_route_table.aim_private_rtb.id
}

resource "aws_route_table_association" "aim_private_rt_assoc_2" {
  subnet_id      = aws_subnet.aim_private_subnet_c.id
  route_table_id = aws_route_table.aim_private_rtb.id
}
