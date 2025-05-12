# ------------------------------------------------------------------------
# Nat Gateway
# ------------------------------------------------------------------------
resource "aws_nat_gateway" "aim_nat" {
  allocation_id = aws_eip.aim_eip.id
  subnet_id     = aws_subnet.aim_public_subnet_a.id

  # igw 생성 → eip, nat 생성
  depends_on = [aws_internet_gateway.aim_igw]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-nat-gw"
  })
}

# elastic IP 생성
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip 
resource "aws_eip" "aim_eip" {
  # vpc = true
  domain = "vpc"

  # igw 생성 → eip, nat 생성
  depends_on = [aws_internet_gateway.aim_igw]

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-eip"
  })
}