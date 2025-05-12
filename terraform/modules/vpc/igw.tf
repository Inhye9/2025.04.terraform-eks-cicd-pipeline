# ------------------------------------------------------------------------
# Internet Gateway
# ------------------------------------------------------------------------
resource "aws_internet_gateway" "aim_igw" {
  vpc_id = aws_vpc.aim_vpc.id

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-igw"
  })
}