# ------------------------------------------------------------------------
# VPC & Subnets(VPC & Subnet)
# ------------------------------------------------------------------------
# VPC ID를 통해 VPC 정보를 가져옴
data "aws_vpc" "selected_vpc" {
  id = var.vpc_id
}

# VPC ID를 통해 EKS 설치 서브넷 정보 가져옴 
data "aws_subnets" "eks_subnets" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
#    values = [data.aws_vpc.selected_vpc.id]
  }

  # Tag가 eks=true 
  filter {
    name   = "tag:eks"
    values = ["true"]
  }
}

# VPC ID를 통해 EKS Controlplane 설치 서브넷 정보를 가져옴
data "aws_subnets" "eks_controlplane_subnets" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }

  #Tag가 eks=true && env=private
   filter {
    name   = "tag:env"
    values = ["private"]
  }

  filter {
    name   = "tag:eks"
    values = ["true"]
  }
}
