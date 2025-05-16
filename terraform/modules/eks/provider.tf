# ------------------------------------------------------------------------
# Provider 설정 
# Terraform에서 kubernetes, helm 접근 할 수 있도록 인증 정보 제공
# ------------------------------------------------------------------------
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
    profile = "2244615"
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.certificate_authority_data)
#  cluster_ca_certificate = base64decode(module.eks.certificate_authority[0].data)
   token                  = data.aws_eks_cluster_auth.eks-blue-auth.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.ekscluster_certificate_authority_data)
#    cluster_ca_certificate = base64decode(module.eks.certificate_authority[0].data)
#    token                  = data.aws_eks_cluster_auth.eks-blue-auth.token
  
    exec { # 테라폼 실행환경에 awscli 설치 및 설정되어 있는 경우 token 대신 사용 
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--region", "${var.region}",  "--cluster-name", module.eks.name]
      command     = "aws"
    }
  }
}
