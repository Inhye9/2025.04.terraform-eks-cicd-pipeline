# ------------------------------------------------------------------------ 
# Pod Identity
# ------------------------------------------------------------------------ 
module "aws_vpc_cni_ipv4_pod_identity" {
  source = "terraform-aws-modules/eks-pod-identity/aws"

  name = "${var.project_name}-${var.env}-eks-vpccni-pid-role-v${replace(var.eks_version, ".", "_")}"
  use_name_prefix           = false
  aws_vpc_cni_policy_name   = "${var.project_name}-${var.env}-eks-vpccni-pid-pol-v${replace(var.eks_version, ".", "_")}"
  attach_aws_vpc_cni_policy = true
  aws_vpc_cni_enable_ipv4   = true
  
  tags = local.default_tags
}

module "aws_ebs_csi_pod_identity" {
  source = "terraform-aws-modules/eks-pod-identity/aws"

  name = "${var.project_name}-${var.env}-eks-ebscsi-pid-role-v${replace(var.eks_version, ".", "_")}"
  use_name_prefix           = false
  aws_ebs_csi_policy_name   = "${var.project_name}-${var.env}-eks-ebscsi-pid-pol-v${replace(var.eks_version, ".", "_")}"
  attach_aws_ebs_csi_policy = true
  
  tags = local.default_tags
}

module "aws_efs_csi_pod_identity" {
  source = "terraform-aws-modules/eks-pod-identity/aws"

  name = "${var.project_name}-${var.env}-eks-efscsi-pid-role-v${replace(var.eks_version, ".", "_")}"
  use_name_prefix           = false
  aws_efs_csi_policy_name   = "${var.project_name}-${var.env}-eks-efscsi-pid-pol-v${replace(var.eks_version, ".", "_")}"
  attach_aws_efs_csi_policy = true
  
  tags = local.default_tags
}

module "aws_lb_controller_pod_identity" { 
  source = "terraform-aws-modules/eks-pod-identity/aws"

  name = "${var.project_name}-${var.env}-eks-lbc-pid-role-v${replace(var.eks_version, ".", "_")}"
  use_name_prefix                 = false
  aws_lb_controller_policy_name   = "${var.project_name}-${var.env}-eks-lbc-pid-pol-v${replace(var.eks_version, ".", "_")}"
  attach_aws_lb_controller_policy = true
  
  association_defaults = {
    namespace       = "kube-system"
    service_account = "aws-load-balancer-controller-sa"
  }
  associations = {
    cluster = {
      cluster_name = module.eks.cluster_name
    }
  }
  
  tags = local.default_tags
}

module "cluster_autoscaler_pod_identity" {
  source = "terraform-aws-modules/eks-pod-identity/aws"

  name = "${var.project_name}-${var.env}-eks-ca-pid-role-v${replace(var.eks_version, ".", "_")}"
  use_name_prefix                  = false
  cluster_autoscaler_policy_name   = "${var.project_name}-${var.env}-eks-ca-pid-pol-v${replace(var.eks_version, ".", "_")}"
  attach_cluster_autoscaler_policy = true
  cluster_autoscaler_cluster_names = [module.eks.cluster_name]
  
  association_defaults = {
    namespace       = "kube-system"
    service_account = "cluster-autoscaler-sa"
  }
  associations = {
    cluster = {
      cluster_name = module.eks.cluster_name
    }
  }

  tags = local.default_tags
}


##########################################################################################
### Supporting Resource
##########################################################################################
# https://github.com/terraform-aws-modules/terraform-aws-iam/blob/master/examples/iam-assumable-role/README.md
# 환경별 정책 확인 후 변경 필요
module "eks_node_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
    
  trusted_role_services = [
    "ec2.amazonaws.com"
  ]
    
  create_role             = true
  role_name               = "${var.project_name}-${var.env}-eks-node-role-v${replace(var.eks_version, ".", "_")}"
  role_requires_mfa       = false
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonElasticFileSystemFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::934563315680:policy/ssm-agent-cloudwatch-logs-put-policy",
    "arn:aws:iam::934563315680:policy/custom-ClusterAutoScaler-pol",
    "arn:aws:iam::934563315680:policy/custom-autorun-sms-s3-allow-pol"
  ]
}
