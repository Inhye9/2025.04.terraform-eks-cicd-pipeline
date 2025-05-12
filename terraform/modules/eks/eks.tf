# 데이터 소스를 통해 테라폼에서 리소스 생성 시 필요한 AWS 정보들을 가져온다
data "aws_availability_zones" "available" {}                       
data "aws_caller_identity" "current" {}  // IAM User 또는 Role 정보
data "aws_eks_cluster_auth" "eks" {name = module.eks.cluster_name}  // EKS와 통신을 위한 인증 토큰

##########################################################################################
### EKS Cluster
##########################################################################################
# https://github.com/terraform-aws-modules/terraform-aws-eks/tree/master
# terraform-aws-eks 모듈을 사용하여 Cluster 생성

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "v20.31.6"  // v20 부터 aws-auth가 아닌 access_entries를 기본으로 사용함

  ## General
  cluster_name                   = "${var.project_name}-${var.env}-eks-cluster-v${replace(var.eks_version, ".", "_")}"
  cluster_version                = var.eks_version
  cluster_upgrade_policy         = { support_type = "STANDARD" }
  cluster_service_ipv4_cidr      = "172.20.0.0/16"
  cluster_endpoint_public_access = false
  authentication_mode            = "API"
  
  vpc_id                         = var.eks_vpc_id
  subnet_ids                     = var.eks_subnet_ids  
  //control_plane_subnet_ids       = var.eks_controlplane_subnet_ids // 설정 시 subnet_id 값은 무시되서 퍼블릭 서브넷이 안붙는다. 내가 의도한 동작을하는 옵션이 아닌듯.

  ## Encryption
  cluster_encryption_config      = {}  // {} is disabled
  create_kms_key                 = false

  ## Access Entries
  // https://docs.aws.amazon.com/ko_kr/eks/latest/userguide/access-entries.html
  // https://github.com/terraform-aws-modules/terraform-aws-eks-pod-identity/blob/master/README.md
  enable_cluster_creator_admin_permissions = true // EKS 생성 주체, Node Role 자동 추가
  access_entries = {
    jenkins = {
      user_name     = "jenkins"
      principal_arn = "arn:aws:iam::934563315680:role/thm-dev-jenkins-role"
      type = "STANDARD"
      policy_associations = {
        jenkins = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
            // namespaces = ["default"]
            // type       = "namespace"
          }
        }
      }
    }
  }
  
  ## Logging
  cluster_enabled_log_types              = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  create_cloudwatch_log_group            = true
  cloudwatch_log_group_retention_in_days = 7
  
  ## Security Group
  // 클러스터 보안그룹과 규칙은 EKS에서 자동 생성하므로 커스터마이징이 불가능하며 규칙은 생성 이후 최소권한으로 수동 변경 필요
  // terraform-aws-eks 모듈에서는 클러스터 보안그룹을 cluster_primary_security_group로, 추가 보안그룹을 cluster_security_group로 정의해서 사용한다.
  
  # 클러스터 보안그룹
  create_cluster_primary_security_group_tags = true
  
  # 추가 보안그룹
  cluster_additional_security_group_ids  = var.eks_additional_sg_ids
  create_cluster_security_group          = true
  cluster_security_group_name            = "${var.project_name}-${var.env}-eks-controlplane-sg-v${replace(var.eks_version, ".", "_")}"
  cluster_security_group_use_name_prefix = false
  # cluster_security_group_additional_rules = {
  #   ingress_nodes_443 = {
  #     description                = "Node groups to cluster API"
  #     protocol                   = "tcp"
  #     from_port                  = 443
  #     to_port                    = 443
  #     type                       = "ingress"
  #     source_node_security_group = true
  #   }
    
  #   ingress_workbench_443 = {
  #     description              = "Workbench to cluster API"
  #     protocol                 = "tcp"
  #     from_port                = 443
  #     to_port                  = 443
  #     type                     = "ingress"
  #     source_security_group_id = var.workbench_sg_id
  #   }     
  # }

  # 노드 보안그룹
  create_node_security_group = false
  # node_security_group_id     = ""  // eks module에서는 노드 보안그룹은 1개만 추가 가능, 시작 템플릿 사용
  # node_security_group_name                     = "${var.project_name}-${var.env}-eks-node-v${replace(var.eks_version, ".", "_")}-sg"
  # node_security_group_use_name_prefix          = false
  # node_security_group_enable_recommended_rules = true

  ## Cluster IAM Role
  iam_role_name            = "${var.project_name}-${var.env}-eks-cluster-role-v${replace(var.eks_version, ".", "_")}"
  iam_role_use_name_prefix = false

  ## Cluster Addons
  // pod-identity-agent를 사용할 경우, vpc-cni와 순환 종속성 문제가 있음
  // 해당 이슈는 terraform의 리소스 생성 특성(무작위)에 따라 간헐적으로 발생하며, 약 15분정도 이후 정상 처리됨.
  // 또한 terraform apply 실행 시 helm-chart 설치를 위한 token을 발급하는데, 이 토큰의 유효기간이 15분이라 helm chart 설치 에러(timeout)가 발생한다.
  // 실패 시 terraform apply를 한번 더 실행해주면 토큰이 갱신되면서 helm-chart 설치가 가능함.
  // https://github.com/terraform-aws-modules/terraform-aws-eks/issues/3260
  // https://github.com/hashicorp/terraform/issues/29182
  cluster_addons = {
    eks-pod-identity-agent = {
      addon_version  = var.eks_addon_versions["eks-pod-identity-agent"]
      before_compute = true
    }
    
    vpc-cni = {
      // most_recent              = true
      addon_version            = "v1.19.2-eksbuild.1"
      before_compute           = true  // VPC CNI 애드온이 우선 설치되어야 노드가 클러스터에 정상적으로 조인할 수 있음
      resolve_conflicts        = "OVERWRITE"
      # configuration_values     = jsonencode({
      #   env = {
      #     ENABLE_PREFIX_DELEGATION = "true"  // prefix assignment mode 활성화
      #     WARM_PREFIX_TARGET       = "1"  // 기본 권장 값
      #   }
      # })
      pod_identity_association = [{
        role_arn = module.aws_vpc_cni_ipv4_pod_identity.iam_role_arn
        service_account = "aws-node"
      }]
    }
    
    kube-proxy = {
      addon_version = var.eks_addon_versions["kube-proxy"]
    }

    coredns = {
      addon_version        = var.eks_addon_versions["coredns"]
      configuration_values = jsonencode({
        nodeSelector = {
          "node-group" = "mgmt"
        }
      })
    }
    
    aws-ebs-csi-driver = {
      addon_version        = var.eks_addon_versions["aws-ebs-csi-driver"]
      configuration_values = jsonencode({
        "controller": {
          "nodeSelector": {
            "node-group": "mgmt"
          }
        },
        "sidecars": {
          "snapshotter": {
            "forceEnable": false
          }
        }
      })
      pod_identity_association = [{
        role_arn = module.aws_ebs_csi_pod_identity.iam_role_arn
        service_account = "ebs-csi-controller-sa"
      }]      
    }
      
    aws-efs-csi-driver = {
      addon_version        = var.eks_addon_versions["aws-efs-csi-driver"]
      configuration_values = jsonencode({
        "controller": {
          "nodeSelector": {
            "node-group": "mgmt"
          }
        }
      })
      pod_identity_association = [{
        role_arn = module.aws_efs_csi_pod_identity.iam_role_arn
        service_account = "efs-csi-controller-sa"
      }]      
    }

    metrics-server = {
      addon_version        = var.eks_addon_versions["metrics-server"]
      configuration_values = jsonencode({
        nodeSelector = {
          "node-group" = "mgmt"
        }
      })      
    }
  }

##########################################################################################
### EKS Managed NodeGroup
##########################################################################################
# https://github.com/terraform-aws-modules/terraform-aws-eks/tree/master/modules/eks-managed-node-group
# eks-managed-node-group 서브 모듈을 사용하여 Managed NodeGroup 설정

  eks_managed_node_group_defaults = {  // 노드 그룹에 사용할 공통 사항 정의
    cluster_version            = ""  // 시작템플릿에서 image_id 지정 시, 즉 Custom AMI 사용 시 null 설정 필요
    use_name_prefix            = false  // 노드 그룹 이름의 Prefix
    subnet_ids                 = var.eks_controlplane_subnet_ids // 노드도 private subnet에서만 생성되도록 설정
    create_launch_template     = false
    use_custom_launch_template = true
    
    ## Node IAM Role
    // eks-managed-node-group 서브 모듈에서는 노드 그룹별로 노드 Role을 생성하도록 구현되어있어서, 모든 노드 그룹에 단일 Role을 사용하려면 별도 생성하여 arn 설정 필요
    // https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/modules/eks-managed-node-group/main.tf#L526
    iam_role_arn               = module.eks_node_role.iam_role_arn
    create_iam_role            = false
    
    # 노드 그룹별 IAM Role 생성
    // iam_role_name              = "${var.project_name}-${var.env}-eks-node-v${replace(var.eks_version, ".", "_")}-role"
    // iam_role_use_name_prefix   = false
    // iam_role_attach_cni_policy = true
  }
  
  ## eks_managed_node_groups와 같은 데이터블록 수준에서는 for_each 반복문 사용 불가능하여 직접 수정해야함
  eks_managed_node_groups = {  // 노드 그룹 정의
    app = {
      name               = "${var.project_name}-${var.env}-eks-app-ng-v${replace(var.eks_version, ".", "_")}"
      launch_template_id = aws_launch_template.lt["app"].id
      desired_size       = var.eks_nodegroup_info.app.node_capacity[0]
      min_size           = var.eks_nodegroup_info.app.node_capacity[1]
      max_size           = var.eks_nodegroup_info.app.node_capacity[2]

      labels = {  // kubernetes labels
        node-group = "app"
      }       
    } 
    
    batch = {
      name               = "${var.project_name}-${var.env}-eks-batch-ng-v${replace(var.eks_version, ".", "_")}"
      launch_template_id = aws_launch_template.lt["batch"].id
      desired_size       = var.eks_nodegroup_info.batch.node_capacity[0]
      min_size           = var.eks_nodegroup_info.batch.node_capacity[1]
      max_size           = var.eks_nodegroup_info.batch.node_capacity[2]

      labels = {  // kubernetes labels
        node-group = "batch"
      }       
    } 
    
    front = {
      name               = "${var.project_name}-${var.env}-eks-front-ng-v${replace(var.eks_version, ".", "_")}"
      launch_template_id = aws_launch_template.lt["front"].id
      desired_size       = var.eks_nodegroup_info.front.node_capacity[0]
      min_size           = var.eks_nodegroup_info.front.node_capacity[1]
      max_size           = var.eks_nodegroup_info.front.node_capacity[2]
      
      labels = {  // kubernetes labels
        node-group = "front"
      }        
    }
  
    mgmt = {
      name               = "${var.project_name}-${var.env}-eks-mgmt-ng-v${replace(var.eks_version, ".", "_")}"
      launch_template_id = aws_launch_template.lt["mgmt"].id
      desired_size       = var.eks_nodegroup_info.mgmt.node_capacity[0]
      min_size           = var.eks_nodegroup_info.mgmt.node_capacity[1]
      max_size           = var.eks_nodegroup_info.mgmt.node_capacity[2]
      
      labels = {  // kubernetes labels
        node-group = "mgmt"
      }       
    } 
  }
   
  tags = local.default_tags
}


##########################################################################################
### Pod Identity
##########################################################################################
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
### HELM
##########################################################################################
# https://registry.terraform.io/providers/hashicorp/helm/latest/docs/resources/release
# https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.5/
# 추후 관리형 에드온을 포함한 모든 에드온 통합 관리 가능한 eks_blueprints_addons 모듈로 대체
# eks_blueprints_addons 모듈이 아직 Pod Identity를 지원하지 않아 적용하지 않았으며 Helm 설치 적용

resource "helm_release" "aws-load-balancer-controller" {
  repository = "https://aws.github.io/eks-charts"  
  chart      = "aws-load-balancer-controller"  // Helm 차트 패키지 이름  
  name       = "aws-load-balancer-controller"  // EKS 배포 시 설정할 차트 이름
  namespace  = "kube-system"
  version    = var.eks_addon_versions["aws-lb-controller"]
  timeout    = 10000 // 15분 토큰 만료 해결 test

  dynamic "set" {
    for_each = {
      "clusterName"             = module.eks.cluster_name
      "serviceAccount.create"   = "true"
      "serviceAccount.name"     = "aws-load-balancer-controller-sa"
      "nodeSelector.node-group" = "mgmt"
      // 아래 옵션은 사용하지 않지만 기본값이 true임, 불필요한 로깅 방지를 위해 비활성화
      "enableShield"            = "false"
      "enableWaf"               = "false"
      "enableWafv2"             = "false"
    }
    content {
      name =  set.key
      value = set.value
    }
  }
  depends_on = [module.aws_lb_controller_pod_identity]  
}


resource "helm_release" "cluster-autoscaler" {
  repository = "https://kubernetes.github.io/autoscaler"
  chart      = "cluster-autoscaler"  // Helm 차트 패키지 이름
  name       = "cluster-autoscaler"  // EKS 배포 시 설정할 차트 이름
  namespace  = "kube-system"
  version    = var.eks_addon_versions["cluster-autoscaler"]
  timeout    = 10000 // 15분 토큰 만료 해결 test

  dynamic "set" {
    for_each = {
      "fullnameOverride"                                  = "cluster-autoscaler"
      "autoDiscovery.clusterName"                         = module.eks.cluster_name
      "awsRegion"                                         = "ap-northeast-2"
      "rbac.serviceAccount.create"                        = "true"
      "rbac.serviceAccount.name"                          = "cluster-autoscaler-sa"
      "securityContext.runAsNonRoot"                      = "true"
      "securityContext.runAsUser"                         = "65534"
      "securityContext.fsGroup"                           = "65534"
      "securityContext.seccompProfile.type"               = "RuntimeDefault"
      "containers.resources.limits.cpu"                   = "100m"
      "containers.resources.limits.memory"                = "600Mi"
      "containers.resources.requests.cpu"                 = "100m"
      "containers.resources.requests.memory"              = "600Mi"
      "extraArgs.skip-nodes-with-local-storage"           = "false"
      "extraArgs.expander"                                = "least-waste"
      "extraArgs.balance-similar-node-groups"             = "true"
      "extraArgs.skip-nodes-with-system-pods"             = "false"
      "extraArgs.scale-down-delay-after-add"              = "3m"
      "extraArgs.scale-down-unneeded-time"                = "3m"
      "containerSecurityContext.allowPrivilegeEscalation" = "false"
      "containerSecurityContext.capabilities.drop[0]"     = "ALL"
      "containerSecurityContext.readOnlyRootFilesystem"   = "true"
    }
    content {
      name =  set.key
      value = set.value
    }
  }
  depends_on = [module.cluster_autoscaler_pod_identity]
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
    "arn:aws:iam::934563315680:policy/thm-dev-ClusterAutoScaler-pol",
    "arn:aws:iam::934563315680:policy/thm-dev-pri-autorun-sms-s3-allow-pol"
  ]
}
