##########################################################################################
### Launch Template
##########################################################################################
## terraform-aws-modules-eks 모듈을 통해서 시작템플릿을 생성하지 않는 이유
# terraform-aws-modules-eks 모듈에서는 'enable_bootstrap_user_data=true' Input을 설정하면 서브 모듈인 _user_data를 통해 Output으로 userdata를 생성해준다
# 하지만 이 서브 모듈을 통해 생성된 userdata(output)은 서브 모듈인 eks-managed-node-group 내의 Input인 'create_launch_template=true'를 설정했을 때 생성된 시작템플릿에 붙도록 되어있다
# 아래 eks-managed-node-group 서브 모듈 코드를 보면 1개의 시작템플릿만 생성하도록 되어있다
# https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/modules/eks-managed-node-group/main.tf#L72

## 서브 모듈인 _user_data를 직접 선언하여 사용하는 이유
# 위의 EKS v1.30부터 AL2023을 사용하는 이슈로, AL2를 사용하도록 Custom AMI를 직접 지정해야한다
# Custom AMI + Custom Launch Template 환경에서는 EKS에서 시작템플릿에 클러스터 조인을 위한 bootstrap.sh 스크립트를 자동으로 추가해주지 않는다
# 따라서 해당 스크립트를 직접 작성해야하는데, 테라폼 코드에 하드코딩하지 않기 위해 직접 선언하여 userdata를 편리하게 생성하고, output을 시작템플릿에 추가해주었다

# 서브 모듈 _user_data
# https://github.com/terraform-aws-modules/terraform-aws-eks/blob/master/modules/_user_data/README.md
# https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/latest/submodules/_user_data 내 Provision Instructions 참고
module "eks_user_data" { 
  source  = "terraform-aws-modules/eks/aws//modules/_user_data"
  version = "20.31.6"

  for_each = var.eks_nodegroup_info
  
  ami_type             = "AL2_x86_64"
  cluster_name         = module.eks.cluster_name
  cluster_endpoint     = module.eks.cluster_endpoint
  cluster_auth_base64  = module.eks.cluster_certificate_authority_data
  cluster_ip_family    = module.eks.cluster_ip_family
  cluster_service_cidr = module.eks.cluster_service_cidr

  enable_bootstrap_user_data = true

  // 부트스트랩 실행 전(pre)
  pre_bootstrap_user_data = try(
    templatefile("${path.module}/userdata/${each.value.userdata[0]}", {
      service   = var.project_name,
      env       = var.env,
      node_role = each.key,
      version   = replace(var.eks_version, ".", "_")
    }), ""
  )
  
  // 클러스터 조인을 위한 부트스트랩 실행
  bootstrap_extra_args = "--kubelet-extra-args '--node-labels=node-group=${each.key}'"
  user_data_template_path = "${path.module}/userdata/bootstrap_al2.tpl"  // 동적 변수 할당은 모듈이 수행하므로 file 또는 templatefile 선언 필요없음
  
  // 부트스트랩 실행 후(post)
  post_bootstrap_user_data = try(
    templatefile("${path.module}/userdata/${each.value.userdata[1]}", {
      service   = var.project_name,
      env       = var.env,
      node_role = each.key
    }), ""
  )
}

resource "aws_launch_template" "lt" {  // 다른 모듈에서 key기반으로 for_each를 통해 사용해야하므로 output 별도 선언
  for_each = var.eks_nodegroup_info
  
  name                   = "${var.project_name}-${var.env}-eks-${each.key}-template-v${replace(var.eks_version, ".", "_")}"
  image_id               = each.value.image_id
  instance_type          = each.value.instance_type
  key_name               = var.lt_keypair_name
  vpc_security_group_ids = concat(var.eks_node_sg_ids, [module.eks.cluster_primary_security_group_id])
  user_data              = module.eks_user_data[each.key].user_data
  
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = each.value.disk_capacity
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }
  dynamic "tag_specifications" {  # 시작 템플릿을 통해 생성된 리소스에 태그 추가
  for_each = toset(var.lt_resource_tags)
    content {
      resource_type = tag_specifications.key
      tags = {
        Service = var.project_name
        Env     = var.env
      }
    }
  }
  
  tags = local.default_tags
}
