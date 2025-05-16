// 클러스터명 : [project_name]-[env]-cluster-v[eks_version]
variable "region" {
  description = "AWS region"
  type        = string
}

variable "project_name" {
  description = "Project Name"
  type        = string
}

variable "profile" {
  description = "AWS Profile Name"
  type        = string
}

variable "env" {
  type        = string
  default     = "test"
}

variable "eks_version" {
  type        = string
  default     = "1.31"
}

variable "vpc_id" {
  description = "AWS VPC ID"
  type        = string
}

# variable "eks_subnet_ids" {
#   description = "EKS 생성 시 설정하는 서브넷 목록(퍼블릭 서브넷 포함)"
#   type        = list(string)
#   default     = []
# }

# variable "eks_controlplane_subnet_ids" {
#   description = "EKS 생성 시 컨트롤 플레인 ENI를 생성할 서브넷 목록"
#   type        = list(string)
#   default     = []  // 테스트용이 아닌 경우 private subnet만 설정 권장
# }

variable "eks_additional_sg_ids" {
  description = "EKS에 연결할 추가 보안그룹 ID 목록"
  type        = list(string)
  default     = []
}

variable "eks_node_sg_ids" {
  description = "EKS 노드에 연결할 보안그룹 ID 목록. 시작템플릿에 설정됨"
  type        = list(string)
  default     = []
}

variable "eks_addon_versions" {  // k8s 버전과 add-on 버전 호환 확인(aws eks describe-addon-versions --addon-name [add-on 명] --kubernetes-version [k8s 버전명])
  description = "EKS에 설치할 Add-On 버전 정의" 
  type        = map(string)
  default = {              // for EKS v1.31
    vpc-cni                = "v1.19.2-eksbuild.1"
    eks-pod-identity-agent = "v1.3.4-eksbuild.1"
    kube-proxy             = "v1.31.2-eksbuild.3"
    metrics-server         = "v0.7.2-eksbuild.1"
    coredns                = "v1.11.3-eksbuild.1"
    aws-ebs-csi-driver     = "v1.38.1-eksbuild.1"
    aws-efs-csi-driver     = "v2.1.3-eksbuild.1"
    aws-lb-controller      = "1.5.3"  // 헬름 차트 버전 기입 Helm chart ver v1.5.3 // Add-On ver v2.10.1
    cluster-autoscaler     = ""       // 헬름 차트 버전 기입 Helm chart ver v.     // Add-On ver v1.31.1
  }
}

variable "eks_node_name_info" {
  description = "생성할 노드그룹명 정의"
  type        = list(string)
  default     = ["app", "mgmt"]
}

# https://blog.wimwauters.com/devops/2022-03-01_terraformusecases/
variable "eks_nodegroup_info" {
  description = "노드그룹별 상세 설정 정의"
  type        = map(object({
    image_id      = string,       // ami-012714cd802de2bd9(amazon-eks-node-1.31-v20241225)
    instance_type = string,
    disk_capacity = number,       // GB
    node_capacity = list(number)  // desired, min, max
    userdata      = list(string)  // pre_userdata_filename(클러스터 조인 전 실행), post_userdata_filename(클러스터 조인 후 실행)
  }))
  default     = {}
}

variable "lt_keypair_name" {
  description = "EKS 노드 생성 시 사용할 키페어명 정의"
  type        = string
  default     = ""
}

variable "workbench_sg_id" { 
  description = "EKS API를 호출하는 용도의 인스턴스 접근 허용을 위한 보안그룹 ID"
  type        = string
  default     = ""
}

variable "lt_resource_tags" {
  description = "시작 템플릿을 통해 생성된 리소스에 자동으로 태그를 추가하고자 하는 리소스"
  type    = set(string)
  default = ["instance", "volume", "network-interface"]
}


variable "jenkins_ec2_arn" {
  description = "Jenkins EC2 ARN"
  type        = string
}
