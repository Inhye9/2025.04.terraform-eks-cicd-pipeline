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


