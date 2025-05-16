%{ if enable_bootstrap_user_data ~}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="//"
--//
Content-Type: text/x-shellscript; charset="us-ascii"
#!/bin/bash
%{ endif ~}
${pre_bootstrap_user_data ~}
%{ if enable_bootstrap_user_data ~}
set -ex
B64_CLUSTER_CA=${cluster_auth_base64}
API_SERVER_URL=${cluster_endpoint}
/etc/eks/bootstrap.sh ${cluster_name} ${bootstrap_extra_args} --b64-cluster-ca $B64_CLUSTER_CA --apiserver-endpoint $API_SERVER_URL
${post_bootstrap_user_data ~}
--//--
%{ endif ~}