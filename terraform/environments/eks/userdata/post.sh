aws s3 cp s3://thm-prd-pri-eks-userdata-s3/thm-eks-userdata-deepsecurity.sh /
chmod 700 thm-eks-userdata-deepsecurity.sh
./thm-eks-userdata-deepsecurity.sh > userdata-deepsecurity-log-`date '+%Y%m%d'`.txt 2>&1
rm -rf thm-eks-userdata-deepsecurity.sh

sleep 30 && /opt/ds_agent/dsa_control -r
/opt/ds_agent/dsa_control -a dsm://10.217.248.42:4120/ "policyid:14"
sleep 30 && /opt/ds_agent/dsa_control -m dsm://10.217.248.42:4120/ 'RecommendationScan:true' >> /tmp/AgentDeploymentScript.log &