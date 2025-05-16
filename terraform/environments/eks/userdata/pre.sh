ec2ip=$(ifconfig eth0 | grep -w inet | awk '{ print $2 }'  | tr '.' '-' )
tagName="${service}-${env}-eks-node-${node_role}-v${version}-"$ec2ip
Instance_id=`curl -s http://169.254.169.254/latest/meta-data/instance-id/`
vol_id=`aws ec2 describe-instances --instance-ids $${Instance_id} --region ap-northeast-2 --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' | sed 's/\"//g'`

echo $(aws ec2 create-tags --resources $${Instance_id} --tags Key="Name",Value=$tagName --region ap-northeast-2)
echo $(aws ec2 create-tags --resources $${vol_id} --tags Key=Name,Value=$tagName-root-ebs Key=Env,Value=${env} Key=Service,Value=${service} --region ap-northeast-2)
