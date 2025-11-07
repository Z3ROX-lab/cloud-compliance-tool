import boto3
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger()


class AWSScanner:
    """AWS Cloud Scanner - Discovers and analyzes AWS resources"""

    def __init__(self, access_key: Optional[str] = None, secret_key: Optional[str] = None, region: str = "eu-west-1"):
        """Initialize AWS scanner with credentials"""
        self.region = region
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        logger.info("AWS Scanner initialized", region=region)

    def scan_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scan all AWS resources"""
        logger.info("Starting full AWS scan")

        resources = {
            "ec2_instances": self.scan_ec2_instances(),
            "s3_buckets": self.scan_s3_buckets(),
            "iam_users": self.scan_iam_users(),
            "iam_roles": self.scan_iam_roles(),
            "iam_policies": self.scan_iam_policies(),
            "vpc": self.scan_vpcs(),
            "security_groups": self.scan_security_groups(),
            "cloudtrail": self.scan_cloudtrail(),
            "rds_instances": self.scan_rds_instances(),
            "lambda_functions": self.scan_lambda_functions(),
            "ebs_volumes": self.scan_ebs_volumes(),
            "ebs_snapshots": self.scan_ebs_snapshots(),
            "kms_keys": self.scan_kms_keys(),
            "cloudwatch_alarms": self.scan_cloudwatch_alarms(),
            "load_balancers": self.scan_load_balancers(),
        }

        logger.info("AWS scan completed", total_resources=sum(len(v) for v in resources.values()))
        return resources

    def scan_ec2_instances(self) -> List[Dict[str, Any]]:
        """Scan EC2 instances"""
        try:
            ec2 = self.session.client('ec2')
            response = ec2.describe_instances()

            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append({
                        "resource_id": instance['InstanceId'],
                        "resource_type": "EC2Instance",
                        "resource_name": self._get_tag_value(instance.get('Tags', []), 'Name'),
                        "region": self.region,
                        "metadata": {
                            "instance_type": instance.get('InstanceType'),
                            "state": instance.get('State', {}).get('Name'),
                            "launch_time": instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                            "vpc_id": instance.get('VpcId'),
                            "subnet_id": instance.get('SubnetId'),
                            "public_ip": instance.get('PublicIpAddress'),
                            "private_ip": instance.get('PrivateIpAddress'),
                            "security_groups": instance.get('SecurityGroups', []),
                            "iam_instance_profile": instance.get('IamInstanceProfile'),
                            "monitoring": instance.get('Monitoring', {}).get('State'),
                            "ebs_optimized": instance.get('EbsOptimized'),
                        },
                        "tags": instance.get('Tags', [])
                    })

            logger.info("EC2 instances scanned", count=len(instances))
            return instances
        except Exception as e:
            logger.error("Failed to scan EC2 instances", error=str(e))
            return []

    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """Scan S3 buckets"""
        try:
            s3 = self.session.client('s3')
            response = s3.list_buckets()

            buckets = []
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']

                # Get bucket details
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                    logging = s3.get_bucket_logging(Bucket=bucket_name)
                except Exception as e:
                    logger.warning("Failed to get bucket details", bucket=bucket_name, error=str(e))
                    location = versioning = encryption = acl = public_access_block = logging = {}

                buckets.append({
                    "resource_id": f"arn:aws:s3:::{bucket_name}",
                    "resource_type": "S3Bucket",
                    "resource_name": bucket_name,
                    "region": location.get('LocationConstraint', 'us-east-1'),
                    "metadata": {
                        "creation_date": bucket['CreationDate'].isoformat() if bucket.get('CreationDate') else None,
                        "versioning": versioning.get('Status'),
                        "encryption": encryption.get('ServerSideEncryptionConfiguration'),
                        "acl": acl.get('Grants', []),
                        "public_access_block": public_access_block.get('PublicAccessBlockConfiguration'),
                        "logging": logging.get('LoggingEnabled'),
                    },
                    "tags": []
                })

            logger.info("S3 buckets scanned", count=len(buckets))
            return buckets
        except Exception as e:
            logger.error("Failed to scan S3 buckets", error=str(e))
            return []

    def scan_iam_users(self) -> List[Dict[str, Any]]:
        """Scan IAM users"""
        try:
            iam = self.session.client('iam')
            response = iam.list_users()

            users = []
            for user in response.get('Users', []):
                user_name = user['UserName']

                # Get MFA devices
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=user_name)
                    access_keys = iam.list_access_keys(UserName=user_name)
                except Exception:
                    mfa_devices = {"MFADevices": []}
                    access_keys = {"AccessKeyMetadata": []}

                users.append({
                    "resource_id": user['Arn'],
                    "resource_type": "IAMUser",
                    "resource_name": user_name,
                    "region": "global",
                    "metadata": {
                        "user_id": user['UserId'],
                        "path": user.get('Path'),
                        "create_date": user.get('CreateDate').isoformat() if user.get('CreateDate') else None,
                        "password_last_used": user.get('PasswordLastUsed').isoformat() if user.get('PasswordLastUsed') else None,
                        "mfa_enabled": len(mfa_devices.get('MFADevices', [])) > 0,
                        "mfa_devices_count": len(mfa_devices.get('MFADevices', [])),
                        "access_keys_count": len(access_keys.get('AccessKeyMetadata', [])),
                    },
                    "tags": user.get('Tags', [])
                })

            logger.info("IAM users scanned", count=len(users))
            return users
        except Exception as e:
            logger.error("Failed to scan IAM users", error=str(e))
            return []

    def scan_iam_roles(self) -> List[Dict[str, Any]]:
        """Scan IAM roles"""
        try:
            iam = self.session.client('iam')
            response = iam.list_roles()

            roles = []
            for role in response.get('Roles', []):
                roles.append({
                    "resource_id": role['Arn'],
                    "resource_type": "IAMRole",
                    "resource_name": role['RoleName'],
                    "region": "global",
                    "metadata": {
                        "role_id": role['RoleId'],
                        "path": role.get('Path'),
                        "create_date": role.get('CreateDate').isoformat() if role.get('CreateDate') else None,
                        "assume_role_policy": role.get('AssumeRolePolicyDocument'),
                        "max_session_duration": role.get('MaxSessionDuration'),
                    },
                    "tags": role.get('Tags', [])
                })

            logger.info("IAM roles scanned", count=len(roles))
            return roles
        except Exception as e:
            logger.error("Failed to scan IAM roles", error=str(e))
            return []

    def scan_iam_policies(self) -> List[Dict[str, Any]]:
        """Scan IAM policies"""
        try:
            iam = self.session.client('iam')
            response = iam.list_policies(Scope='Local')

            policies = []
            for policy in response.get('Policies', []):
                policies.append({
                    "resource_id": policy['Arn'],
                    "resource_type": "IAMPolicy",
                    "resource_name": policy['PolicyName'],
                    "region": "global",
                    "metadata": {
                        "policy_id": policy['PolicyId'],
                        "path": policy.get('Path'),
                        "create_date": policy.get('CreateDate').isoformat() if policy.get('CreateDate') else None,
                        "update_date": policy.get('UpdateDate').isoformat() if policy.get('UpdateDate') else None,
                        "attachment_count": policy.get('AttachmentCount'),
                        "is_attachable": policy.get('IsAttachable'),
                    },
                    "tags": policy.get('Tags', [])
                })

            logger.info("IAM policies scanned", count=len(policies))
            return policies
        except Exception as e:
            logger.error("Failed to scan IAM policies", error=str(e))
            return []

    def scan_vpcs(self) -> List[Dict[str, Any]]:
        """Scan VPCs"""
        try:
            ec2 = self.session.client('ec2')
            response = ec2.describe_vpcs()

            vpcs = []
            for vpc in response.get('Vpcs', []):
                vpcs.append({
                    "resource_id": vpc['VpcId'],
                    "resource_type": "VPC",
                    "resource_name": self._get_tag_value(vpc.get('Tags', []), 'Name'),
                    "region": self.region,
                    "metadata": {
                        "cidr_block": vpc.get('CidrBlock'),
                        "state": vpc.get('State'),
                        "is_default": vpc.get('IsDefault'),
                        "dhcp_options_id": vpc.get('DhcpOptionsId'),
                        "instance_tenancy": vpc.get('InstanceTenancy'),
                    },
                    "tags": vpc.get('Tags', [])
                })

            logger.info("VPCs scanned", count=len(vpcs))
            return vpcs
        except Exception as e:
            logger.error("Failed to scan VPCs", error=str(e))
            return []

    def scan_security_groups(self) -> List[Dict[str, Any]]:
        """Scan Security Groups"""
        try:
            ec2 = self.session.client('ec2')
            response = ec2.describe_security_groups()

            security_groups = []
            for sg in response.get('SecurityGroups', []):
                security_groups.append({
                    "resource_id": sg['GroupId'],
                    "resource_type": "SecurityGroup",
                    "resource_name": sg.get('GroupName'),
                    "region": self.region,
                    "metadata": {
                        "description": sg.get('Description'),
                        "vpc_id": sg.get('VpcId'),
                        "ingress_rules": sg.get('IpPermissions', []),
                        "egress_rules": sg.get('IpPermissionsEgress', []),
                    },
                    "tags": sg.get('Tags', [])
                })

            logger.info("Security Groups scanned", count=len(security_groups))
            return security_groups
        except Exception as e:
            logger.error("Failed to scan Security Groups", error=str(e))
            return []

    def scan_cloudtrail(self) -> List[Dict[str, Any]]:
        """Scan CloudTrail trails"""
        try:
            cloudtrail = self.session.client('cloudtrail')
            response = cloudtrail.describe_trails()

            trails = []
            for trail in response.get('trailList', []):
                trail_name = trail['Name']

                # Get trail status
                try:
                    status = cloudtrail.get_trail_status(Name=trail_name)
                except Exception:
                    status = {}

                trails.append({
                    "resource_id": trail['TrailARN'],
                    "resource_type": "CloudTrail",
                    "resource_name": trail_name,
                    "region": trail.get('HomeRegion', self.region),
                    "metadata": {
                        "s3_bucket_name": trail.get('S3BucketName'),
                        "is_logging": status.get('IsLogging', False),
                        "is_multi_region_trail": trail.get('IsMultiRegionTrail', False),
                        "include_global_service_events": trail.get('IncludeGlobalServiceEvents', False),
                        "log_file_validation_enabled": trail.get('LogFileValidationEnabled', False),
                        "kms_key_id": trail.get('KmsKeyId'),
                        "latest_delivery_time": status.get('LatestDeliveryTime').isoformat() if status.get('LatestDeliveryTime') else None,
                    },
                    "tags": []
                })

            logger.info("CloudTrail trails scanned", count=len(trails))
            return trails
        except Exception as e:
            logger.error("Failed to scan CloudTrail", error=str(e))
            return []

    def scan_rds_instances(self) -> List[Dict[str, Any]]:
        """Scan RDS instances"""
        try:
            rds = self.session.client('rds')
            response = rds.describe_db_instances()

            instances = []
            for instance in response.get('DBInstances', []):
                instances.append({
                    "resource_id": instance['DBInstanceArn'],
                    "resource_type": "RDSInstance",
                    "resource_name": instance['DBInstanceIdentifier'],
                    "region": self.region,
                    "metadata": {
                        "engine": instance.get('Engine'),
                        "engine_version": instance.get('EngineVersion'),
                        "instance_class": instance.get('DBInstanceClass'),
                        "storage_encrypted": instance.get('StorageEncrypted'),
                        "multi_az": instance.get('MultiAZ'),
                        "publicly_accessible": instance.get('PubliclyAccessible'),
                        "backup_retention_period": instance.get('BackupRetentionPeriod'),
                        "auto_minor_version_upgrade": instance.get('AutoMinorVersionUpgrade'),
                        "deletion_protection": instance.get('DeletionProtection'),
                    },
                    "tags": instance.get('TagList', [])
                })

            logger.info("RDS instances scanned", count=len(instances))
            return instances
        except Exception as e:
            logger.error("Failed to scan RDS instances", error=str(e))
            return []

    def scan_lambda_functions(self) -> List[Dict[str, Any]]:
        """Scan Lambda functions"""
        try:
            lambda_client = self.session.client('lambda')
            response = lambda_client.list_functions()

            functions = []
            for function in response.get('Functions', []):
                functions.append({
                    "resource_id": function['FunctionArn'],
                    "resource_type": "LambdaFunction",
                    "resource_name": function['FunctionName'],
                    "region": self.region,
                    "metadata": {
                        "runtime": function.get('Runtime'),
                        "handler": function.get('Handler'),
                        "memory_size": function.get('MemorySize'),
                        "timeout": function.get('Timeout'),
                        "last_modified": function.get('LastModified'),
                        "role": function.get('Role'),
                        "environment": function.get('Environment'),
                    },
                    "tags": {}
                })

            logger.info("Lambda functions scanned", count=len(functions))
            return functions
        except Exception as e:
            logger.error("Failed to scan Lambda functions", error=str(e))
            return []

    def scan_ebs_volumes(self) -> List[Dict[str, Any]]:
        """Scan EBS volumes"""
        try:
            ec2 = self.session.client('ec2')
            response = ec2.describe_volumes()

            volumes = []
            for volume in response.get('Volumes', []):
                volumes.append({
                    "resource_id": volume['VolumeId'],
                    "resource_type": "EBSVolume",
                    "resource_name": self._get_tag_value(volume.get('Tags', []), 'Name'),
                    "region": self.region,
                    "metadata": {
                        "size": volume.get('Size'),
                        "volume_type": volume.get('VolumeType'),
                        "encrypted": volume.get('Encrypted'),
                        "state": volume.get('State'),
                        "iops": volume.get('Iops'),
                        "availability_zone": volume.get('AvailabilityZone'),
                        "attachments": volume.get('Attachments', []),
                    },
                    "tags": volume.get('Tags', [])
                })

            logger.info("EBS volumes scanned", count=len(volumes))
            return volumes
        except Exception as e:
            logger.error("Failed to scan EBS volumes", error=str(e))
            return []

    def scan_ebs_snapshots(self) -> List[Dict[str, Any]]:
        """Scan EBS snapshots"""
        try:
            ec2 = self.session.client('ec2')
            response = ec2.describe_snapshots(OwnerIds=['self'])

            snapshots = []
            for snapshot in response.get('Snapshots', []):
                snapshots.append({
                    "resource_id": snapshot['SnapshotId'],
                    "resource_type": "EBSSnapshot",
                    "resource_name": self._get_tag_value(snapshot.get('Tags', []), 'Name'),
                    "region": self.region,
                    "metadata": {
                        "volume_id": snapshot.get('VolumeId'),
                        "volume_size": snapshot.get('VolumeSize'),
                        "encrypted": snapshot.get('Encrypted'),
                        "state": snapshot.get('State'),
                        "start_time": snapshot.get('StartTime').isoformat() if snapshot.get('StartTime') else None,
                    },
                    "tags": snapshot.get('Tags', [])
                })

            logger.info("EBS snapshots scanned", count=len(snapshots))
            return snapshots
        except Exception as e:
            logger.error("Failed to scan EBS snapshots", error=str(e))
            return []

    def scan_kms_keys(self) -> List[Dict[str, Any]]:
        """Scan KMS keys"""
        try:
            kms = self.session.client('kms')
            response = kms.list_keys()

            keys = []
            for key in response.get('Keys', []):
                key_id = key['KeyId']

                try:
                    key_metadata = kms.describe_key(KeyId=key_id)['KeyMetadata']
                except Exception:
                    continue

                keys.append({
                    "resource_id": key_metadata['Arn'],
                    "resource_type": "KMSKey",
                    "resource_name": key_id,
                    "region": self.region,
                    "metadata": {
                        "key_state": key_metadata.get('KeyState'),
                        "creation_date": key_metadata.get('CreationDate').isoformat() if key_metadata.get('CreationDate') else None,
                        "enabled": key_metadata.get('Enabled'),
                        "key_usage": key_metadata.get('KeyUsage'),
                        "key_manager": key_metadata.get('KeyManager'),
                    },
                    "tags": []
                })

            logger.info("KMS keys scanned", count=len(keys))
            return keys
        except Exception as e:
            logger.error("Failed to scan KMS keys", error=str(e))
            return []

    def scan_cloudwatch_alarms(self) -> List[Dict[str, Any]]:
        """Scan CloudWatch alarms"""
        try:
            cloudwatch = self.session.client('cloudwatch')
            response = cloudwatch.describe_alarms()

            alarms = []
            for alarm in response.get('MetricAlarms', []):
                alarms.append({
                    "resource_id": alarm['AlarmArn'],
                    "resource_type": "CloudWatchAlarm",
                    "resource_name": alarm['AlarmName'],
                    "region": self.region,
                    "metadata": {
                        "metric_name": alarm.get('MetricName'),
                        "namespace": alarm.get('Namespace'),
                        "state": alarm.get('StateValue'),
                        "actions_enabled": alarm.get('ActionsEnabled'),
                        "alarm_actions": alarm.get('AlarmActions', []),
                    },
                    "tags": []
                })

            logger.info("CloudWatch alarms scanned", count=len(alarms))
            return alarms
        except Exception as e:
            logger.error("Failed to scan CloudWatch alarms", error=str(e))
            return []

    def scan_load_balancers(self) -> List[Dict[str, Any]]:
        """Scan ELB/ALB/NLB load balancers"""
        try:
            elbv2 = self.session.client('elbv2')
            response = elbv2.describe_load_balancers()

            load_balancers = []
            for lb in response.get('LoadBalancers', []):
                load_balancers.append({
                    "resource_id": lb['LoadBalancerArn'],
                    "resource_type": "LoadBalancer",
                    "resource_name": lb['LoadBalancerName'],
                    "region": self.region,
                    "metadata": {
                        "type": lb.get('Type'),
                        "scheme": lb.get('Scheme'),
                        "vpc_id": lb.get('VpcId'),
                        "state": lb.get('State', {}).get('Code'),
                        "dns_name": lb.get('DNSName'),
                        "security_groups": lb.get('SecurityGroups', []),
                    },
                    "tags": []
                })

            logger.info("Load balancers scanned", count=len(load_balancers))
            return load_balancers
        except Exception as e:
            logger.error("Failed to scan Load balancers", error=str(e))
            return []

    def _get_tag_value(self, tags: List[Dict], key: str) -> Optional[str]:
        """Get tag value by key"""
        for tag in tags:
            if tag.get('Key') == key:
                return tag.get('Value')
        return None
