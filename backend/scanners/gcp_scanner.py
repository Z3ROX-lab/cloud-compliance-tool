from google.cloud import compute_v1, storage, resourcemanager_v3
from google.cloud import logging as cloud_logging
from google.cloud import container_v1
from google.cloud.sql.connector import Connector
from google.oauth2 import service_account
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger()


class GCPScanner:
    """GCP Cloud Scanner - Discovers and analyzes GCP resources"""

    def __init__(
        self,
        project_id: Optional[str] = None,
        credentials_path: Optional[str] = None
    ):
        """Initialize GCP scanner with credentials"""
        self.project_id = project_id

        # Initialize credentials
        if credentials_path:
            self.credentials = service_account.Credentials.from_service_account_file(
                credentials_path
            )
        else:
            self.credentials = None

        logger.info("GCP Scanner initialized", project_id=project_id)

    def scan_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scan all GCP resources"""
        logger.info("Starting full GCP scan")

        resources = {
            "compute_instances": self.scan_compute_instances(),
            "storage_buckets": self.scan_storage_buckets(),
            "gke_clusters": self.scan_gke_clusters(),
            "vpc_networks": self.scan_vpc_networks(),
            "firewall_rules": self.scan_firewall_rules(),
            "compute_disks": self.scan_compute_disks(),
            "sql_instances": self.scan_sql_instances(),
            "load_balancers": self.scan_load_balancers(),
            "iam_service_accounts": self.scan_iam_service_accounts(),
        }

        logger.info("GCP scan completed", total_resources=sum(len(v) for v in resources.values()))
        return resources

    def scan_compute_instances(self) -> List[Dict[str, Any]]:
        """Scan GCP Compute Engine instances"""
        try:
            instances_client = compute_v1.InstancesClient(credentials=self.credentials)
            instances = []

            # List zones
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            zones = zones_client.list(project=self.project_id)

            for zone in zones:
                try:
                    zone_instances = instances_client.list(
                        project=self.project_id,
                        zone=zone.name
                    )

                    for instance in zone_instances:
                        # Extract disk encryption info
                        disk_encryption = []
                        for disk in instance.disks:
                            disk_encryption.append({
                                "device_name": disk.device_name,
                                "encrypted": disk.disk_encryption_key is not None
                            })

                        # Extract network info
                        network_interfaces = []
                        for nic in instance.network_interfaces:
                            network_interfaces.append({
                                "network": nic.network,
                                "subnetwork": nic.subnetwork,
                                "has_external_ip": len(nic.access_configs) > 0 if nic.access_configs else False
                            })

                        instances.append({
                            "resource_id": f"projects/{self.project_id}/zones/{zone.name}/instances/{instance.name}",
                            "resource_type": "ComputeInstance",
                            "resource_name": instance.name,
                            "region": zone.name,
                            "metadata": {
                                "machine_type": instance.machine_type.split('/')[-1],
                                "status": instance.status,
                                "zone": zone.name,
                                "disks": disk_encryption,
                                "network_interfaces": network_interfaces,
                                "service_accounts": [
                                    {"email": sa.email, "scopes": sa.scopes}
                                    for sa in (instance.service_accounts or [])
                                ],
                                "deletion_protection": instance.deletion_protection,
                                "shielded_instance_config": {
                                    "enable_secure_boot": instance.shielded_instance_config.enable_secure_boot if instance.shielded_instance_config else False,
                                    "enable_vtpm": instance.shielded_instance_config.enable_vtpm if instance.shielded_instance_config else False,
                                    "enable_integrity_monitoring": instance.shielded_instance_config.enable_integrity_monitoring if instance.shielded_instance_config else False,
                                } if instance.shielded_instance_config else {}
                            },
                            "tags": dict(instance.labels) if instance.labels else {}
                        })
                except Exception as e:
                    logger.warning("Failed to scan instances in zone", zone=zone.name, error=str(e))

            logger.info("GCP Compute instances scanned", count=len(instances))
            return instances
        except Exception as e:
            logger.error("Failed to scan GCP Compute instances", error=str(e))
            return []

    def scan_storage_buckets(self) -> List[Dict[str, Any]]:
        """Scan GCP Cloud Storage buckets"""
        try:
            storage_client = storage.Client(
                project=self.project_id,
                credentials=self.credentials
            )
            buckets = []

            for bucket in storage_client.list_buckets():
                # Check bucket encryption
                encryption_config = bucket.default_kms_key_name is not None

                # Check public access
                iam_policy = bucket.get_iam_policy()
                is_public = any(
                    'allUsers' in binding.get('members', []) or
                    'allAuthenticatedUsers' in binding.get('members', [])
                    for binding in iam_policy.bindings
                )

                # Check versioning
                versioning_enabled = bucket.versioning_enabled

                # Check logging
                logging_enabled = bucket.logging is not None

                buckets.append({
                    "resource_id": f"projects/{self.project_id}/buckets/{bucket.name}",
                    "resource_type": "StorageBucket",
                    "resource_name": bucket.name,
                    "region": bucket.location,
                    "metadata": {
                        "storage_class": bucket.storage_class,
                        "location_type": bucket.location_type,
                        "encryption": {
                            "default_kms_key": bucket.default_kms_key_name,
                            "enabled": encryption_config
                        },
                        "versioning_enabled": versioning_enabled,
                        "logging_enabled": logging_enabled,
                        "public_access": is_public,
                        "lifecycle_rules": len(bucket.lifecycle_rules) if bucket.lifecycle_rules else 0,
                        "retention_policy": {
                            "retention_period": bucket.retention_period,
                            "is_locked": bucket.retention_policy_locked
                        } if bucket.retention_period else None,
                    },
                    "tags": dict(bucket.labels) if bucket.labels else {}
                })

            logger.info("GCP Storage buckets scanned", count=len(buckets))
            return buckets
        except Exception as e:
            logger.error("Failed to scan GCP Storage buckets", error=str(e))
            return []

    def scan_gke_clusters(self) -> List[Dict[str, Any]]:
        """Scan GKE (Google Kubernetes Engine) clusters"""
        try:
            container_client = container_v1.ClusterManagerClient(credentials=self.credentials)
            clusters = []

            # Get clusters in all locations
            parent = f"projects/{self.project_id}/locations/-"
            response = container_client.list_clusters(parent=parent)

            for cluster in response.clusters:
                clusters.append({
                    "resource_id": cluster.self_link,
                    "resource_type": "GKECluster",
                    "resource_name": cluster.name,
                    "region": cluster.location,
                    "metadata": {
                        "status": cluster.status.name,
                        "current_version": cluster.current_master_version,
                        "node_pools": [
                            {
                                "name": pool.name,
                                "node_count": pool.initial_node_count,
                                "machine_type": pool.config.machine_type if pool.config else None,
                                "disk_size_gb": pool.config.disk_size_gb if pool.config else None,
                            }
                            for pool in cluster.node_pools
                        ],
                        "network": cluster.network,
                        "subnetwork": cluster.subnetwork,
                        "enable_kubernetes_alpha": cluster.enable_kubernetes_alpha,
                        "network_policy": cluster.network_policy.enabled if cluster.network_policy else False,
                        "master_authorized_networks": {
                            "enabled": cluster.master_authorized_networks_config.enabled if cluster.master_authorized_networks_config else False,
                            "cidr_blocks": len(cluster.master_authorized_networks_config.cidr_blocks) if cluster.master_authorized_networks_config else 0
                        },
                        "binary_authorization": cluster.binary_authorization.enabled if cluster.binary_authorization else False,
                        "workload_identity": cluster.workload_identity_config.workload_pool if cluster.workload_identity_config else None,
                    },
                    "tags": dict(cluster.resource_labels) if cluster.resource_labels else {}
                })

            logger.info("GKE clusters scanned", count=len(clusters))
            return clusters
        except Exception as e:
            logger.error("Failed to scan GKE clusters", error=str(e))
            return []

    def scan_vpc_networks(self) -> List[Dict[str, Any]]:
        """Scan GCP VPC Networks"""
        try:
            networks_client = compute_v1.NetworksClient(credentials=self.credentials)
            networks = []

            for network in networks_client.list(project=self.project_id):
                # Get subnets
                subnets_client = compute_v1.SubnetworksClient(credentials=self.credentials)
                subnets_info = []

                if network.subnetworks:
                    for subnet_url in network.subnetworks:
                        # Parse subnet URL to get region and name
                        parts = subnet_url.split('/')
                        if len(parts) >= 2:
                            region = parts[-3]
                            subnet_name = parts[-1]
                            try:
                                subnet = subnets_client.get(
                                    project=self.project_id,
                                    region=region,
                                    subnetwork=subnet_name
                                )
                                subnets_info.append({
                                    "name": subnet.name,
                                    "ip_cidr_range": subnet.ip_cidr_range,
                                    "region": subnet.region.split('/')[-1],
                                    "private_ip_google_access": subnet.private_ip_google_access
                                })
                            except Exception:
                                pass

                networks.append({
                    "resource_id": f"projects/{self.project_id}/global/networks/{network.name}",
                    "resource_type": "VPCNetwork",
                    "resource_name": network.name,
                    "region": "global",
                    "metadata": {
                        "auto_create_subnetworks": network.auto_create_subnetworks,
                        "routing_mode": network.routing_config.routing_mode.name if network.routing_config else None,
                        "subnets": subnets_info,
                        "mtu": network.mtu,
                    },
                    "tags": {}
                })

            logger.info("GCP VPC Networks scanned", count=len(networks))
            return networks
        except Exception as e:
            logger.error("Failed to scan GCP VPC Networks", error=str(e))
            return []

    def scan_firewall_rules(self) -> List[Dict[str, Any]]:
        """Scan GCP Firewall Rules"""
        try:
            firewalls_client = compute_v1.FirewallsClient(credentials=self.credentials)
            rules = []

            for firewall in firewalls_client.list(project=self.project_id):
                rules.append({
                    "resource_id": f"projects/{self.project_id}/global/firewalls/{firewall.name}",
                    "resource_type": "FirewallRule",
                    "resource_name": firewall.name,
                    "region": "global",
                    "metadata": {
                        "network": firewall.network,
                        "direction": firewall.direction,
                        "priority": firewall.priority,
                        "source_ranges": firewall.source_ranges or [],
                        "destination_ranges": firewall.destination_ranges or [],
                        "allowed": [
                            {"protocol": rule.I_p_protocol, "ports": rule.ports or []}
                            for rule in (firewall.allowed or [])
                        ],
                        "denied": [
                            {"protocol": rule.I_p_protocol, "ports": rule.ports or []}
                            for rule in (firewall.denied or [])
                        ],
                        "disabled": firewall.disabled,
                        "target_tags": firewall.target_tags or [],
                        "source_tags": firewall.source_tags or [],
                    },
                    "tags": {}
                })

            logger.info("GCP Firewall Rules scanned", count=len(rules))
            return rules
        except Exception as e:
            logger.error("Failed to scan GCP Firewall Rules", error=str(e))
            return []

    def scan_compute_disks(self) -> List[Dict[str, Any]]:
        """Scan GCP Compute Engine disks"""
        try:
            disks_client = compute_v1.DisksClient(credentials=self.credentials)
            disks = []

            # List zones
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            zones = zones_client.list(project=self.project_id)

            for zone in zones:
                try:
                    zone_disks = disks_client.list(
                        project=self.project_id,
                        zone=zone.name
                    )

                    for disk in zone_disks:
                        disks.append({
                            "resource_id": f"projects/{self.project_id}/zones/{zone.name}/disks/{disk.name}",
                            "resource_type": "ComputeDisk",
                            "resource_name": disk.name,
                            "region": zone.name,
                            "metadata": {
                                "size_gb": disk.size_gb,
                                "type": disk.type_.split('/')[-1] if disk.type_ else None,
                                "status": disk.status,
                                "encrypted": disk.disk_encryption_key is not None,
                                "encryption_key_type": "CUSTOMER_MANAGED" if disk.disk_encryption_key else "GOOGLE_MANAGED",
                                "users": [user.split('/')[-1] for user in (disk.users or [])],
                            },
                            "tags": dict(disk.labels) if disk.labels else {}
                        })
                except Exception as e:
                    logger.warning("Failed to scan disks in zone", zone=zone.name, error=str(e))

            logger.info("GCP Compute Disks scanned", count=len(disks))
            return disks
        except Exception as e:
            logger.error("Failed to scan GCP Compute Disks", error=str(e))
            return []

    def scan_sql_instances(self) -> List[Dict[str, Any]]:
        """Scan GCP Cloud SQL instances"""
        try:
            # Note: This requires google-cloud-sql library
            # For now, we'll return empty list as it requires additional setup
            logger.info("GCP Cloud SQL scanning not yet fully implemented")
            return []
        except Exception as e:
            logger.error("Failed to scan GCP Cloud SQL", error=str(e))
            return []

    def scan_load_balancers(self) -> List[Dict[str, Any]]:
        """Scan GCP Load Balancers"""
        try:
            # Scan forwarding rules (represents load balancers)
            forwarding_rules_client = compute_v1.ForwardingRulesClient(credentials=self.credentials)
            load_balancers = []

            # Global forwarding rules
            try:
                for rule in forwarding_rules_client.list(project=self.project_id, region="-"):
                    load_balancers.append({
                        "resource_id": rule.self_link,
                        "resource_type": "LoadBalancer",
                        "resource_name": rule.name,
                        "region": "global" if not rule.region else rule.region.split('/')[-1],
                        "metadata": {
                            "ip_address": rule.I_p_address,
                            "ip_protocol": rule.I_p_protocol,
                            "load_balancing_scheme": rule.load_balancing_scheme,
                            "port_range": rule.port_range,
                            "target": rule.target.split('/')[-1] if rule.target else None,
                        },
                        "tags": dict(rule.labels) if rule.labels else {}
                    })
            except Exception as e:
                logger.warning("Failed to scan global forwarding rules", error=str(e))

            logger.info("GCP Load Balancers scanned", count=len(load_balancers))
            return load_balancers
        except Exception as e:
            logger.error("Failed to scan GCP Load Balancers", error=str(e))
            return []

    def scan_iam_service_accounts(self) -> List[Dict[str, Any]]:
        """Scan GCP IAM Service Accounts"""
        try:
            # Note: This requires google-cloud-iam library
            # For now, we'll return empty list as it requires additional setup
            logger.info("GCP IAM Service Accounts scanning not yet fully implemented")
            return []
        except Exception as e:
            logger.error("Failed to scan GCP IAM Service Accounts", error=str(e))
            return []
