from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.containerservice import ContainerServiceClient
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger()


class AzureScanner:
    """Azure Cloud Scanner - Discovers and analyzes Azure resources"""

    def __init__(
        self,
        subscription_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None
    ):
        """Initialize Azure scanner with credentials"""
        self.subscription_id = subscription_id

        # Initialize credentials
        if client_id and client_secret and tenant_id:
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            self.credential = DefaultAzureCredential()

        logger.info("Azure Scanner initialized", subscription_id=subscription_id)

    def _get_compute_client(self):
        return ComputeManagementClient(self.credential, self.subscription_id)

    def _get_storage_client(self):
        return StorageManagementClient(self.credential, self.subscription_id)

    def _get_network_client(self):
        return NetworkManagementClient(self.credential, self.subscription_id)

    def _get_sql_client(self):
        return SqlManagementClient(self.credential, self.subscription_id)

    def _get_keyvault_client(self):
        return KeyVaultManagementClient(self.credential, self.subscription_id)

    def _get_monitor_client(self):
        return MonitorManagementClient(self.credential, self.subscription_id)

    def _get_resource_client(self):
        return ResourceManagementClient(self.credential, self.subscription_id)

    def _get_aks_client(self):
        return ContainerServiceClient(self.credential, self.subscription_id)

    def scan_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scan all Azure resources"""
        logger.info("Starting full Azure scan")

        resources = {
            "virtual_machines": self.scan_virtual_machines(),
            "storage_accounts": self.scan_storage_accounts(),
            "sql_databases": self.scan_sql_databases(),
            "network_security_groups": self.scan_network_security_groups(),
            "virtual_networks": self.scan_virtual_networks(),
            "key_vaults": self.scan_key_vaults(),
            "aks_clusters": self.scan_aks_clusters(),
            "disks": self.scan_disks(),
            "load_balancers": self.scan_load_balancers(),
            "public_ips": self.scan_public_ips(),
        }

        logger.info("Azure scan completed", total_resources=sum(len(v) for v in resources.values()))
        return resources

    def scan_virtual_machines(self) -> List[Dict[str, Any]]:
        """Scan Azure Virtual Machines"""
        try:
            compute_client = self._get_compute_client()
            vms = []

            for vm in compute_client.virtual_machines.list_all():
                # Get instance view for runtime info
                try:
                    instance_view = compute_client.virtual_machines.instance_view(
                        vm.id.split('/')[4],  # resource group
                        vm.name
                    )
                    power_state = next(
                        (s.code.split('/')[-1] for s in instance_view.statuses if s.code.startswith('PowerState')),
                        'unknown'
                    )
                except Exception:
                    power_state = 'unknown'

                vms.append({
                    "resource_id": vm.id,
                    "resource_type": "VirtualMachine",
                    "resource_name": vm.name,
                    "region": vm.location,
                    "metadata": {
                        "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                        "os_type": vm.storage_profile.os_disk.os_type if vm.storage_profile and vm.storage_profile.os_disk else None,
                        "power_state": power_state,
                        "resource_group": vm.id.split('/')[4],
                        "managed_disk": vm.storage_profile.os_disk.managed_disk is not None if vm.storage_profile and vm.storage_profile.os_disk else False,
                        "encryption": vm.storage_profile.os_disk.encryption_settings if vm.storage_profile and vm.storage_profile.os_disk else None,
                        "network_interfaces": [nic.id for nic in vm.network_profile.network_interfaces] if vm.network_profile else [],
                    },
                    "tags": vm.tags or {}
                })

            logger.info("Azure VMs scanned", count=len(vms))
            return vms
        except Exception as e:
            logger.error("Failed to scan Azure VMs", error=str(e))
            return []

    def scan_storage_accounts(self) -> List[Dict[str, Any]]:
        """Scan Azure Storage Accounts"""
        try:
            storage_client = self._get_storage_client()
            accounts = []

            for account in storage_client.storage_accounts.list():
                # Get account properties
                try:
                    account_props = storage_client.storage_accounts.get_properties(
                        account.id.split('/')[4],
                        account.name
                    )
                except Exception:
                    account_props = account

                accounts.append({
                    "resource_id": account.id,
                    "resource_type": "StorageAccount",
                    "resource_name": account.name,
                    "region": account.location,
                    "metadata": {
                        "kind": account.kind.value if account.kind else None,
                        "sku": account.sku.name.value if account.sku else None,
                        "encryption": {
                            "enabled": account_props.encryption is not None,
                            "services": {
                                "blob": account_props.encryption.services.blob.enabled if account_props.encryption and account_props.encryption.services and account_props.encryption.services.blob else False,
                                "file": account_props.encryption.services.file.enabled if account_props.encryption and account_props.encryption.services and account_props.encryption.services.file else False,
                            } if account_props.encryption and account_props.encryption.services else {}
                        },
                        "https_only": account_props.enable_https_traffic_only if hasattr(account_props, 'enable_https_traffic_only') else False,
                        "public_access": not (account_props.allow_blob_public_access if hasattr(account_props, 'allow_blob_public_access') else True),
                        "minimum_tls_version": account_props.minimum_tls_version.value if hasattr(account_props, 'minimum_tls_version') and account_props.minimum_tls_version else None,
                    },
                    "tags": account.tags or {}
                })

            logger.info("Azure Storage Accounts scanned", count=len(accounts))
            return accounts
        except Exception as e:
            logger.error("Failed to scan Azure Storage Accounts", error=str(e))
            return []

    def scan_sql_databases(self) -> List[Dict[str, Any]]:
        """Scan Azure SQL Databases"""
        try:
            sql_client = self._get_sql_client()
            databases = []

            # List all SQL servers first
            for server in sql_client.servers.list():
                resource_group = server.id.split('/')[4]

                # List databases in each server
                try:
                    for db in sql_client.databases.list_by_server(resource_group, server.name):
                        if db.name == 'master':  # Skip master DB
                            continue

                        # Get transparent data encryption status
                        try:
                            tde = sql_client.transparent_data_encryptions.get(
                                resource_group, server.name, db.name, 'current'
                            )
                            encryption_enabled = tde.status == 'Enabled'
                        except Exception:
                            encryption_enabled = False

                        databases.append({
                            "resource_id": db.id,
                            "resource_type": "SQLDatabase",
                            "resource_name": f"{server.name}/{db.name}",
                            "region": db.location,
                            "metadata": {
                                "server_name": server.name,
                                "database_name": db.name,
                                "sku": db.sku.name if db.sku else None,
                                "max_size_bytes": db.max_size_bytes,
                                "encryption_enabled": encryption_enabled,
                                "collation": db.collation,
                                "zone_redundant": db.zone_redundant if hasattr(db, 'zone_redundant') else False,
                            },
                            "tags": db.tags or {}
                        })
                except Exception as e:
                    logger.warning("Failed to list databases for server", server=server.name, error=str(e))

            logger.info("Azure SQL Databases scanned", count=len(databases))
            return databases
        except Exception as e:
            logger.error("Failed to scan Azure SQL Databases", error=str(e))
            return []

    def scan_network_security_groups(self) -> List[Dict[str, Any]]:
        """Scan Azure Network Security Groups"""
        try:
            network_client = self._get_network_client()
            nsgs = []

            for nsg in network_client.network_security_groups.list_all():
                nsgs.append({
                    "resource_id": nsg.id,
                    "resource_type": "NetworkSecurityGroup",
                    "resource_name": nsg.name,
                    "region": nsg.location,
                    "metadata": {
                        "resource_group": nsg.id.split('/')[4],
                        "security_rules": [
                            {
                                "name": rule.name,
                                "priority": rule.priority,
                                "direction": rule.direction,
                                "access": rule.access,
                                "protocol": rule.protocol,
                                "source_port_range": rule.source_port_range,
                                "destination_port_range": rule.destination_port_range,
                                "source_address_prefix": rule.source_address_prefix,
                                "destination_address_prefix": rule.destination_address_prefix,
                            }
                            for rule in (nsg.security_rules or [])
                        ],
                        "default_security_rules_count": len(nsg.default_security_rules or []),
                    },
                    "tags": nsg.tags or {}
                })

            logger.info("Azure NSGs scanned", count=len(nsgs))
            return nsgs
        except Exception as e:
            logger.error("Failed to scan Azure NSGs", error=str(e))
            return []

    def scan_virtual_networks(self) -> List[Dict[str, Any]]:
        """Scan Azure Virtual Networks"""
        try:
            network_client = self._get_network_client()
            vnets = []

            for vnet in network_client.virtual_networks.list_all():
                vnets.append({
                    "resource_id": vnet.id,
                    "resource_type": "VirtualNetwork",
                    "resource_name": vnet.name,
                    "region": vnet.location,
                    "metadata": {
                        "resource_group": vnet.id.split('/')[4],
                        "address_space": vnet.address_space.address_prefixes if vnet.address_space else [],
                        "subnets": [
                            {
                                "name": subnet.name,
                                "address_prefix": subnet.address_prefix,
                                "nsg": subnet.network_security_group.id if subnet.network_security_group else None
                            }
                            for subnet in (vnet.subnets or [])
                        ],
                        "enable_ddos_protection": vnet.enable_ddos_protection if hasattr(vnet, 'enable_ddos_protection') else False,
                    },
                    "tags": vnet.tags or {}
                })

            logger.info("Azure VNets scanned", count=len(vnets))
            return vnets
        except Exception as e:
            logger.error("Failed to scan Azure VNets", error=str(e))
            return []

    def scan_key_vaults(self) -> List[Dict[str, Any]]:
        """Scan Azure Key Vaults"""
        try:
            kv_client = self._get_keyvault_client()
            vaults = []

            for vault in kv_client.vaults.list():
                vaults.append({
                    "resource_id": vault.id,
                    "resource_type": "KeyVault",
                    "resource_name": vault.name,
                    "region": vault.location,
                    "metadata": {
                        "resource_group": vault.id.split('/')[4],
                        "vault_uri": vault.properties.vault_uri if vault.properties else None,
                        "sku": vault.properties.sku.name.value if vault.properties and vault.properties.sku else None,
                        "enable_soft_delete": vault.properties.enable_soft_delete if vault.properties else False,
                        "enable_purge_protection": vault.properties.enable_purge_protection if vault.properties else False,
                        "enable_rbac_authorization": vault.properties.enable_rbac_authorization if vault.properties else False,
                        "public_network_access": vault.properties.public_network_access if vault.properties and hasattr(vault.properties, 'public_network_access') else 'Enabled',
                    },
                    "tags": vault.tags or {}
                })

            logger.info("Azure Key Vaults scanned", count=len(vaults))
            return vaults
        except Exception as e:
            logger.error("Failed to scan Azure Key Vaults", error=str(e))
            return []

    def scan_aks_clusters(self) -> List[Dict[str, Any]]:
        """Scan Azure Kubernetes Service (AKS) clusters"""
        try:
            aks_client = self._get_aks_client()
            clusters = []

            for cluster in aks_client.managed_clusters.list():
                clusters.append({
                    "resource_id": cluster.id,
                    "resource_type": "AKSCluster",
                    "resource_name": cluster.name,
                    "region": cluster.location,
                    "metadata": {
                        "resource_group": cluster.id.split('/')[4],
                        "kubernetes_version": cluster.kubernetes_version,
                        "node_pools": [
                            {
                                "name": pool.name,
                                "count": pool.count,
                                "vm_size": pool.vm_size,
                                "os_type": pool.os_type,
                            }
                            for pool in (cluster.agent_pool_profiles or [])
                        ],
                        "enable_rbac": cluster.enable_rbac if hasattr(cluster, 'enable_rbac') else False,
                        "network_profile": {
                            "network_plugin": cluster.network_profile.network_plugin if cluster.network_profile else None,
                            "network_policy": cluster.network_profile.network_policy if cluster.network_profile else None,
                        } if cluster.network_profile else {},
                        "api_server_access_profile": cluster.api_server_access_profile.authorized_ip_ranges if cluster.api_server_access_profile and hasattr(cluster.api_server_access_profile, 'authorized_ip_ranges') else [],
                    },
                    "tags": cluster.tags or {}
                })

            logger.info("Azure AKS clusters scanned", count=len(clusters))
            return clusters
        except Exception as e:
            logger.error("Failed to scan Azure AKS clusters", error=str(e))
            return []

    def scan_disks(self) -> List[Dict[str, Any]]:
        """Scan Azure Managed Disks"""
        try:
            compute_client = self._get_compute_client()
            disks = []

            for disk in compute_client.disks.list():
                disks.append({
                    "resource_id": disk.id,
                    "resource_type": "ManagedDisk",
                    "resource_name": disk.name,
                    "region": disk.location,
                    "metadata": {
                        "resource_group": disk.id.split('/')[4],
                        "disk_size_gb": disk.disk_size_gb,
                        "sku": disk.sku.name.value if disk.sku else None,
                        "encryption": disk.encryption is not None,
                        "encryption_type": disk.encryption.type.value if disk.encryption and disk.encryption.type else None,
                        "os_type": disk.os_type.value if disk.os_type else None,
                        "disk_state": disk.disk_state.value if disk.disk_state else None,
                    },
                    "tags": disk.tags or {}
                })

            logger.info("Azure Managed Disks scanned", count=len(disks))
            return disks
        except Exception as e:
            logger.error("Failed to scan Azure Managed Disks", error=str(e))
            return []

    def scan_load_balancers(self) -> List[Dict[str, Any]]:
        """Scan Azure Load Balancers"""
        try:
            network_client = self._get_network_client()
            lbs = []

            for lb in network_client.load_balancers.list_all():
                lbs.append({
                    "resource_id": lb.id,
                    "resource_type": "LoadBalancer",
                    "resource_name": lb.name,
                    "region": lb.location,
                    "metadata": {
                        "resource_group": lb.id.split('/')[4],
                        "sku": lb.sku.name.value if lb.sku else None,
                        "frontend_ip_configurations": len(lb.frontend_ip_configurations or []),
                        "backend_address_pools": len(lb.backend_address_pools or []),
                        "load_balancing_rules": len(lb.load_balancing_rules or []),
                    },
                    "tags": lb.tags or {}
                })

            logger.info("Azure Load Balancers scanned", count=len(lbs))
            return lbs
        except Exception as e:
            logger.error("Failed to scan Azure Load Balancers", error=str(e))
            return []

    def scan_public_ips(self) -> List[Dict[str, Any]]:
        """Scan Azure Public IP Addresses"""
        try:
            network_client = self._get_network_client()
            ips = []

            for ip in network_client.public_ip_addresses.list_all():
                ips.append({
                    "resource_id": ip.id,
                    "resource_type": "PublicIP",
                    "resource_name": ip.name,
                    "region": ip.location,
                    "metadata": {
                        "resource_group": ip.id.split('/')[4],
                        "ip_address": ip.ip_address,
                        "allocation_method": ip.public_ip_allocation_method.value if ip.public_ip_allocation_method else None,
                        "sku": ip.sku.name.value if ip.sku else None,
                        "associated_resource": ip.ip_configuration.id if ip.ip_configuration else None,
                    },
                    "tags": ip.tags or {}
                })

            logger.info("Azure Public IPs scanned", count=len(ips))
            return ips
        except Exception as e:
            logger.error("Failed to scan Azure Public IPs", error=str(e))
            return []
