from kubernetes import client, config
from kubernetes.client.rest import ApiException
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog
import os

logger = structlog.get_logger()


class KubernetesScanner:
    """Kubernetes Scanner - Discovers and analyzes K8s resources"""

    def __init__(
        self,
        kubeconfig_path: Optional[str] = None,
        context: Optional[str] = None,
        in_cluster: bool = False
    ):
        """Initialize Kubernetes scanner"""
        try:
            if in_cluster:
                config.load_incluster_config()
            elif kubeconfig_path:
                config.load_kube_config(config_file=kubeconfig_path, context=context)
            else:
                config.load_kube_config(context=context)

            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.networking_v1 = client.NetworkingV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            self.policy_v1 = client.PolicyV1Api()
            self.storage_v1 = client.StorageV1Api()

            logger.info("Kubernetes Scanner initialized")
        except Exception as e:
            logger.error("Failed to initialize Kubernetes client", error=str(e))
            raise

    def scan_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scan all Kubernetes resources"""
        logger.info("Starting full Kubernetes scan")

        resources = {
            "namespaces": self.scan_namespaces(),
            "pods": self.scan_pods(),
            "deployments": self.scan_deployments(),
            "services": self.scan_services(),
            "ingresses": self.scan_ingresses(),
            "configmaps": self.scan_configmaps(),
            "secrets": self.scan_secrets(),
            "persistent_volumes": self.scan_persistent_volumes(),
            "persistent_volume_claims": self.scan_persistent_volume_claims(),
            "service_accounts": self.scan_service_accounts(),
            "roles": self.scan_roles(),
            "role_bindings": self.scan_role_bindings(),
            "cluster_roles": self.scan_cluster_roles(),
            "cluster_role_bindings": self.scan_cluster_role_bindings(),
            "network_policies": self.scan_network_policies(),
            "pod_security_policies": self.scan_pod_security_policies(),
            "storage_classes": self.scan_storage_classes(),
        }

        logger.info("Kubernetes scan completed", total_resources=sum(len(v) for v in resources.values()))
        return resources

    def scan_namespaces(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Namespaces"""
        try:
            namespaces = []
            for ns in self.v1.list_namespace().items:
                namespaces.append({
                    "resource_id": f"namespace/{ns.metadata.name}",
                    "resource_type": "Namespace",
                    "resource_name": ns.metadata.name,
                    "region": "kubernetes",
                    "metadata": {
                        "status": ns.status.phase,
                        "created": ns.metadata.creation_timestamp.isoformat() if ns.metadata.creation_timestamp else None,
                        "labels": ns.metadata.labels or {},
                        "annotations": ns.metadata.annotations or {},
                    },
                    "tags": ns.metadata.labels or {}
                })

            logger.info("K8s Namespaces scanned", count=len(namespaces))
            return namespaces
        except ApiException as e:
            logger.error("Failed to scan K8s Namespaces", error=str(e))
            return []

    def scan_pods(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Pods"""
        try:
            pods = []
            for pod in self.v1.list_pod_for_all_namespaces().items:
                # Analyze security context
                security_issues = []
                if pod.spec.containers:
                    for container in pod.spec.containers:
                        if container.security_context:
                            sc = container.security_context
                            if sc.privileged:
                                security_issues.append(f"Container {container.name} runs as privileged")
                            if sc.run_as_non_root == False:
                                security_issues.append(f"Container {container.name} can run as root")
                        else:
                            security_issues.append(f"Container {container.name} has no security context")

                pods.append({
                    "resource_id": f"pod/{pod.metadata.namespace}/{pod.metadata.name}",
                    "resource_type": "Pod",
                    "resource_name": f"{pod.metadata.namespace}/{pod.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": pod.metadata.namespace,
                        "status": pod.status.phase,
                        "node": pod.spec.node_name,
                        "containers": [
                            {
                                "name": c.name,
                                "image": c.image,
                                "privileged": c.security_context.privileged if c.security_context else False,
                                "run_as_non_root": c.security_context.run_as_non_root if c.security_context else None,
                                "read_only_root_filesystem": c.security_context.read_only_root_filesystem if c.security_context else False,
                            }
                            for c in (pod.spec.containers or [])
                        ],
                        "service_account": pod.spec.service_account_name,
                        "host_network": pod.spec.host_network or False,
                        "host_pid": pod.spec.host_pid or False,
                        "host_ipc": pod.spec.host_ipc or False,
                        "security_issues": security_issues,
                    },
                    "tags": pod.metadata.labels or {}
                })

            logger.info("K8s Pods scanned", count=len(pods))
            return pods
        except ApiException as e:
            logger.error("Failed to scan K8s Pods", error=str(e))
            return []

    def scan_deployments(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Deployments"""
        try:
            deployments = []
            for deploy in self.apps_v1.list_deployment_for_all_namespaces().items:
                deployments.append({
                    "resource_id": f"deployment/{deploy.metadata.namespace}/{deploy.metadata.name}",
                    "resource_type": "Deployment",
                    "resource_name": f"{deploy.metadata.namespace}/{deploy.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": deploy.metadata.namespace,
                        "replicas": deploy.spec.replicas,
                        "ready_replicas": deploy.status.ready_replicas or 0,
                        "available_replicas": deploy.status.available_replicas or 0,
                        "strategy": deploy.spec.strategy.type if deploy.spec.strategy else None,
                        "selector": deploy.spec.selector.match_labels if deploy.spec.selector else {},
                    },
                    "tags": deploy.metadata.labels or {}
                })

            logger.info("K8s Deployments scanned", count=len(deployments))
            return deployments
        except ApiException as e:
            logger.error("Failed to scan K8s Deployments", error=str(e))
            return []

    def scan_services(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Services"""
        try:
            services = []
            for svc in self.v1.list_service_for_all_namespaces().items:
                # Check if service is exposed externally
                is_external = svc.spec.type in ['LoadBalancer', 'NodePort']

                services.append({
                    "resource_id": f"service/{svc.metadata.namespace}/{svc.metadata.name}",
                    "resource_type": "Service",
                    "resource_name": f"{svc.metadata.namespace}/{svc.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": svc.metadata.namespace,
                        "type": svc.spec.type,
                        "cluster_ip": svc.spec.cluster_ip,
                        "external_ips": svc.spec.external_i_ps or [],
                        "ports": [
                            {
                                "name": p.name,
                                "port": p.port,
                                "target_port": str(p.target_port),
                                "protocol": p.protocol
                            }
                            for p in (svc.spec.ports or [])
                        ],
                        "is_external": is_external,
                        "load_balancer_ip": svc.spec.load_balancer_ip,
                    },
                    "tags": svc.metadata.labels or {}
                })

            logger.info("K8s Services scanned", count=len(services))
            return services
        except ApiException as e:
            logger.error("Failed to scan K8s Services", error=str(e))
            return []

    def scan_ingresses(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Ingresses"""
        try:
            ingresses = []
            for ing in self.networking_v1.list_ingress_for_all_namespaces().items:
                # Check TLS configuration
                tls_configured = len(ing.spec.tls or []) > 0

                ingresses.append({
                    "resource_id": f"ingress/{ing.metadata.namespace}/{ing.metadata.name}",
                    "resource_type": "Ingress",
                    "resource_name": f"{ing.metadata.namespace}/{ing.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": ing.metadata.namespace,
                        "ingress_class": ing.spec.ingress_class_name,
                        "tls_configured": tls_configured,
                        "tls_hosts": [tls.hosts for tls in (ing.spec.tls or [])],
                        "rules": [
                            {
                                "host": rule.host,
                                "paths": [
                                    {
                                        "path": path.path,
                                        "path_type": path.path_type,
                                        "backend_service": path.backend.service.name if path.backend and path.backend.service else None
                                    }
                                    for path in (rule.http.paths if rule.http else [])
                                ]
                            }
                            for rule in (ing.spec.rules or [])
                        ],
                    },
                    "tags": ing.metadata.labels or {}
                })

            logger.info("K8s Ingresses scanned", count=len(ingresses))
            return ingresses
        except ApiException as e:
            logger.error("Failed to scan K8s Ingresses", error=str(e))
            return []

    def scan_configmaps(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes ConfigMaps"""
        try:
            configmaps = []
            for cm in self.v1.list_config_map_for_all_namespaces().items:
                configmaps.append({
                    "resource_id": f"configmap/{cm.metadata.namespace}/{cm.metadata.name}",
                    "resource_type": "ConfigMap",
                    "resource_name": f"{cm.metadata.namespace}/{cm.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": cm.metadata.namespace,
                        "data_keys": list(cm.data.keys()) if cm.data else [],
                        "data_count": len(cm.data) if cm.data else 0,
                    },
                    "tags": cm.metadata.labels or {}
                })

            logger.info("K8s ConfigMaps scanned", count=len(configmaps))
            return configmaps
        except ApiException as e:
            logger.error("Failed to scan K8s ConfigMaps", error=str(e))
            return []

    def scan_secrets(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Secrets"""
        try:
            secrets = []
            for secret in self.v1.list_secret_for_all_namespaces().items:
                secrets.append({
                    "resource_id": f"secret/{secret.metadata.namespace}/{secret.metadata.name}",
                    "resource_type": "Secret",
                    "resource_name": f"{secret.metadata.namespace}/{secret.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": secret.metadata.namespace,
                        "type": secret.type,
                        "data_keys": list(secret.data.keys()) if secret.data else [],
                        "data_count": len(secret.data) if secret.data else 0,
                    },
                    "tags": secret.metadata.labels or {}
                })

            logger.info("K8s Secrets scanned", count=len(secrets))
            return secrets
        except ApiException as e:
            logger.error("Failed to scan K8s Secrets", error=str(e))
            return []

    def scan_persistent_volumes(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Persistent Volumes"""
        try:
            pvs = []
            for pv in self.v1.list_persistent_volume().items:
                pvs.append({
                    "resource_id": f"pv/{pv.metadata.name}",
                    "resource_type": "PersistentVolume",
                    "resource_name": pv.metadata.name,
                    "region": "kubernetes",
                    "metadata": {
                        "capacity": pv.spec.capacity.get('storage') if pv.spec.capacity else None,
                        "access_modes": pv.spec.access_modes or [],
                        "storage_class": pv.spec.storage_class_name,
                        "status": pv.status.phase,
                        "claim": f"{pv.spec.claim_ref.namespace}/{pv.spec.claim_ref.name}" if pv.spec.claim_ref else None,
                    },
                    "tags": pv.metadata.labels or {}
                })

            logger.info("K8s Persistent Volumes scanned", count=len(pvs))
            return pvs
        except ApiException as e:
            logger.error("Failed to scan K8s Persistent Volumes", error=str(e))
            return []

    def scan_persistent_volume_claims(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Persistent Volume Claims"""
        try:
            pvcs = []
            for pvc in self.v1.list_persistent_volume_claim_for_all_namespaces().items:
                pvcs.append({
                    "resource_id": f"pvc/{pvc.metadata.namespace}/{pvc.metadata.name}",
                    "resource_type": "PersistentVolumeClaim",
                    "resource_name": f"{pvc.metadata.namespace}/{pvc.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": pvc.metadata.namespace,
                        "storage_requested": pvc.spec.resources.requests.get('storage') if pvc.spec.resources and pvc.spec.resources.requests else None,
                        "access_modes": pvc.spec.access_modes or [],
                        "storage_class": pvc.spec.storage_class_name,
                        "status": pvc.status.phase,
                        "volume_name": pvc.spec.volume_name,
                    },
                    "tags": pvc.metadata.labels or {}
                })

            logger.info("K8s Persistent Volume Claims scanned", count=len(pvcs))
            return pvcs
        except ApiException as e:
            logger.error("Failed to scan K8s Persistent Volume Claims", error=str(e))
            return []

    def scan_service_accounts(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Service Accounts"""
        try:
            service_accounts = []
            for sa in self.v1.list_service_account_for_all_namespaces().items:
                service_accounts.append({
                    "resource_id": f"serviceaccount/{sa.metadata.namespace}/{sa.metadata.name}",
                    "resource_type": "ServiceAccount",
                    "resource_name": f"{sa.metadata.namespace}/{sa.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": sa.metadata.namespace,
                        "secrets": [s.name for s in (sa.secrets or [])],
                        "automount_token": sa.automount_service_account_token,
                    },
                    "tags": sa.metadata.labels or {}
                })

            logger.info("K8s Service Accounts scanned", count=len(service_accounts))
            return service_accounts
        except ApiException as e:
            logger.error("Failed to scan K8s Service Accounts", error=str(e))
            return []

    def scan_roles(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Roles"""
        try:
            roles = []
            for role in self.rbac_v1.list_role_for_all_namespaces().items:
                roles.append({
                    "resource_id": f"role/{role.metadata.namespace}/{role.metadata.name}",
                    "resource_type": "Role",
                    "resource_name": f"{role.metadata.namespace}/{role.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": role.metadata.namespace,
                        "rules": [
                            {
                                "api_groups": rule.api_groups or [],
                                "resources": rule.resources or [],
                                "verbs": rule.verbs or [],
                            }
                            for rule in (role.rules or [])
                        ],
                    },
                    "tags": role.metadata.labels or {}
                })

            logger.info("K8s Roles scanned", count=len(roles))
            return roles
        except ApiException as e:
            logger.error("Failed to scan K8s Roles", error=str(e))
            return []

    def scan_role_bindings(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes RoleBindings"""
        try:
            role_bindings = []
            for rb in self.rbac_v1.list_role_binding_for_all_namespaces().items:
                role_bindings.append({
                    "resource_id": f"rolebinding/{rb.metadata.namespace}/{rb.metadata.name}",
                    "resource_type": "RoleBinding",
                    "resource_name": f"{rb.metadata.namespace}/{rb.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": rb.metadata.namespace,
                        "role_ref": {
                            "kind": rb.role_ref.kind,
                            "name": rb.role_ref.name,
                        } if rb.role_ref else {},
                        "subjects": [
                            {
                                "kind": s.kind,
                                "name": s.name,
                                "namespace": s.namespace,
                            }
                            for s in (rb.subjects or [])
                        ],
                    },
                    "tags": rb.metadata.labels or {}
                })

            logger.info("K8s RoleBindings scanned", count=len(role_bindings))
            return role_bindings
        except ApiException as e:
            logger.error("Failed to scan K8s RoleBindings", error=str(e))
            return []

    def scan_cluster_roles(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes ClusterRoles"""
        try:
            cluster_roles = []
            for cr in self.rbac_v1.list_cluster_role().items:
                cluster_roles.append({
                    "resource_id": f"clusterrole/{cr.metadata.name}",
                    "resource_type": "ClusterRole",
                    "resource_name": cr.metadata.name,
                    "region": "kubernetes",
                    "metadata": {
                        "rules": [
                            {
                                "api_groups": rule.api_groups or [],
                                "resources": rule.resources or [],
                                "verbs": rule.verbs or [],
                            }
                            for rule in (cr.rules or [])
                        ],
                    },
                    "tags": cr.metadata.labels or {}
                })

            logger.info("K8s ClusterRoles scanned", count=len(cluster_roles))
            return cluster_roles
        except ApiException as e:
            logger.error("Failed to scan K8s ClusterRoles", error=str(e))
            return []

    def scan_cluster_role_bindings(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes ClusterRoleBindings"""
        try:
            cluster_role_bindings = []
            for crb in self.rbac_v1.list_cluster_role_binding().items:
                cluster_role_bindings.append({
                    "resource_id": f"clusterrolebinding/{crb.metadata.name}",
                    "resource_type": "ClusterRoleBinding",
                    "resource_name": crb.metadata.name,
                    "region": "kubernetes",
                    "metadata": {
                        "role_ref": {
                            "kind": crb.role_ref.kind,
                            "name": crb.role_ref.name,
                        } if crb.role_ref else {},
                        "subjects": [
                            {
                                "kind": s.kind,
                                "name": s.name,
                                "namespace": s.namespace,
                            }
                            for s in (crb.subjects or [])
                        ],
                    },
                    "tags": crb.metadata.labels or {}
                })

            logger.info("K8s ClusterRoleBindings scanned", count=len(cluster_role_bindings))
            return cluster_role_bindings
        except ApiException as e:
            logger.error("Failed to scan K8s ClusterRoleBindings", error=str(e))
            return []

    def scan_network_policies(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Network Policies"""
        try:
            network_policies = []
            for np in self.networking_v1.list_network_policy_for_all_namespaces().items:
                network_policies.append({
                    "resource_id": f"networkpolicy/{np.metadata.namespace}/{np.metadata.name}",
                    "resource_type": "NetworkPolicy",
                    "resource_name": f"{np.metadata.namespace}/{np.metadata.name}",
                    "region": "kubernetes",
                    "metadata": {
                        "namespace": np.metadata.namespace,
                        "pod_selector": np.spec.pod_selector.match_labels if np.spec.pod_selector else {},
                        "policy_types": np.spec.policy_types or [],
                        "ingress_rules_count": len(np.spec.ingress or []),
                        "egress_rules_count": len(np.spec.egress or []),
                    },
                    "tags": np.metadata.labels or {}
                })

            logger.info("K8s Network Policies scanned", count=len(network_policies))
            return network_policies
        except ApiException as e:
            logger.error("Failed to scan K8s Network Policies", error=str(e))
            return []

    def scan_pod_security_policies(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Pod Security Policies (deprecated in K8s 1.25+)"""
        try:
            # Pod Security Policies are deprecated, returning empty list
            logger.info("Pod Security Policies are deprecated in Kubernetes 1.25+")
            return []
        except Exception as e:
            logger.error("Failed to scan K8s Pod Security Policies", error=str(e))
            return []

    def scan_storage_classes(self) -> List[Dict[str, Any]]:
        """Scan Kubernetes Storage Classes"""
        try:
            storage_classes = []
            for sc in self.storage_v1.list_storage_class().items:
                storage_classes.append({
                    "resource_id": f"storageclass/{sc.metadata.name}",
                    "resource_type": "StorageClass",
                    "resource_name": sc.metadata.name,
                    "region": "kubernetes",
                    "metadata": {
                        "provisioner": sc.provisioner,
                        "reclaim_policy": sc.reclaim_policy,
                        "volume_binding_mode": sc.volume_binding_mode,
                        "allow_volume_expansion": sc.allow_volume_expansion or False,
                        "parameters": sc.parameters or {},
                    },
                    "tags": sc.metadata.labels or {}
                })

            logger.info("K8s Storage Classes scanned", count=len(storage_classes))
            return storage_classes
        except ApiException as e:
            logger.error("Failed to scan K8s Storage Classes", error=str(e))
            return []
