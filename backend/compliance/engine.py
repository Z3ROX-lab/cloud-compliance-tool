from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import os
import structlog
from models import ComplianceStatus, ComplianceFramework

logger = structlog.get_logger()


class ComplianceEngine:
    """Compliance evaluation engine for NIS2, SecNumCloud, and other frameworks"""

    def __init__(self, rules_path: str = "compliance_rules"):
        """Initialize compliance engine with rules directory"""
        self.rules_path = rules_path
        self.rules = {}
        self.load_all_rules()
        logger.info("Compliance Engine initialized", rules_loaded=len(self.rules))

    def load_all_rules(self):
        """Load all compliance rules from directory"""
        if not os.path.exists(self.rules_path):
            logger.warning("Rules path does not exist", path=self.rules_path)
            return

        for framework in os.listdir(self.rules_path):
            framework_path = os.path.join(self.rules_path, framework)
            if os.path.isdir(framework_path):
                self.rules[framework.lower()] = {}
                for rule_file in os.listdir(framework_path):
                    if rule_file.endswith('.json'):
                        rule_path = os.path.join(framework_path, rule_file)
                        with open(rule_path, 'r', encoding='utf-8') as f:
                            rule = json.load(f)
                            rule_id = rule.get('id', rule_file.replace('.json', ''))
                            self.rules[framework.lower()][rule_id] = rule
                            logger.debug("Rule loaded", framework=framework, rule_id=rule_id)

    def evaluate_resource(self, resource: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single resource against a compliance rule"""
        rule_id = rule.get('id')
        checks = rule.get('checks', [])

        results = []
        for check in checks:
            result = self._execute_check(resource, check, rule)
            results.append(result)

        # Aggregate results
        all_passed = all(r['status'] == ComplianceStatus.COMPLIANT for r in results)
        any_failed = any(r['status'] == ComplianceStatus.NON_COMPLIANT for r in results)
        any_warning = any(r['status'] == ComplianceStatus.WARNING for r in results)

        if all_passed:
            final_status = ComplianceStatus.COMPLIANT
            message = "All checks passed"
        elif any_failed:
            final_status = ComplianceStatus.NON_COMPLIANT
            message = "One or more checks failed"
        elif any_warning:
            final_status = ComplianceStatus.WARNING
            message = "One or more checks have warnings"
        else:
            final_status = ComplianceStatus.NOT_APPLICABLE
            message = "Not applicable"

        return {
            "rule_id": rule_id,
            "status": final_status,
            "message": message,
            "evidence": results,
            "remediation_steps": rule.get('remediation', []),
            "checked_at": datetime.utcnow().isoformat()
        }

    def _execute_check(self, resource: Dict[str, Any], check: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single check on a resource"""
        check_type = check.get('type', 'property')

        if check_type == 'property':
            return self._check_property(resource, check)
        elif check_type == 'exists':
            return self._check_exists(resource, check)
        elif check_type == 'regex':
            return self._check_regex(resource, check)
        elif check_type == 'custom':
            return self._check_custom(resource, check)
        else:
            return {
                'status': ComplianceStatus.ERROR,
                'message': f"Unknown check type: {check_type}"
            }

    def _check_property(self, resource: Dict[str, Any], check: Dict[str, Any]) -> Dict[str, Any]:
        """Check if a property matches expected value"""
        property_path = check.get('property', '').split('.')
        expected_value = check.get('expected')
        operator = check.get('operator', 'equals')

        # Navigate through nested properties
        current = resource
        for prop in property_path:
            if isinstance(current, dict):
                current = current.get(prop)
            else:
                return {
                    'status': ComplianceStatus.ERROR,
                    'message': f"Cannot access property: {'.'.join(property_path)}"
                }

        # Compare values based on operator
        if operator == 'equals':
            if current == expected_value:
                return {'status': ComplianceStatus.COMPLIANT, 'message': f"Property matches: {current}"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': f"Expected {expected_value}, got {current}"}

        elif operator == 'not_equals':
            if current != expected_value:
                return {'status': ComplianceStatus.COMPLIANT, 'message': f"Property does not match: {current}"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': f"Should not equal {expected_value}"}

        elif operator == 'contains':
            if isinstance(current, (list, str)) and expected_value in current:
                return {'status': ComplianceStatus.COMPLIANT, 'message': f"Contains {expected_value}"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': f"Does not contain {expected_value}"}

        elif operator == 'greater_than':
            if current and current > expected_value:
                return {'status': ComplianceStatus.COMPLIANT, 'message': f"Value {current} > {expected_value}"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': f"Value {current} not > {expected_value}"}

        elif operator == 'less_than':
            if current and current < expected_value:
                return {'status': ComplianceStatus.COMPLIANT, 'message': f"Value {current} < {expected_value}"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': f"Value {current} not < {expected_value}"}

        elif operator == 'is_true':
            if current is True or current == 'true' or current == 'True':
                return {'status': ComplianceStatus.COMPLIANT, 'message': "Property is true"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': f"Property is not true: {current}"}

        elif operator == 'is_false':
            if current is False or current == 'false' or current == 'False':
                return {'status': ComplianceStatus.COMPLIANT, 'message': "Property is false"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': f"Property is not false: {current}"}

        else:
            return {'status': ComplianceStatus.ERROR, 'message': f"Unknown operator: {operator}"}

    def _check_exists(self, resource: Dict[str, Any], check: Dict[str, Any]) -> Dict[str, Any]:
        """Check if a property exists"""
        property_path = check.get('property', '').split('.')

        current = resource
        for prop in property_path:
            if isinstance(current, dict) and prop in current:
                current = current[prop]
            else:
                return {
                    'status': ComplianceStatus.NON_COMPLIANT,
                    'message': f"Property does not exist: {'.'.join(property_path)}"
                }

        return {
            'status': ComplianceStatus.COMPLIANT,
            'message': f"Property exists: {'.'.join(property_path)}"
        }

    def _check_regex(self, resource: Dict[str, Any], check: Dict[str, Any]) -> Dict[str, Any]:
        """Check if a property matches a regex pattern"""
        import re

        property_path = check.get('property', '').split('.')
        pattern = check.get('pattern')

        current = resource
        for prop in property_path:
            if isinstance(current, dict):
                current = current.get(prop)
            else:
                return {
                    'status': ComplianceStatus.ERROR,
                    'message': f"Cannot access property: {'.'.join(property_path)}"
                }

        if current and re.match(pattern, str(current)):
            return {'status': ComplianceStatus.COMPLIANT, 'message': f"Matches pattern: {pattern}"}
        else:
            return {'status': ComplianceStatus.NON_COMPLIANT, 'message': f"Does not match pattern: {pattern}"}

    def _check_custom(self, resource: Dict[str, Any], check: Dict[str, Any]) -> Dict[str, Any]:
        """Execute custom check logic"""
        check_name = check.get('check_name')

        # Custom checks can be implemented here
        if check_name == 'public_access':
            return self._check_public_access(resource)
        elif check_name == 'encryption':
            return self._check_encryption(resource)
        elif check_name == 'mfa_enabled':
            return self._check_mfa_enabled(resource)
        elif check_name == 'logging_enabled':
            return self._check_logging_enabled(resource)
        else:
            return {'status': ComplianceStatus.ERROR, 'message': f"Unknown custom check: {check_name}"}

    def _check_public_access(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Check if resource has public access"""
        resource_type = resource.get('resource_type')
        metadata = resource.get('metadata', {})

        if resource_type == 'S3Bucket':
            public_access_block = metadata.get('public_access_block', {})
            if public_access_block.get('BlockPublicAcls') and public_access_block.get('BlockPublicPolicy'):
                return {'status': ComplianceStatus.COMPLIANT, 'message': "Public access blocked"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "Public access not fully blocked"}

        elif resource_type == 'EC2Instance':
            if metadata.get('public_ip'):
                return {'status': ComplianceStatus.WARNING, 'message': "Instance has public IP"}
            else:
                return {'status': ComplianceStatus.COMPLIANT, 'message': "No public IP"}

        elif resource_type == 'RDSInstance':
            if metadata.get('publicly_accessible'):
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "Database is publicly accessible"}
            else:
                return {'status': ComplianceStatus.COMPLIANT, 'message': "Database is not publicly accessible"}

        return {'status': ComplianceStatus.NOT_APPLICABLE, 'message': "Public access check not applicable"}

    def _check_encryption(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Check if resource is encrypted"""
        resource_type = resource.get('resource_type')
        metadata = resource.get('metadata', {})

        if resource_type == 'S3Bucket':
            if metadata.get('encryption'):
                return {'status': ComplianceStatus.COMPLIANT, 'message': "Bucket is encrypted"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "Bucket is not encrypted"}

        elif resource_type == 'EBSVolume':
            if metadata.get('encrypted'):
                return {'status': ComplianceStatus.COMPLIANT, 'message': "Volume is encrypted"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "Volume is not encrypted"}

        elif resource_type == 'RDSInstance':
            if metadata.get('storage_encrypted'):
                return {'status': ComplianceStatus.COMPLIANT, 'message': "Database is encrypted"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "Database is not encrypted"}

        elif resource_type == 'EBSSnapshot':
            if metadata.get('encrypted'):
                return {'status': ComplianceStatus.COMPLIANT, 'message': "Snapshot is encrypted"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "Snapshot is not encrypted"}

        return {'status': ComplianceStatus.NOT_APPLICABLE, 'message': "Encryption check not applicable"}

    def _check_mfa_enabled(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Check if MFA is enabled"""
        resource_type = resource.get('resource_type')
        metadata = resource.get('metadata', {})

        if resource_type == 'IAMUser':
            if metadata.get('mfa_enabled'):
                return {'status': ComplianceStatus.COMPLIANT, 'message': "MFA is enabled"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "MFA is not enabled"}

        return {'status': ComplianceStatus.NOT_APPLICABLE, 'message': "MFA check not applicable"}

    def _check_logging_enabled(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Check if logging is enabled"""
        resource_type = resource.get('resource_type')
        metadata = resource.get('metadata', {})

        if resource_type == 'CloudTrail':
            if metadata.get('is_logging'):
                return {'status': ComplianceStatus.COMPLIANT, 'message': "CloudTrail logging is enabled"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "CloudTrail logging is disabled"}

        elif resource_type == 'S3Bucket':
            if metadata.get('logging'):
                return {'status': ComplianceStatus.COMPLIANT, 'message': "S3 bucket logging is enabled"}
            else:
                return {'status': ComplianceStatus.NON_COMPLIANT, 'message': "S3 bucket logging is disabled"}

        return {'status': ComplianceStatus.NOT_APPLICABLE, 'message': "Logging check not applicable"}

    def evaluate_framework(self, resources: List[Dict[str, Any]], framework: str) -> Dict[str, Any]:
        """Evaluate all resources against a compliance framework"""
        framework_rules = self.rules.get(framework.lower(), {})

        if not framework_rules:
            logger.warning("No rules found for framework", framework=framework)
            return {
                'framework': framework,
                'status': 'error',
                'message': f"No rules found for framework: {framework}",
                'results': []
            }

        results = []
        total_checks = 0
        passed_checks = 0
        failed_checks = 0
        warning_checks = 0

        for rule_id, rule in framework_rules.items():
            # Filter applicable resources
            applicable_resource_types = rule.get('resource_types', [])
            applicable_resources = [r for r in resources if r.get('resource_type') in applicable_resource_types] if applicable_resource_types else resources

            for resource in applicable_resources:
                result = self.evaluate_resource(resource, rule)
                result['resource_id'] = resource.get('resource_id')
                result['resource_type'] = resource.get('resource_type')
                result['resource_name'] = resource.get('resource_name')
                results.append(result)

                total_checks += 1
                if result['status'] == ComplianceStatus.COMPLIANT:
                    passed_checks += 1
                elif result['status'] == ComplianceStatus.NON_COMPLIANT:
                    failed_checks += 1
                elif result['status'] == ComplianceStatus.WARNING:
                    warning_checks += 1

        # Calculate compliance score
        compliance_score = (passed_checks / total_checks * 100) if total_checks > 0 else 0

        return {
            'framework': framework,
            'status': 'completed',
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'warning_checks': warning_checks,
            'compliance_score': round(compliance_score, 2),
            'results': results,
            'evaluated_at': datetime.utcnow().isoformat()
        }
