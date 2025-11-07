from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Float, Enum, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import enum


class ComplianceStatus(enum.Enum):
    """Compliance status enumeration"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class CloudProvider(enum.Enum):
    """Cloud provider enumeration"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OVH = "ovh"
    SCALEWAY = "scaleway"
    ON_PREMISE = "on_premise"


class ComplianceFramework(enum.Enum):
    """Compliance framework enumeration"""
    NIS2 = "nis2"
    SECNUMCLOUD = "secnumcloud"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HDS = "hds"
    PCI_DSS = "pci_dss"


class Organization(Base):
    """Organization/Company model"""
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    cloud_accounts = relationship("CloudAccount", back_populates="organization")
    audits = relationship("Audit", back_populates="organization")


class CloudAccount(Base):
    """Cloud account/subscription model"""
    __tablename__ = "cloud_accounts"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    name = Column(String, nullable=False)
    provider = Column(Enum(CloudProvider), nullable=False)
    account_id = Column(String)  # AWS Account ID, Azure Subscription ID, etc.
    region = Column(String)
    credentials = Column(JSON)  # Encrypted credentials
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", back_populates="cloud_accounts")
    resources = relationship("CloudResource", back_populates="cloud_account")


class CloudResource(Base):
    """Cloud resource model (EC2, S3, VM, etc.)"""
    __tablename__ = "cloud_resources"

    id = Column(Integer, primary_key=True, index=True)
    cloud_account_id = Column(Integer, ForeignKey("cloud_accounts.id"))
    resource_id = Column(String, nullable=False)  # AWS ARN, Azure Resource ID, etc.
    resource_type = Column(String, nullable=False)  # EC2, S3, VirtualMachine, etc.
    resource_name = Column(String)
    region = Column(String)
    metadata = Column(JSON)  # Full resource details
    tags = Column(JSON)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    last_scanned = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    cloud_account = relationship("CloudAccount", back_populates="resources")
    compliance_results = relationship("ComplianceResult", back_populates="resource")


class Audit(Base):
    """Audit execution model"""
    __tablename__ = "audits"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    name = Column(String, nullable=False)
    framework = Column(Enum(ComplianceFramework), nullable=False)
    status = Column(String, default="running")  # running, completed, failed
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    warning_checks = Column(Integer, default=0)
    compliance_score = Column(Float)  # 0-100
    metadata = Column(JSON)

    # Relationships
    organization = relationship("Organization", back_populates="audits")
    compliance_results = relationship("ComplianceResult", back_populates="audit")


class ComplianceRule(Base):
    """Compliance rule definition model"""
    __tablename__ = "compliance_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, nullable=False)
    framework = Column(Enum(ComplianceFramework), nullable=False)
    category = Column(String)  # Article 21, Article 22, etc.
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String)  # critical, high, medium, low
    remediation = Column(Text)
    references = Column(JSON)  # Links to official documentation
    cloud_providers = Column(JSON)  # List of applicable providers
    resource_types = Column(JSON)  # List of applicable resource types
    checks = Column(JSON)  # Check configuration
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    compliance_results = relationship("ComplianceResult", back_populates="rule")


class ComplianceResult(Base):
    """Compliance check result model"""
    __tablename__ = "compliance_results"

    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(Integer, ForeignKey("audits.id"))
    rule_id = Column(Integer, ForeignKey("compliance_rules.id"))
    resource_id = Column(Integer, ForeignKey("cloud_resources.id"))
    status = Column(Enum(ComplianceStatus), nullable=False)
    message = Column(Text)
    evidence = Column(JSON)  # Proof of compliance/non-compliance
    remediation_steps = Column(JSON)  # Specific steps to fix
    checked_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    audit = relationship("Audit", back_populates="compliance_results")
    rule = relationship("ComplianceRule", back_populates="compliance_results")
    resource = relationship("CloudResource", back_populates="compliance_results")
