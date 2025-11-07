from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import structlog
import uvicorn

from config import settings
from database import get_db, init_db
from models import (
    Organization, CloudAccount, CloudResource, Audit,
    ComplianceRule, ComplianceResult, ComplianceStatus,
    ComplianceFramework, CloudProvider
)
from scanners.aws_scanner import AWSScanner
from compliance.engine import ComplianceEngine

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="API for Cloud Compliance Auditing (NIS2, SecNumCloud)",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize compliance engine
compliance_engine = ComplianceEngine(rules_path=settings.COMPLIANCE_RULES_PATH)


# ============== API Endpoints ==============

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    logger.info("Starting Cloud Compliance Tool API", version=settings.APP_VERSION)
    init_db()


@app.get("/")
def read_root():
    """Root endpoint"""
    return {
        "status": "OK",
        "message": "Cloud Compliance Tool API",
        "version": settings.APP_VERSION,
        "frameworks": ["NIS2", "SecNumCloud", "ISO27001", "GDPR"]
    }


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# ============== Cloud Account Endpoints ==============

@app.post("/api/v1/cloud-accounts/scan")
async def scan_cloud_account(
    provider: str = "aws",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: str = "eu-west-1",
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db)
):
    """
    Scan cloud account to discover resources
    """
    logger.info("Starting cloud scan", provider=provider, region=region)

    try:
        if provider.lower() == "aws":
            scanner = AWSScanner(
                access_key=access_key or settings.AWS_ACCESS_KEY_ID,
                secret_key=secret_key or settings.AWS_SECRET_ACCESS_KEY,
                region=region
            )
            resources = scanner.scan_all()

            # Return discovered resources
            return {
                "status": "success",
                "provider": provider,
                "region": region,
                "resources_discovered": {k: len(v) for k, v in resources.items()},
                "total_resources": sum(len(v) for v in resources.values()),
                "resources": resources
            }
        else:
            raise HTTPException(status_code=400, detail=f"Provider {provider} not yet supported")

    except Exception as e:
        logger.error("Cloud scan failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# ============== Compliance Audit Endpoints ==============

@app.post("/api/v1/audits/run")
async def run_compliance_audit(
    framework: str = "NIS2",
    provider: str = "aws",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: str = "eu-west-1",
    db: Session = Depends(get_db)
):
    """
    Run a complete compliance audit
    """
    logger.info("Starting compliance audit", framework=framework, provider=provider)

    try:
        # Step 1: Scan cloud resources
        if provider.lower() == "aws":
            scanner = AWSScanner(
                access_key=access_key or settings.AWS_ACCESS_KEY_ID,
                secret_key=secret_key or settings.AWS_SECRET_ACCESS_KEY,
                region=region
            )
            scanned_resources = scanner.scan_all()

            # Flatten resources for evaluation
            all_resources = []
            for resource_type, resources in scanned_resources.items():
                all_resources.extend(resources)

        else:
            raise HTTPException(status_code=400, detail=f"Provider {provider} not supported")

        # Step 2: Evaluate compliance
        audit_result = compliance_engine.evaluate_framework(all_resources, framework)

        # Step 3: Return results
        return {
            "status": "success",
            "audit": audit_result,
            "summary": {
                "framework": framework,
                "compliance_score": audit_result.get('compliance_score'),
                "total_checks": audit_result.get('total_checks'),
                "passed_checks": audit_result.get('passed_checks'),
                "failed_checks": audit_result.get('failed_checks'),
                "warning_checks": audit_result.get('warning_checks'),
            }
        }

    except Exception as e:
        logger.error("Compliance audit failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/audits/{audit_id}")
async def get_audit(audit_id: int, db: Session = Depends(get_db)):
    """Get audit details by ID"""
    audit = db.query(Audit).filter(Audit.id == audit_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


@app.get("/api/v1/audits")
async def list_audits(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List all audits"""
    audits = db.query(Audit).offset(skip).limit(limit).all()
    return audits


# ============== Compliance Rules Endpoints ==============

@app.get("/api/v1/compliance/frameworks")
async def list_frameworks():
    """List all supported compliance frameworks"""
    return {
        "frameworks": [
            {
                "id": "NIS2",
                "name": "Directive NIS2",
                "description": "Network and Information Systems Directive (EU)",
                "rules_count": len(compliance_engine.rules.get('nis2', {}))
            },
            {
                "id": "SecNumCloud",
                "name": "SecNumCloud ANSSI",
                "description": "Référentiel SecNumCloud de l'ANSSI",
                "rules_count": len(compliance_engine.rules.get('secnumcloud', {}))
            }
        ]
    }


@app.get("/api/v1/compliance/rules/{framework}")
async def list_framework_rules(framework: str):
    """List all rules for a specific framework"""
    framework_rules = compliance_engine.rules.get(framework.lower(), {})

    if not framework_rules:
        raise HTTPException(status_code=404, detail=f"Framework {framework} not found")

    return {
        "framework": framework,
        "rules_count": len(framework_rules),
        "rules": framework_rules
    }


# ============== Reports Endpoints ==============

@app.get("/api/v1/reports/audit/{audit_id}")
async def generate_audit_report(
    audit_id: int,
    format: str = "json",
    db: Session = Depends(get_db)
):
    """Generate audit report in various formats"""
    audit = db.query(Audit).filter(Audit.id == audit_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    # Get compliance results
    results = db.query(ComplianceResult).filter(ComplianceResult.audit_id == audit_id).all()

    if format == "json":
        return {
            "audit": audit,
            "results": results
        }
    elif format == "pdf":
        # TODO: Implement PDF generation
        raise HTTPException(status_code=501, detail="PDF format not yet implemented")
    elif format == "excel":
        # TODO: Implement Excel generation
        raise HTTPException(status_code=501, detail="Excel format not yet implemented")
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")


# ============== Statistics Endpoints ==============

@app.get("/api/v1/stats/compliance-overview")
async def get_compliance_overview(
    provider: str = "aws",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: str = "eu-west-1"
):
    """Get compliance overview with scores for all frameworks"""
    try:
        # Scan resources
        if provider.lower() == "aws":
            scanner = AWSScanner(
                access_key=access_key or settings.AWS_ACCESS_KEY_ID,
                secret_key=secret_key or settings.AWS_SECRET_ACCESS_KEY,
                region=region
            )
            scanned_resources = scanner.scan_all()

            all_resources = []
            for resource_type, resources in scanned_resources.items():
                all_resources.extend(resources)

        # Evaluate all frameworks
        frameworks_results = {}
        for framework in ['NIS2', 'SecNumCloud']:
            result = compliance_engine.evaluate_framework(all_resources, framework)
            frameworks_results[framework] = {
                "compliance_score": result.get('compliance_score'),
                "total_checks": result.get('total_checks'),
                "passed_checks": result.get('passed_checks'),
                "failed_checks": result.get('failed_checks'),
                "warning_checks": result.get('warning_checks'),
            }

        # Calculate global score
        global_score = sum(f['compliance_score'] for f in frameworks_results.values()) / len(frameworks_results)

        return {
            "status": "success",
            "global_compliance_score": round(global_score, 2),
            "frameworks": frameworks_results,
            "total_resources": len(all_resources),
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error("Failed to get compliance overview", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
