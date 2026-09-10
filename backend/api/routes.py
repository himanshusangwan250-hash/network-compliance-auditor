"""
API Routes — V6 primary / V4 fallback dual-model AI pipeline.

Architecture:
  Config → Parser → Normalization → Evidence Extraction → V6 Analysis
                                      ↓
                          Confidence Gate → V4 if uncertain → Fusion
                                      ↓
                                   Findings

The deterministic rules engine is NOT used for compliance decisions.
It is only used for rule metadata (IDs, descriptions, severity).
"""

from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List, Dict, Any
import json
import logging

from backend.parser.vendor_detector import detect_vendor
from backend.parser.cisco_ios import parse_cisco_ios
from backend.parser.juniper_junos import parse_juniper_junos
from backend.parser.paloalto_panos import parse_paloalto_panos
from backend.parser.paloalto_curly import parse_paloalto_curly
from backend.compliance.models import normalize
from backend.compliance.rules_engine import get_rule_ids, get_rule_details
from backend.ml.semantic_compliance import analyze_compliance
from backend.ml.evidence_extractor import extract_rule_evidence

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


@router.get("/health")
def health_check():
    return {"status": "ok"}


@router.get("/vendors")
def list_vendors() -> List[str]:
    return ["cisco_ios", "juniper_junos", "paloalto_panos"]


@router.get("/rules")
def list_rules() -> List[str]:
    """Return list of supported rule IDs."""
    return get_rule_ids()


@router.get("/rules/{rule_id}")
def rule_detail(rule_id: str) -> Dict[str, Any]:
    """Return metadata for a specific rule."""
    try:
        return get_rule_details(rule_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/audit")
async def audit_config(file: UploadFile = File(...)):
    """
    Audit an uploaded network configuration using the V6→V4 dual-model AI pipeline.

    For each CIS rule:
      1. Extract rule-specific evidence from the normalized config.
      2. Run V6 (primary model, ~95% F1).
      3. If V6 confidence < threshold → run V4 (fallback, strong real-world performance).
      4. Fuse results and return finding with full AI pipeline metadata.
    """
    # Read and validate file
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File too large. Maximum upload size is 10 MB.")
    try:
        config_text = content.decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to decode file as UTF-8. Please upload a text-based configuration file.")
    if not config_text.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty. Please provide a valid configuration file.")

    # Detect vendor
    detection = detect_vendor(config_text)
    vendor = detection.get("vendor")
    if vendor == "unknown":
        raise HTTPException(
            status_code=400,
            detail="Unable to detect vendor. Please ensure the file contains a supported network configuration.",
        )

    # Parse configuration
    if vendor == "cisco_ios":
        parsed = parse_cisco_ios(config_text)
    elif vendor == "juniper_junos":
        parsed = parse_juniper_junos(config_text)
    elif vendor == "paloalto_panos":
        try:
            parsed = parse_paloalto_panos(config_text)
        except Exception:
            parsed = parse_paloalto_curly(config_text)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported vendor '{vendor}'.")

    # Normalize configuration
    normalized = normalize(vendor, parsed)

    # Per-rule AI analysis via V6→V4 pipeline
    findings = []
    rule_ids = get_rule_ids()

    for rule_id in rule_ids:
        try:
            rule_info = get_rule_details(rule_id)
            policy_text = rule_info["description"]
        except ValueError:
            policy_text = f"Verify {rule_id} compliance"

        # Extract rule-specific evidence
        evidence_text = extract_rule_evidence(rule_id, normalized)

        # Run dual-model AI analysis
        ai_result = analyze_compliance(
            policy_text=policy_text,
            config_text=evidence_text,
            vendor=vendor,
            rule_id=rule_id,
        )

        # Map AI prediction to human-readable status
        prediction = ai_result.get("prediction", "uncertain")
        if prediction == "compliant":
            status = "PASS"
        elif prediction == "non_compliant":
            status = "FAIL"
        else:
            status = "UNKNOWN"

        # Build the ai_analysis sub-object for the frontend
        # Always include v6 info; include v4 only when fallback was triggered.
        ai_panel: Dict[str, Any] = {
            "prediction": prediction,
            "confidence": ai_result.get("confidence", 0.0),
            "probability": ai_result.get("probability", 0.5),
            "model_used": ai_result.get("model_used", "unknown"),
            "fallback_used": ai_result.get("fallback_used", False),
            "v6": ai_result.get("v6"),
        }
        if ai_result.get("fallback_used"):
            ai_panel["v4"] = ai_result.get("v4")
            ai_panel["models_agree"] = ai_result.get("models_agree", False)

        finding = {
            "rule_id": rule_id,
            "title": rule_info.get("title", rule_id),
            "severity": rule_info.get("severity", "Medium"),
            "status": status,
            "evidence": f"AI analysis: {prediction} (confidence: {ai_result.get('confidence', 0):.2%})",
            "remediation": rule_info.get("remediation", "Review configuration manually."),
            "ai_analysis": ai_panel,
        }
        findings.append(finding)

    # Calculate compliance score
    pass_count = sum(1 for f in findings if f["status"] == "PASS")
    fail_count = sum(1 for f in findings if f["status"] == "FAIL")
    unknown_count = sum(1 for f in findings if f["status"] == "UNKNOWN")
    total = len(findings)

    score = round((pass_count / total) * 100, 1) if total > 0 else None

    summary = {
        "pass": pass_count,
        "fail": fail_count,
        "unknown": unknown_count,
        "total": total,
    }

    return {
        "vendor": vendor,
        "format": parsed.get("format"),
        "hostname": normalized.hostname,
        "score": score,
        "summary": summary,
        "findings": findings,
        "unsupported_fields": normalized.unsupported_fields,
        "ai_pipeline": {
            "primary": "V6",
            "fallback": "V4",
            "v6_confidence_threshold": 0.80,
            "v6_weight": 0.60,
            "v4_weight": 0.40,
        },
    }
