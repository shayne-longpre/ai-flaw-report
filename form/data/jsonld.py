#!/usr/bin/env python3
"""
Convert AI Flaw Report JSON to JSON-LD format
"""

import json
import sys
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    from pydantic import BaseModel, Field, validator
except ImportError:
    print("Warning: pydantic not installed. Install with: pip install pydantic")
    BaseModel = object
    Field = lambda *args, **kwargs: None
    validator = lambda *args, **kwargs: lambda f: f

try:
    from pyld import jsonld
    PYLD_AVAILABLE = True
except ImportError:
    PYLD_AVAILABLE = False
    print("Note: pyld not installed. JSON-LD compaction will be skipped. Install with: pip install PyLD")


class NewFormatReport(BaseModel if BaseModel != object else object):
    """Schema for the new JSON format from the uploaded file"""
    
    class Config:
        extra = "allow"
    
    metadata: Optional[Dict[str, Any]] = None
    step: Optional[str] = None
    classifyReport: Optional[Dict[str, Any]] = None
    reporterDetails: Optional[Dict[str, Any]] = None
    incidentDescription: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    impactAssessment: Optional[Dict[str, Any]] = None
    securityDetails: Optional[Dict[str, Any]] = None
    disclosurePlan: Optional[Dict[str, Any]] = None
    reviewReport: Optional[Dict[str, Any]] = None


class AISystem(BaseModel if BaseModel != object else object):
    """Enriched AI System information"""
    
    id: str = Field(..., description="System identifier/URL")
    name: str = Field(..., description="System name")
    version: str = Field(default="", description="System version")
    display_name: str = Field(..., description="Human-friendly display name")
    system_type: str = Field(default="known", description="'known' or 'unknown'")


class ProcessedAIFlawReport(BaseModel if BaseModel != object else object):
    """Fully processed flaw report with enriched data"""
    
    report_id: str
    ai_systems: List[AISystem]
    created_at: datetime
    flaw_description: str
    policy_violation: str
    prevalence: str
    severity: str
    impacts: List[str] = Field(default=[])
    specific_harm_types: List[str] = Field(default=[])
    impacted_stakeholders: List[str] = Field(default=[])
    report_types: List[str] = Field(default=[])
    
    # Optional sections
    reporter_email: Optional[str] = None
    security_data: Optional[Dict[str, Any]] = None
    evidence_data: Optional[Dict[str, Any]] = None
    disclosure_intent: Optional[str] = None
    disclosure_timeline: Optional[str] = None
    disclosure_channels: List[str] = Field(default=[])
    
    # Classification flags
    real_world_harm: bool = False
    malicious_use: bool = False
    csam_involved: bool = False
    
    # Raw data storage
    raw_data: Optional[Dict[str, Any]] = None


def process_new_format_report(raw_data: Dict[str, Any]) -> ProcessedAIFlawReport:
    """Convert new JSON format to processed report structure"""
    
    metadata = raw_data.get("metadata", {})
    classify = raw_data.get("classifyReport", {})
    reporter_details = raw_data.get("reporterDetails", {})
    system_info = reporter_details.get("system", {})
    reporter_info = reporter_details.get("reporter", {})
    incident = raw_data.get("incidentDescription", {})
    evidence = raw_data.get("evidence", {})
    impact = raw_data.get("impactAssessment", {})
    security = raw_data.get("securityDetails", {})
    disclosure = raw_data.get("disclosurePlan", {})
    review = raw_data.get("reviewReport", {})
    
    # Generate report ID
    created_at_str = metadata.get("createdAt", datetime.now(timezone.utc).isoformat())
    report_id = f"AFL-{hashlib.md5(created_at_str.encode()).hexdigest()[:8]}"
    
    try:
        created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
    except:
        created_at = datetime.now(timezone.utc)
    
    ai_systems = []
    platforms = system_info.get("platforms", [])
    models = system_info.get("models", [])
    
    if platforms or models:
        for i, platform in enumerate(platforms):
            model = models[i] if i < len(models) else ""
            system_name = f"{platform} - {model}" if model else platform
            
            ai_systems.append(AISystem(
                id=f"https://ai-reports.org/systems/{platform.replace(' ', '_')}",
                name=platform,
                version=model,
                display_name=system_name,
                system_type="known"
            ))
    
    if not ai_systems:
        ai_systems.append(AISystem(
            id=f"https://ai-reports.org/reports/{report_id}/unknown-system",
            name="Unknown System",
            version="",
            display_name="Unknown System",
            system_type="unknown"
        ))
    
    # Extract description
    description = incident.get("issueDescription", "No description provided")
    
    # Extract policy violation
    policy_violation = incident.get("policyViolation", {})
    if isinstance(policy_violation, dict):
        policy_violation_text = policy_violation.get("reason", "Not specified")
    else:
        policy_violation_text = str(policy_violation) if policy_violation else "Not specified"
    
    # Determine report types
    report_types = []
    if classify.get("malicious_use"):
        report_types.append("Malicious Use")
    if classify.get("real_world_harm"):
        report_types.append("Real-World Incidents")
    if not report_types:
        report_types.append("General Report")
    
    # Security data
    security_data = None
    if security:
        security_data = {
            "substrate_relationship": security.get("substrateRelationship"),
            "attacker_resources": security.get("attackerResources"),
            "attacker_objectives": security.get("attackerObjectives"),
            "detection_method": security.get("detectionMethod"),
            "discovery_narrative": security.get("discoveryNarrative")
        }
    
    # Evidence data
    evidence_data = None
    if evidence:
        evidence_data = {
            "steps_to_reproduce": evidence.get("stepsToReproduce")
        }
    
    # Impact assessment
    harm_types = impact.get("harmTypes", [])
    if impact.get("harmOtherText"):
        harm_types.append(impact.get("harmOtherText"))
    
    # Disclosure
    disclosure_intent_map = {
        "yes": "Yes",
        "no": "No",
        "undecided": "Undecided"
    }
    disclosure_intent = disclosure_intent_map.get(
        disclosure.get("publicDisclosureIntent", "").lower(),
        disclosure.get("publicDisclosureIntent")
    )
    
    disclosure_channels = review.get("selectedStakeholders", [])
    
    processed_report = ProcessedAIFlawReport(
        report_id=report_id,
        ai_systems=ai_systems,
        created_at=created_at,
        flaw_description=description,
        policy_violation=policy_violation_text,
        prevalence=impact.get("prevalence", "Unknown"),
        severity=impact.get("severityOfHarm", "Unknown"),
        impacts=[impact.get("harmType")] if impact.get("harmType") else [],
        specific_harm_types=harm_types,
        impacted_stakeholders=impact.get("affectedStakeholders", []),
        report_types=report_types,
        reporter_email=reporter_info.get("email"),
        security_data=security_data,
        evidence_data=evidence_data,
        disclosure_intent=disclosure_intent,
        disclosure_timeline=disclosure.get("disclosureTimeline"),
        disclosure_channels=disclosure_channels,
        real_world_harm=classify.get("real_world_harm", False),
        malicious_use=classify.get("malicious_use", False),
        csam_involved=classify.get("csam_involved", False),
        raw_data=raw_data
    )
    
    return processed_report


def serialize_to_jsonld(processed_report: ProcessedAIFlawReport) -> Dict[str, Any]:
    """Convert processed report to JSON-LD format"""
    
    jsonld_systems = []
    system_names = []
    for system in processed_report.ai_systems:
        jsonld_systems.append({
            "@type": "schema:SoftwareApplication",
            "@id": system.id,
            "name": system.name,
            "version": system.version,
            "description": system.display_name
        })
        system_names.append(system.display_name)
    
    jsonld_report = {
        "@context": [
            "https://schema.org/",
            {
                "flare": "https://ai-reports.org/schema/",
                "aiSystem": "flare:aiSystem",
                "severity": "flare:severity",
                "prevalence": "flare:prevalence",
                "impacts": "flare:impacts",
                "reportType": "flare:reportType"
            }
        ],
        "@type": "flare:AIFlawReport",
        "@id": f"https://ai-reports.org/reports/{processed_report.report_id}",
        "name": f"AI Flaw Report: {', '.join(system_names)}",
        "description": processed_report.flaw_description,
        "aiSystem": jsonld_systems,
        "severity": processed_report.severity,
        "prevalence": processed_report.prevalence,
        "impacts": processed_report.impacts,
        "reportType": processed_report.report_types,
        "dateCreated": processed_report.created_at.isoformat(),
        "identifier": processed_report.report_id,
        "flare:policyViolation": processed_report.policy_violation
    }
    
    if processed_report.reporter_email:
        jsonld_report["author"] = {
            "@type": "schema:Person",
            "email": processed_report.reporter_email
        }
    
    if processed_report.impacted_stakeholders:
        jsonld_report["flare:impactedStakeholders"] = processed_report.impacted_stakeholders
    
    if processed_report.specific_harm_types:
        jsonld_report["flare:specificHarmTypes"] = processed_report.specific_harm_types
    
    jsonld_report["flare:classification"] = {
        "@type": "flare:ThreatClassification",
        "flare:realWorldHarm": processed_report.real_world_harm,
        "flare:maliciousUse": processed_report.malicious_use,
        "flare:csamInvolved": processed_report.csam_involved
    }
    
    if processed_report.security_data:
        sec = {
            "@type": "flare:SecurityIncident"
        }
        if processed_report.security_data.get("substrate_relationship"):
            sec["flare:substrateRelationship"] = processed_report.security_data["substrate_relationship"]
        if processed_report.security_data.get("attacker_resources"):
            sec["flare:attackerResources"] = processed_report.security_data["attacker_resources"]
        if processed_report.security_data.get("attacker_objectives"):
            sec["flare:attackerObjectives"] = processed_report.security_data["attacker_objectives"]
        if processed_report.security_data.get("detection_method"):
            sec["flare:detectionMethod"] = processed_report.security_data["detection_method"]
        if processed_report.security_data.get("discovery_narrative"):
            sec["flare:discoveryNarrative"] = processed_report.security_data["discovery_narrative"]
        jsonld_report["flare:securityAspect"] = sec
    
    if processed_report.evidence_data:
        jsonld_report["flare:evidence"] = {
            "@type": "flare:Evidence",
            "flare:stepsToReproduce": processed_report.evidence_data.get("steps_to_reproduce")
        }
    
    disclosure = {
        "@type": "flare:DisclosurePlan"
    }
    if processed_report.disclosure_intent:
        disclosure["flare:intent"] = processed_report.disclosure_intent
    if processed_report.disclosure_timeline:
        disclosure["flare:timeline"] = processed_report.disclosure_timeline
    if processed_report.disclosure_channels:
        disclosure["flare:channels"] = processed_report.disclosure_channels
    jsonld_report["flare:disclosure"] = disclosure
    
    if processed_report.raw_data:
        jsonld_report["flare:raw"] = processed_report.raw_data
    
    return jsonld_report


def generate_machine_readable_output(form_data: Dict[str, Any]) -> str:
    """
    Main function to convert new format JSON to JSON-LD
    """
    try:
        processed_report = process_new_format_report(form_data)
        jsonld_report = serialize_to_jsonld(processed_report)
        
        if PYLD_AVAILABLE:
            try:
                compacted = jsonld.compact(jsonld_report, jsonld_report["@context"])
                return json.dumps(compacted, indent=2)
            except Exception:
                pass
        
        return json.dumps(jsonld_report, indent=2)
            
    except Exception as e:
        # Fallback with error
        return json.dumps({
            "@context": "https://schema.org/",
            "@type": "Report",
            "@id": f"https://ai-reports.org/reports/error",
            "name": "AI Flaw Report (Processing Error)",
            "description": form_data.get("incidentDescription", {}).get("issueDescription", ""),
            "dateCreated": datetime.now(timezone.utc).isoformat(),
            "flare:processingError": str(e)
        }, indent=2)


def main():
    if len(sys.argv) < 2:
        print("Usage: python jsonld.py <input.json> [output.jsonld]")
        sys.exit(1)
    
    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else input_file.with_suffix('.jsonld')
    
    with open(input_file, 'r') as f:
        report_data = json.load(f)
    
    jsonld_output = generate_machine_readable_output(report_data)
    
    with open(output_file, 'w') as f:
        f.write(jsonld_output)
    
    print(f"Converted {input_file} to JSON-LD format")
    print(f"Output saved to {output_file}")


if __name__ == "__main__":
    main()