"""
AI Flaw Report to VINCE Format Transformer
Converts AI Flaw Report JSON structure to VINCE vulnerability report format
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
import json


def get_systems_array(reporter_details: Dict) -> List[str]:
    """
    Extract all systems from the reporter details into a single array.
    Combines platform, platforms, and models fields.
    """
    systems = []
    
    system_info = reporter_details.get('system', {})
    
    if system_info.get('platform'):
        systems.append(system_info['platform'])
    
    if system_info.get('platforms'):
        systems.extend(system_info['platforms'])
    
    if system_info.get('models'):
        systems.extend(system_info['models'])
    
    return systems


def build_vul_description(ai_report: Dict) -> str:
    """
    Aggregate multiple fields into a comprehensive vulnerability description.
    """
    parts = []
    
    # Metadata
    metadata = ai_report.get('metadata', {})
    if metadata:
        parts.append(f"Report Type: {metadata.get('reportType', 'N/A')}")
        parts.append(f"Created At: {metadata.get('createdAt', 'N/A')}")
    
    # Issue description
    incident_desc = ai_report.get('incidentDescription', {})
    if incident_desc.get('issueDescription'):
        parts.append(f"\nIssue Description:\n{incident_desc['issueDescription']}")
    
    # Policy violation
    policy_violation = incident_desc.get('policyViolation', {})
    if policy_violation.get('reason'):
        parts.append(f"\nPolicy Violation Reason:\n{policy_violation['reason']}")
    
    # Impact assessment
    impact = ai_report.get('impactAssessment', {})
    if impact:
        parts.append(f"\nSeverity: {impact.get('severityOfHarm', 'N/A')}")
        parts.append(f"Prevalence: {impact.get('prevalence', 'N/A')}")
        parts.append(f"Harm Type: {impact.get('harmType', 'N/A')}")
        
        if impact.get('harmTypes'):
            parts.append(f"Specific Harm Types: {', '.join(impact['harmTypes'])}")
        
        if impact.get('affectedStakeholders'):
            parts.append(f"Affected Stakeholders: {', '.join(impact['affectedStakeholders'])}")
        
        if impact.get('documentedHarmCwe'):
            parts.append(f"CWE Classification: {impact['documentedHarmCwe']}")
        
        if impact.get('harmOtherText'):
            parts.append(f"Additional Harm Details: {impact['harmOtherText']}")
    
    return "\n".join(parts)


def build_vul_exploit(ai_report: Dict) -> str:
    """
    Build the vulnerability exploit description.
    Combines reproduction steps and attacker resources.
    """
    parts = []
    
    # Steps to reproduce
    evidence = ai_report.get('evidence', {})
    if evidence.get('stepsToReproduce'):
        parts.append(f"Steps to Reproduce:\n{evidence['stepsToReproduce']}")
    
    # Attacker resources
    security = ai_report.get('securityDetails', {})
    if security.get('attackerResources'):
        parts.append(f"\nAttacker Resources Required:\n{security['attackerResources']}")
    
    return "\n\n".join(parts) if parts else "See vulnerability description for details."


def build_vul_impact(ai_report: Dict) -> str:
    """
    Build the vulnerability impact description.
    """
    security = ai_report.get('securityDetails', {})
    classify = ai_report.get('classifyReport', {})
    
    if classify.get('malicious_use'):
        parts = []
        
        if security.get('attackerObjectives'):
            parts.append(f"Attacker Objectives: {security['attackerObjectives']}")
        
        # Add context from policy violation
        incident = ai_report.get('incidentDescription', {})
        policy = incident.get('policyViolation', {})
        if policy.get('reason'):
            parts.append(f"\nContext: {policy['reason']}")
        
        return "\n".join(parts) if parts else "Malicious use potential identified."
    else:
        return "N/A - This vulnerability does not involve a malign actor."


def build_vul_discovery(ai_report: Dict) -> str:
    """
    Build the vulnerability discovery description.
    """
    parts = []
    
    # Discovery narrative
    security = ai_report.get('securityDetails', {})
    if security.get('discoveryNarrative'):
        parts.append(f"Discovery Narrative:\n{security['discoveryNarrative']}")
    
    # Reproduction steps
    evidence = ai_report.get('evidence', {})
    if evidence.get('stepsToReproduce'):
        parts.append(f"\nReproduction Steps:\n{evidence['stepsToReproduce']}")
    
    return "\n\n".join(parts) if parts else "See evidence section for details."


def build_disclosure_plans(ai_report: Dict) -> str:
    """
    Build the disclosure plans description.
    """
    disclosure = ai_report.get('disclosurePlan', {})
    
    if not disclosure:
        return ""
    
    parts = []
    
    if disclosure.get('publicDisclosureIntent'):
        parts.append(f"Public Disclosure Intent: {disclosure['publicDisclosureIntent']}")
    
    if disclosure.get('disclosureTimeline'):
        parts.append(f"Timeline: {disclosure['disclosureTimeline']}")
    
    if disclosure.get('disclosureDatepicker'):
        try:
            date_obj = datetime.fromisoformat(disclosure['disclosureDatepicker'].replace('Z', '+00:00'))
            formatted_date = date_obj.strftime('%Y-%m-%d')
            parts.append(f"Planned Disclosure Date: {formatted_date}")
        except:
            parts.append(f"Planned Disclosure Date: {disclosure['disclosureDatepicker']}")
    
    if disclosure.get('embargoDetails'):
        parts.append(f"Embargo Details: {disclosure['embargoDetails']}")
    
    return "\n".join(parts)


def determine_ics_impact(ai_report: Dict) -> bool:
    """
    Determine if this affects industrial control systems or operational technology.
    Returns True if affected stakeholders include critical infrastructure indicators.
    """
    impact = ai_report.get('impactAssessment', {})
    stakeholders = impact.get('affectedStakeholders', [])
    
    critical_indicators = ['critical_systems', 'critical_infrastructure', 'operational_technology']
    
    return any(indicator in str(stakeholders).lower() for indicator in critical_indicators)


def transform_to_vince(ai_report: Dict) -> Dict[str, Any]:
    """
    Transform an AI Flaw Report JSON to VINCE format.
    
    Args:
        ai_report: Dictionary containing the AI Flaw Report data
        
    Returns:
        Dictionary in VINCE format
    """
    systems = get_systems_array(ai_report.get('reporterDetails', {}))
    
    multiplevendors = len(systems) > 1
    
    product_name = systems[0] if systems else "Unknown System"
    other_vendors = "\r\n".join(systems[1:]) if len(systems) > 1 else ""
    
    product_version = "\r\n".join(systems) if systems else "Not specified"
    
    reporter_details = ai_report.get('reporterDetails', {})
    reporter = reporter_details.get('reporter', {})
    contact_email = reporter.get('email', '')
    
    classify = ai_report.get('classifyReport', {})
    vul_exploited = classify.get('real_world_harm', False)
    
    disclosure = ai_report.get('disclosurePlan', {})
    has_embargo = bool(disclosure.get('embargoDetails', '').strip())
    vul_disclose = disclosure.get('publicDisclosureIntent', '').lower() == 'yes' and not has_embargo
    
    vince_report = {
        "comm_attempt": False,
        
        "first_contact": "",
        "vendor_communication": "",
        
        "why_no_attempt": "3", 
        "please_explain": "Vulnerability report forwarded from the AI Flaw Report form.",
        
        "vendor_name": "",
        
        "multiplevendors": multiplevendors,
        
        "other_vendors": other_vendors,
        
        "product_name": product_name,
        
        "product_version": product_version,
        
        "ics_impact": determine_ics_impact(ai_report),
        
        "ai_ml_system": True,
        
        "vul_description": build_vul_description(ai_report),
        
        "vul_exploit": build_vul_exploit(ai_report),
        
        "vul_impact": build_vul_impact(ai_report),
        
        "vul_discovery": build_vul_discovery(ai_report),
        
        "vul_public": False,
        
        "public_references": "",
        
        "vul_exploited": vul_exploited,
        
        "exploit_references": "",
        
        "vul_disclose": vul_disclose,
        
        "disclosure_plans": build_disclosure_plans(ai_report),
        
        "user_file": "",
        
        "contact_name": "",
        
        "contact_org": "",
        
        "contact_email": contact_email,
        
        "contact_phone": "",
        
        "share_release": False,
        
        "credit_release": False,
        
        "reporter_pgp": "",
        
        "tracking": "",
        
        "comments": "",
        
        "cisa_please": False
    }
    
    return vince_report


def transform_to_vince_json(ai_report_json: str) -> str:
    """
    Transform an AI Flaw Report JSON string to VINCE format JSON string.
    
    Args:
        ai_report_json: JSON string containing the AI Flaw Report data
        
    Returns:
        JSON string in VINCE format
    """
    import json
    
    ai_report = json.loads(ai_report_json)
    vince_report = transform_to_vince(ai_report)
    
    return json.dumps(vince_report, indent=2)


if __name__ == "__main__":
    ai_flaw_example = "/Users/elainezhu/Downloads/ai-flaw-report.json"
    
    with open(ai_flaw_example, 'r') as f:
        ai_report = json.load(f)
    vince_report = transform_to_vince(ai_report)
    print(json.dumps(vince_report, indent=2))