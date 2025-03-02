import streamlit as st
import json
from datetime import datetime
import uuid
import os

import constants

def initialize_session_state():
    """Initialize session state variables if they don't exist"""
    if 'report_id' not in st.session_state:
        st.session_state.report_id = str(uuid.uuid4())
    
    if 'form_data' not in st.session_state:
        st.session_state.form_data = {}
    
    if 'report_types' not in st.session_state:
        st.session_state.report_types = []
    
    if 'common_data' not in st.session_state:
        st.session_state.common_data = {}
    
    if 'submission_status' not in st.session_state:
        st.session_state.submission_status = False
    
    if 'uploaded_files' not in st.session_state:
        st.session_state.uploaded_files = []
    
    if 'involves_real_world_incident' not in st.session_state:
        st.session_state.involves_real_world_incident = False
    
    if 'involves_threat_actor' not in st.session_state:
        st.session_state.involves_threat_actor = False

def determine_report_types():
    """Determine report types based on the answers to key questions"""
    report_types = []
    
    # Determine report types based on answers
    if st.session_state.involves_real_world_incident and st.session_state.involves_threat_actor:
        report_types = ["Real-World Events", "Malign Actor", "Security Incident Report"]
    elif st.session_state.involves_real_world_incident:
        report_types = ["Real-World Events"]
    elif st.session_state.involves_threat_actor:
        report_types = ["Malign Actor", "Vulnerability Report"]
    else:
        report_types = ["Hazard Report"]
    
    return report_types

def validate_required_fields(form_data, required_fields):
    """Validate that all required fields are filled"""
    missing_fields = []
    
    for field in required_fields:
        if field not in form_data or not form_data[field]:
            missing_fields.append(field)
    
    return missing_fields

def generate_recommendations(form_data):
    """Generate recommendations based on form data"""
    recommendations = ["AI System Developer"]
    
    # Add recommendations based on severity
    if form_data.get("Severity") in ["Critical", "High"]:
        recommendations.append("Regulatory Authorities")
    
    # Add recommendations based on impact
    if "Financial" in form_data.get("Impacts", []) or "Financial" in form_data.get("Impacts_Other", ""):
        recommendations.append("Financial Oversight Bodies")
    
    if "Privacy" in form_data.get("Impacts", []) or "Privacy" in form_data.get("Impacts_Other", "") or "Confidentiality breach" in form_data.get("Impact", ""):
        recommendations.append("Data Protection Authority")
    
    if "Users" in form_data.get("Impacted Stakeholder(s)", []) or "Users" in form_data.get("Impacted_Stakeholders_Other", ""):
        recommendations.append("User Community Forums")
    
    # Add recommendations for real-world events
    if "Real-World Events" in form_data.get("Report Types", []):
        recommendations.append("Affected Community Representatives")
        
    # Add security incident specific recommendations
    if "Security Incident Report" in form_data.get("Report Types", []):
        recommendations.append("Computer Emergency Response Team (CERT)")
        
    return recommendations

def handle_submission():
    # Combine all data
    form_data = st.session_state.form_data.copy()
    form_data.update(st.session_state.common_data)
    form_data["Submission Timestamp"] = datetime.now().isoformat()
    
    # Handle uploaded files
    if st.session_state.uploaded_files:
        file_names = [file.name for file in st.session_state.uploaded_files]
        form_data["Uploaded Files"] = file_names
    
    # Store form data in session state
    st.session_state.form_data = form_data
    st.session_state.submission_status = True

def save_uploaded_files(uploaded_files):
    """Save uploaded files and return their paths"""
    file_paths = []
    for file in uploaded_files:
        # Create directory if it doesn't exist
        os.makedirs("uploads", exist_ok=True)
        
        # Save file
        file_path = os.path.join("uploads", file.name)
        with open(file_path, "wb") as f:
            f.write(file.getbuffer())
        
        file_paths.append(file_path)
    
    return file_paths

def update_real_world_incident():
    st.session_state.involves_real_world_incident = st.session_state.real_world_incident

def update_threat_actor():
    st.session_state.involves_threat_actor = st.session_state.threat_actor

def create_app():
    """Main function to create the Streamlit app"""
    st.set_page_config(page_title="AI Flaw Report Form", layout="wide")
    
    # Initialize session state
    initialize_session_state()
    
    # App title and description
    st.title("AI Flaw & Incident Report Form")
    st.markdown("""
    This form allows you to report flaws, vulnerabilities, or incidents related to AI systems. 
    The information you provide will help identify, categorize, and address potential issues.
    
    Please fill out the appropriate sections based on the type of report you're submitting.
    """)
    
    # Common information section (always required)
    st.subheader("Basic Information")
    
    with st.container():
        col1, col2 = st.columns(2)
        
        with col1:
            reporter_id = st.text_input("Reporter ID (anonymous or real identity)", 
                                      help="Required field")
            
            st.text_input("Report ID", st.session_state.report_id, disabled=True)
        
        with col2:
            report_status = st.selectbox("Report Status", options=constants.REPORT_STATUS_OPTIONS)
            session_id = st.text_input("Session ID", help="Optional")
    
    # Common fields for All Flaw Reports  
    st.subheader("Common Fields")
    
    with st.container():
        col1, col2 = st.columns(2)
        
        with col1:
            flaw_timestamp_start = st.date_input("Flaw Timestamp Start", datetime.now())
            flaw_timestamp_end = st.date_input("Flaw Timestamp End", datetime.now())
            
            context_info = st.text_area("Context Info (versions of other software/hardware involved)", 
                                     help="Optional")
        
        with col2:
            # Replace System and Developer with a single "Systems" field
            systems = st.multiselect("Systems", options=constants.SYSTEM_OPTIONS)
            
            # Check if "Other" is selected in Systems
            if "Other" in systems:
                systems_other = st.text_area("Please specify other systems:")
            else:
                systems_other = ""
    
    # Flaw Description and Policy Violation
    flaw_description = st.text_area("Flaw Description (identification, reproduction, how it violates system policies)", 
                                 help="Required field")
    
    policy_violation = st.text_area("Policy Violation (how expectations of the system are violated)", 
                                 help="Required field")
    
    # Severity and Prevalence
    col1, col2 = st.columns(2)
    with col1:
        severity = st.select_slider("Severity", options=constants.SEVERITY_OPTIONS)
    with col2:
        prevalence = st.select_slider("Prevalence", options=constants.PREVALENCE_OPTIONS)
    
    # Impacts and Stakeholders
    col1, col2 = st.columns(2)
    with col1:
        impacts = st.multiselect("Impacts", options=constants.IMPACT_OPTIONS, 
                               help="Required field")
        
        # Check if "Other" is selected in Impacts
        if "Other" in impacts:
            impacts_other = st.text_area("Please specify other impacts:")
        else:
            impacts_other = ""
            
    with col2:
        impacted_stakeholders = st.multiselect("Impacted Stakeholder(s)", options=constants.STAKEHOLDER_OPTIONS, 
                                             help="Required field")
        
        # Check if "Other" is selected in Impacted Stakeholders
        if "Other" in impacted_stakeholders:
            impacted_stakeholders_other = st.text_area("Please specify other impacted stakeholders:")
        else:
            impacted_stakeholders_other = ""
    
    # Risk Source and Bounty Eligibility
    col1, col2 = st.columns(2)
    with col1:
        risk_source = st.multiselect("Risk Source", options=constants.RISK_SOURCE_OPTIONS)
        
        # Check if "Other" is selected in Risk Source
        if "Other" in risk_source:
            risk_source_other = st.text_area("Please specify other risk sources:")
        else:
            risk_source_other = ""
            
    with col2:
        bounty_eligibility = st.radio("Bounty Eligibility", options=constants.BOUNTY_OPTIONS)
    
    # Add file upload option
    uploaded_files = st.file_uploader("Upload Relevant Files", accept_multiple_files=True)
    if uploaded_files:
        st.session_state.uploaded_files = uploaded_files
        st.write(f"{len(uploaded_files)} file(s) uploaded")
    
    # Store the common data
    st.session_state.common_data = {
        "Reporter ID": reporter_id,
        "Report ID": st.session_state.report_id,
        "Report Status": report_status,
        "Session ID": session_id,
        "Flaw Timestamp Start": flaw_timestamp_start.isoformat() if flaw_timestamp_start else None,
        "Flaw Timestamp End": flaw_timestamp_end.isoformat() if flaw_timestamp_end else None,
        "Context Info": context_info,
        "Flaw Description": flaw_description,
        "Policy Violation": policy_violation,
        "Systems": systems,
        "Systems_Other": systems_other,
        "Severity": severity,
        "Prevalence": prevalence,
        "Impacts": impacts,
        "Impacts_Other": impacts_other,
        "Impacted Stakeholder(s)": impacted_stakeholders,
        "Impacted_Stakeholders_Other": impacted_stakeholders_other,
        "Risk Source": risk_source,
        "Risk_Source_Other": risk_source_other,
        "Bounty Eligibility": bounty_eligibility
    }
    
    # New Report Type Selection based on two questions
    st.subheader("Report Type Classification")
    st.markdown("Please answer the following questions to determine the appropriate report type:")
    
    # Question 1: Real-world incident
    st.checkbox(
        "Does this flaw report involve a real-world incident, where some form of harm has already occurred?", 
        key="real_world_incident",
        on_change=update_real_world_incident
    )
    st.caption("(e.g., injury or harm to people, disruption to infrastructure, violations of laws or rights, or harm to property, or communities)")
    
    # Question 2: Threat actor
    st.checkbox(
        "Does this flaw report involve a threat actor (i.e. could be exploited with ill intent)?",
        key="threat_actor",
        on_change=update_threat_actor
    )
    
    # Determine report types based on answers
    report_types = determine_report_types()
    
    # Display selected report types
    st.subheader("Selected Report Types")
    st.write(", ".join(report_types))
    
    # Store report types in session state
    st.session_state.report_types = report_types
    
    # Now show conditional fields based on determined report types
    if report_types:
        st.session_state.form_data = {}  # Reset form data
        
        # Real-World Events fields
        if "Real-World Events" in report_types:
            st.subheader("Real-World Event Details")
            
            with st.container():
                col1, col2 = st.columns(2)
                
                with col1:
                    incident_description = st.text_area("Description of the Incident(s)", 
                                                     help="Required field")
                    implicated_systems = st.text_area("Implicated Systems", 
                                                   help="Required field")
                
                with col2:
                    submitter_relationship = st.selectbox("Submitter Relationship", 
                                                       options=["Affected stakeholder", "Independent observer", "System developer", "Other"])
                    
                    # Check if "Other" is selected in Submitter Relationship
                    if submitter_relationship == "Other":
                        submitter_relationship_other = st.text_area("Please specify your relationship:")
                    else:
                        submitter_relationship_other = ""
                        
                    event_dates = st.date_input("Event Date(s)", datetime.now())
                    event_locations = st.text_input("Event Location(s)", 
                                                 help="Required field")
            
            with st.container():
                col1, col2 = st.columns(2)
                
                with col1:
                    experienced_harm_types = st.multiselect("Experienced Harm Types", options=constants.HARM_TYPES, 
                                                          help="Required field")
                    
                    # Check if "Other" is selected in Harm Types
                    if "Other" in experienced_harm_types:
                        harm_types_other = st.text_area("Please specify other harm types:")
                    else:
                        harm_types_other = ""
                
                with col2:
                    experienced_harm_severity = st.select_slider("Experienced Harm Severity", options=constants.HARM_SEVERITY_OPTIONS)
            
            harm_narrative = st.text_area("Harm Narrative (justification of why the event constitutes harm)", 
                                       help="Required field")
            
            # Update form data
            st.session_state.form_data.update({
                "Description of the Incident(s)": incident_description,
                "Implicated Systems": implicated_systems,
                "Submitter Relationship": submitter_relationship,
                "Submitter_Relationship_Other": submitter_relationship_other,
                "Event Date(s)": event_dates.isoformat() if event_dates else None,
                "Event Location(s)": event_locations,
                "Experienced Harm Types": experienced_harm_types,
                "Harm_Types_Other": harm_types_other,
                "Experienced Harm Severity": experienced_harm_severity,
                "Harm Narrative": harm_narrative
            })
        
        # Malign Actor fields
        if "Malign Actor" in report_types:
            st.subheader("Malign Actor Details")
            
            col1, col2 = st.columns(2)
            with col1:
                tactic_select = st.multiselect("Tactic Select (e.g., from MITRE's ATLAS Matrix)", options=constants.TACTIC_OPTIONS, 
                                             help="Required field")
                
                # Check if "Other" is selected in Tactic Select
                if "Other" in tactic_select:
                    tactic_select_other = st.text_area("Please specify other tactics:")
                else:
                    tactic_select_other = ""
                    
            with col2:
                impact = st.multiselect("Impact", options=constants.IMPACT_TYPE_OPTIONS, 
                                      help="Required field")
                
                # Check if "Other" is selected in Impact
                if "Other" in impact:
                    impact_other = st.text_area("Please specify other impacts:")
                else:
                    impact_other = ""
            
            # Update form data
            st.session_state.form_data.update({
                "Tactic Select": tactic_select,
                "Tactic_Select_Other": tactic_select_other,
                "Impact": impact,
                "Impact_Other": impact_other
            })
        
        # Security Incident Report fields
        if "Security Incident Report" in report_types:
            st.subheader("Security Incident Details")
            
            col1, col2 = st.columns(2)
            with col1:
                threat_actor_intent = st.radio("Threat Actor Intent", options=constants.THREAT_ACTOR_INTENT_OPTIONS)
                
                # Check if "Other" is selected in Threat Actor Intent
                if threat_actor_intent == "Other":
                    threat_actor_intent_other = st.text_area("Please specify other threat actor intent:")
                else:
                    threat_actor_intent_other = ""
                    
            with col2:
                detection = st.multiselect("Detection", options=constants.DETECTION_METHODS, 
                                         help="Required field")
                
                # Check if "Other" is selected in Detection
                if "Other" in detection:
                    detection_other = st.text_area("Please specify other detection methods:")
                else:
                    detection_other = ""
            
            # Update form data
            st.session_state.form_data.update({
                "Threat Actor Intent": threat_actor_intent,
                "Threat_Actor_Intent_Other": threat_actor_intent_other,
                "Detection": detection,
                "Detection_Other": detection_other
            })
        
        # Vulnerability Report fields
        if "Vulnerability Report" in report_types:
            st.subheader("Vulnerability Details")
            
            proof_of_concept = st.text_area("Proof-of-Concept Exploit", 
                                         help="Required field")
            
            # Update form data
            st.session_state.form_data.update({
                "Proof-of-Concept Exploit": proof_of_concept
            })
        
        # Hazard Report fields
        if "Hazard Report" in report_types:
            st.subheader("Hazard Details")
            
            examples = st.text_area("Examples (list of system inputs/outputs)", 
                                  help="Required field")
            
            replication_packet = st.text_area("Replication Packet (files evidencing the flaw)", 
                                           help="Required field")
            
            statistical_argument = st.text_area("Statistical Argument (supporting evidence of a flaw)", 
                                             help="Required field")
            
            # Update form data
            st.session_state.form_data.update({
                "Examples": examples,
                "Replication Packet": replication_packet,
                "Statistical Argument": statistical_argument
            })
        
        # Add "Report Types" to the form data
        st.session_state.form_data["Report Types"] = report_types
        
        # Submit button - outside any form
        if st.button("Submit Report"):
            # Validate all required fields based on selected report types
            required_fields = ["Reporter ID"]
            
            # Add common required fields
            required_fields.extend(["Flaw Description", "Policy Violation", "Impacts", "Impacted Stakeholder(s)"])
            
            # Add type-specific required fields
            if "Real-World Events" in report_types:
                required_fields.extend([
                    "Description of the Incident(s)", "Implicated Systems", "Event Location(s)",
                    "Experienced Harm Types", "Harm Narrative"
                ])
            
            if "Malign Actor" in report_types:
                required_fields.extend(["Tactic Select", "Impact"])
            
            if "Security Incident Report" in report_types:
                required_fields.append("Detection")
            
            if "Vulnerability Report" in report_types:
                required_fields.append("Proof-of-Concept Exploit")
            
            if "Hazard Report" in report_types:
                required_fields.extend(["Examples", "Replication Packet", "Statistical Argument"])
            
            # Combine all data for validation
            all_data = {**st.session_state.common_data, **st.session_state.form_data}
            
            # Validate
            missing_fields = validate_required_fields(all_data, required_fields)
            
            if missing_fields:
                st.error(f"Please fill out the following required fields: {', '.join(missing_fields)}")
            else:
                # Save uploaded files
                if st.session_state.uploaded_files:
                    file_paths = save_uploaded_files(st.session_state.uploaded_files)
                    st.session_state.form_data["Uploaded File Paths"] = file_paths
                
                handle_submission()
    
    # Display submission results if form was submitted
    if st.session_state.submission_status:
        # Generate recommendations
        recommendations = generate_recommendations(st.session_state.form_data)
        
        # Display JSON output and recommendations
        st.success("Report submitted successfully!")
        
        st.subheader("Form Data (JSON)")
        st.json(st.session_state.form_data)
        
        st.subheader("Recommended Recipients")
        for rec in recommendations:
            st.write(f"- {rec}")
        
        # Download button - now outside any form
        json_str = json.dumps(st.session_state.form_data, indent=4)
        st.download_button(
            label="Download JSON",
            data=json_str,
            file_name=f"ai_flaw_report_{st.session_state.report_id}.json",
            mime="application/json"
        )

if __name__ == "__main__":
    create_app()