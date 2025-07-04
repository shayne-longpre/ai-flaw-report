import streamlit as st
import uuid
from datetime import datetime
import os
import json

from form.form_entry import FormEntry, InputType
from form.report_type_logic import determine_report_types
from form import form_sections
from form.data.validation import validate_required_fields
from form.data.constants import *
from form.utils.file_handling import save_uploaded_files
from form.utils.recipients import determine_report_recipients
from storage.storage_interface import get_storage_provider
from form.utils.recipients import display_submission_table

def initialize_session_state():
    """Initialize session state variables if they don't exist"""
    if 'report_id' not in st.session_state:
        st.session_state.report_id = str(uuid.uuid4())
    
    if 'form_data' not in st.session_state:
        st.session_state.form_data = {}
    
    if 'report_types' not in st.session_state:
        st.session_state.report_types = []
    
    if 'welcome_screen_acknowledged' not in st.session_state:
        st.session_state.welcome_screen_acknowledged = False
    
    if 'common_data' not in st.session_state:
        st.session_state.common_data = {}
    
    if 'submission_status' not in st.session_state:
        st.session_state.submission_status = False
    
    if 'uploaded_files' not in st.session_state:
        st.session_state.uploaded_files = []
    
    if 'involves_real_world_incident' not in st.session_state:
        st.session_state.involves_real_world_incident = None
    
    if 'involves_threat_actor' not in st.session_state:
        st.session_state.involves_threat_actor = None
        
    if 'real_world_incident_radio' not in st.session_state:
        st.session_state.real_world_incident_radio = None
        
    if 'threat_actor_radio' not in st.session_state:
        st.session_state.threat_actor_radio = None
    

def update_real_world_incident_radio():
    """Update the session state based on radio button selection"""
    if st.session_state.real_world_incident_radio == "Yes":
        st.session_state.involves_real_world_incident = True
    elif st.session_state.real_world_incident_radio == "No":
        st.session_state.involves_real_world_incident = False
    else:
        st.session_state.involves_real_world_incident = None

def update_threat_actor_radio():
    """Update the session state based on radio button selection"""
    if st.session_state.threat_actor_radio == "Yes":
        st.session_state.involves_threat_actor = True
    elif st.session_state.threat_actor_radio == "No":
        st.session_state.involves_threat_actor = False
    else:
        st.session_state.involves_threat_actor = None

def check_csam_harm_selected(harm_types):
    """Check if CSAM is selected as a harm type and show appropriate warning/guidance"""
    if "Child sexual-abuse material (CSAM)" in harm_types:
        st.error("""
        ## IMPORTANT: CSAM Reporting Guidelines
        
        **Possession and distribution of CSAM and AI-generated CSAM is illegal. Do not include illegal media in this report.**
        
        ### What to do instead:
        1. Report to the **National Center for Missing & Exploited Children (NCMEC)** via their CyberTipline: https://report.cybertip.org/
        2. If outside the US, report to the **Internet Watch Foundation (IWF)**: https://report.iwf.org.uk/
        3. Report directly to the AI model developer through their official channels
        
        Only share information about the nature of the issue, WITHOUT including illegal content, prompts that could generate illegal content, or specific details that could enable others to recreate the issue.
        
        This report will be restricted to appropriate stakeholders on a need-to-know basis.
        """)
        
        # Force user to acknowledge before proceeding
        csam_acknowledge = st.checkbox("I acknowledge these guidelines and confirm this report does NOT contain illegal media")
        
        return csam_acknowledge
    return True

def handle_submission():
    """Combine all data and prepare for submission"""
    form_data = st.session_state.form_data.copy()
    
    form_data.update(st.session_state.common_data)
    
    if check_csam_in_impacts(form_data):
        st.error("⚠️ **Submission blocked:** CSAM-related reports cannot be submitted through this form.")
        return
    
    if "Report ID" not in form_data and "report_id" in st.session_state:
        form_data["Report ID"] = st.session_state.report_id
    
    form_data["Submission Timestamp"] = datetime.now().isoformat()
    
    if st.session_state.uploaded_files:
        file_names = [file.name for file in st.session_state.uploaded_files]
        form_data["Uploaded Files"] = file_names
    
    st.session_state.form_data = form_data
    st.session_state.submission_status = True

def show_report_submission_results(form_data):
    """Redesigned to separate Created vs Submitted states"""
    st.success("Report successfully created!")

    report_id = form_data.get("Report ID", st.session_state.get("report_id", "unknown"))
    form_data["Report ID"] = report_id
    
    st.info(f"Here is the Report ID you can save for your reference in the future: **{report_id}**")
    
    storage_provider = get_storage_provider()
    
    # Make sure the provider is initialized before saving
    if not hasattr(storage_provider, 'initialized') or not storage_provider.initialized:
        #st.sidebar.warning("Storage provider not initialized. Re-initializing...")
        initialized = storage_provider.initialize()
    
    report_path, machine_readable_output = storage_provider.save_report(form_data)
    
    st.subheader("Your Report Has Been Created")
    st.write("Your report has been saved and is available for download in the following formats:")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Download as JSON using the verified report_id
        import json
        json_str = json.dumps(form_data, indent=4)
        st.download_button(
            label="Download Report (JSON)",
            data=json_str,
            file_name=f"ai_flaw_report_{report_id}.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col2:
        # Download as JSON-LD using the verified report_id
        json_ld_str = json.dumps(machine_readable_output, indent=4)
        st.download_button(
            label="Download Machine-Readable Report (JSON-LD)",
            data=json_ld_str,
            file_name=f"ai_flaw_report_{report_id}_jsonld.json",
            mime="application/json",
            use_container_width=True
        )
    
    st.markdown("---")
    
    st.subheader("Submit Your Report")
    st.write("You can automatically submit your report to the following recommended recipients:")
    
    recipients = determine_report_recipients(form_data)
    
    display_submission_table(recipients)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if len(recipients) > 0 and st.button("Submit to Selected Recipients", type="primary", use_container_width=True):
            selected_recipients = []
            
            grouped_recipients = {}
            for recipient in recipients:
                recipient_type = recipient.recipient_type
                if recipient_type not in grouped_recipients:
                    grouped_recipients[recipient_type] = []
                grouped_recipients[recipient_type].append(recipient)
            
            # Check which recipients are selected using the new key format
            for recipient_type, recipients_list in grouped_recipients.items():
                for i, recipient in enumerate(recipients_list):
                    checkbox_key = f"submit_to_{recipient.name.replace(' ', '_').replace('(', '').replace(')', '')}_{recipient_type}_{i}"
                    if st.session_state.get(checkbox_key, True):
                        selected_recipients.append(recipient)
            
            db_selected = st.session_state.get("submit_to_database", True)
            
            if selected_recipients or db_selected:
                total_submissions = len(selected_recipients) + (1 if db_selected else 0)
                st.success(f"Report submitted to {total_submissions} recipient(s)")
                
                st.write("**Submitted to:**")
                if db_selected:
                    st.write("- AI Flaw Report Database")
                for recipient in selected_recipients:
                    st.write(f"- {recipient.name}")
                    
                # FOR FUTURE IMPL: Call recipient.submit(form_data) for each recipient
            else:
                st.warning("No recipients were selected. Please select at least one recipient or download the report manually.")

def display_report_recipients(recipients):
    """Display the recommended recipients for the report with correct pluralization"""
    if not recipients:
        st.write("No specific recipients determined for this report.")
        return
    
    grouped_recipients = {}
    for recipient in recipients:
        recipient_type = recipient.recipient_type
        if recipient_type not in grouped_recipients:
            grouped_recipients[recipient_type] = []
        grouped_recipients[recipient_type].append(recipient)
    
    for recipient_type, recipients_list in grouped_recipients.items():
        if recipient_type == "Authority":
            plural_type = "Authorities"
        elif recipient_type.endswith("y"):
            plural_type = f"{recipient_type[:-1]}ies"  
        elif recipient_type.endswith("s"):
            plural_type = f"{recipient_type}es"
        else:
            plural_type = f"{recipient_type}s"
            
        st.write(f"**{plural_type}:**")
        for recipient in recipients_list:
            st.markdown(f"- [{recipient.name}]({recipient.contact})")

def display_file_upload():
    """Display file upload section"""
    uploaded_files = st.file_uploader("Upload Relevant Files: Any files that pertain to the reproducibility or documentation of the flaw. Please title them and refer to them in descriptions.", accept_multiple_files=True)
    st.caption("You can upload any relevant files that pertain to the reproducibility or documentation of the flaw. Please title them and refer to them in descriptions.")
    if uploaded_files:
        st.session_state.uploaded_files = uploaded_files
        st.write(f"{len(uploaded_files)} file(s) uploaded")

def display_report_type_classification():
    """Display report type classification questions"""
    st.subheader("Report Classification")
    st.markdown("Please answer the following questions to determine the appropriate report type:")

    # Question 1
    real_world_incident_field = FormEntry(
        name="real_world_incident_radio",
        title="Does this flaw report involve a real-world incident, where some form of harm has already occurred?",
        input_type=InputType.SEGMENTED_CONTROL,
        options=["Yes", "No"],
        help_text="(e.g., injury or harm to people, disruption to infrastructure, violations of laws or rights, or harm to property, or communities)",
        extra_params={"key": "real_world_incident_radio", "on_change": update_real_world_incident_radio}
    )
    real_world_incident_field.to_streamlit()
    
    # Question 2
    threat_actor_field = FormEntry(
        name="threat_actor_radio",
        title="Does this flaw report involve a threat actor (i.e. could be exploited with ill intent)?",
        input_type=InputType.SEGMENTED_CONTROL,
        options=["Yes", "No"],
        extra_params={"key": "threat_actor_radio", "on_change": update_threat_actor_radio}
    )
    threat_actor_field.to_streamlit()

def check_csam_in_impacts(form_data):
    """Check if CSAM is selected in any impact-related fields"""
    impacts = form_data.get("Impacts", [])
    experienced_harm_types = form_data.get("Experienced Harm Types", [])
    
    if impacts and "Child sexual-abuse material (CSAM)" in impacts:
        return True
    if experienced_harm_types and "Child sexual-abuse material (CSAM)" in experienced_harm_types:
        return True
    
    return False

# Replace this section in create_app():

def create_app():
    """Main function to create the Streamlit app with database integration"""
    st.set_page_config(page_title="AI Flaw Report Form", layout="wide")

    initialize_session_state()
    
    storage_provider = get_storage_provider()
    st.session_state['storage_provider'] = storage_provider
    
    if st.session_state.get('_needs_complete_reset', False):
        new_report_id = st.session_state.get('_new_report_id', str(uuid.uuid4()))
        current_provider = st.session_state.get('storage_provider')
        
        for key in list(st.session_state.keys()):
            del st.session_state[key]
            
        st.session_state.report_id = new_report_id
        st.session_state['storage_provider'] = current_provider
        initialize_session_state()
    else:
        initialize_session_state()
    
    st.title("AI Flaw & Incident Report Form")

    st.markdown("""
    You are welcome to report any broadly-scoped flaw, vulnerability, or incident relating to an AI system or model. 
    We encourage reports with demonstrable risks, harms, or systematic concerns related to general-purpose AI systems.
        
    **This form will:**
    * Help you generate a comprehensive, machine-readable report, informed by security best practices.
    * Elicit details that will make it easier to review and triage.
    * Provide the option to automatically submit your report to a list of the venues relevant for your flaw.
        
    This form creates a report *for you*. Reports are handled in **strict confidence**, and **will not be saved or sent unless you choose to submit them**.
        
    Please feel free to contact us at aiflawreports@gmail.com for questions or information.
    """)
    
    display_report_type_classification()
    
    # Calculate and IMMEDIATELY store report_types in session state
    report_types = determine_report_types(
        st.session_state.involves_real_world_incident, 
        st.session_state.involves_threat_actor
    )
    st.session_state.report_types = report_types  # ← ADD THIS LINE HERE!
    
    # Now the common fields can access the correct report_types
    basic_info = form_sections.display_basic_information()
    common_fields = form_sections.display_common_fields()
    reproducibility_data = form_sections.display_reproducibility()

    st.session_state.common_data = {**basic_info, **common_fields, **reproducibility_data}
    
    if st.session_state.involves_real_world_incident is not None and st.session_state.involves_threat_actor is not None:
        
        if report_types:
            st.session_state.form_data = {}
            
            # Real-World Events fields
            if "Real-World Incidents" in report_types:
                real_world_fields = form_sections.display_real_world_event_fields()
                st.session_state.form_data.update(real_world_fields)

            # Malign Actor fields
            if "Security Incident Report" in report_types or st.session_state.involves_threat_actor:
                malign_actor_fields = form_sections.display_malign_actor_fields()
                st.session_state.form_data.update(malign_actor_fields)
            
            # Security Incident Report fields
            if "Security Incident Report" in report_types:
                security_incident_fields = form_sections.display_security_incident_fields()
                st.session_state.form_data.update(security_incident_fields)
            
            # Hazard Report fields
            if "Hazard Report" in report_types:
                hazard_fields = form_sections.display_hazard_fields()
                st.session_state.form_data.update(hazard_fields)
            
            # Add public disclosure plan fields
            disclosure_plan = form_sections.display_disclosure_plan()
            st.session_state.form_data.update(disclosure_plan)
            
            st.session_state.form_data["Report Types"] = report_types

    if st.session_state.involves_real_world_incident is not None and st.session_state.involves_threat_actor is not None and report_types:
        if not st.session_state.submission_status:
            st.markdown("---")
            st.markdown(" ")
            
            csam_selected = st.session_state.get('csam_selected', False)
            
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                submit_button = st.button(
                    "Submit Report", 
                    type="primary", 
                    use_container_width=True, 
                    disabled=csam_selected
                )
                
                if csam_selected:
                    st.error("⚠️ **Submission blocked:** Reports involving CSAM cannot be submitted through this form. Please use the appropriate reporting channels listed above.")
                
            if submit_button and not csam_selected:
                required_fields = []
                
                is_incident = "Real-World Incidents" in report_types or "Security Incident Report" in report_types
                description_field = "Incident Description" if is_incident else "Flaw Description"
                
                required_fields.extend([description_field, "Policy Violation", "Impacts", "Impacted Stakeholder(s)"])
                required_fields.append("Disclosure Intent")
                
                all_data = {**st.session_state.common_data, **st.session_state.form_data}
                
                missing_fields = validate_required_fields(all_data, required_fields)
                
                if missing_fields:
                    st.error(f"Please fill out the following required fields: {', '.join(missing_fields)}")
                else:
                    if st.session_state.uploaded_files:
                        file_paths = save_uploaded_files(st.session_state.uploaded_files, report_id=all_data.get("Report ID"))
                        st.session_state.form_data["Uploaded Files"] = list(file_paths.keys())
                        st.session_state.form_data["Uploaded File Paths"] = list(file_paths.values())
                    
                    handle_submission()

    if st.session_state.submission_status:
        show_report_submission_results(st.session_state.form_data)