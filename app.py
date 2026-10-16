import streamlit as st
import os
import tempfile
import json
from scanner import analyze_apk

st.set_page_config(page_title="TruthGuard - Forensic APK Scanner", layout="wide")

st.title("🛡️ TruthGuard: Android APK Forensic & Threat Analyzer")
st.caption("AI-Assisted Security Analysis Platform | Bihar Cyber Hackathon 2026")

uploaded_file = st.file_uploader("Upload an Android APK file for inspection", type=["apk"])

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
        tmp_file.write(uploaded_file.read())
        temp_path = tmp_file.name

    with st.spinner("Decompiling and extracting IoCs..."):
        try:
            results = analyze_apk(temp_path)
            
            st.divider()
            
            # App Metadata Metrics
            col1, col2, col3 = st.columns(3)
            col1.metric("App Name", str(results["app_name"]))
            col2.metric("Package", str(results["package_name"]))
            col3.metric("Target SDK", str(results["target_sdk"]))
            
            st.divider()

            # Risk Summary Card
            score = results["risk_score"]
            level = results["risk_level"]

            if score >= 60:
                st.error(f"🚨 Threat Level: {level} | Risk Score: {score}/100")
            elif score >= 30:
                st.warning(f"⚠️ Threat Level: {level} | Risk Score: {score}/100")
            else:
                st.success(f"✅ Threat Level: {level} | Risk Score: {score}/100")

            # Two Column Analysis
            col_left, col_right = st.columns(2)

            with col_left:
                st.subheader("📋 Permissions Breakdown")
                st.write(f"**Total Permissions Requested:** {results['total_permissions']}")
                if results["dangerous_permissions"]:
                    for perm in results["dangerous_permissions"]:
                        st.write(f"- 🔴 `{perm}`")
                else:
                    st.write("No critical permissions detected.")

            with col_right:
                st.subheader("🌐 Network IoCs & Suspicious Endpoints")
                urls = results.get("extracted_urls", [])
                ips = results.get("extracted_ips", [])
                
                if urls:
                    st.markdown("**Extracted URLs / C2 Domains:**")
                    for u in urls:
                        st.code(u)
                if ips:
                    st.markdown("**Suspicious Remote IP Addresses:**")
                    for ip in ips:
                        st.code(ip)
                if not urls and not ips:
                    st.info("No external endpoints or IoCs found in byte code.")

            # Full Width Section: Explainable AI Insights
            st.divider()
            st.subheader("🧠 Explainable Threat Insights (AI/Heuristic)")
            for finding in results.get("explanations", []):
                st.markdown(finding)

            # Forensic Report Export Button
            st.divider()
            st.subheader("📥 Export Forensic Analysis")
            
            report_data = {
                "scan_summary": {
                    "app_name": results["app_name"],
                    "package_name": results["package_name"],
                    "target_sdk": results["target_sdk"],
                    "risk_score": results["risk_score"],
                    "threat_level": results["risk_level"]
                },
                "findings": {
                    "dangerous_permissions": results["dangerous_permissions"],
                    "extracted_urls": results.get("extracted_urls", []),
                    "extracted_ips": results.get("extracted_ips", []),
                    "threat_insights": results.get("explanations", [])
                }
            }
            
            json_report = json.dumps(report_data, indent=4)
            
            st.download_button(
                label="📄 Download Forensic JSON Report",
                data=json_report,
                file_name=f"{results['package_name']}_forensic_report.json",
                mime="application/json"
            )

        except Exception as e:
            st.error(f"Error analyzing APK: {e}")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)