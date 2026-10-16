import os
import re
import zipfile
from androguard.core.apk import APK

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": 25,
    "android.permission.SEND_SMS": 25,
    "android.permission.RECEIVE_SMS": 20,
    "android.permission.RECORD_AUDIO": 15,
    "android.permission.CAMERA": 10,
    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.READ_CONTACTS": 15,
    "android.permission.READ_CALL_LOG": 20,
    "android.permission.SYSTEM_ALERT_WINDOW": 15,
    "android.permission.REQUEST_INSTALL_PACKAGES": 25,
}

URL_REGEX = r'https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:/[^\s"]*)?'
IP_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

def extract_iocs_from_apk(file_path):
    urls = set()
    ips = set()
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            for filename in z.namelist():
                if filename.endswith(".dex") or filename.startswith("assets/"):
                    content = z.read(filename).decode("latin-1", errors="ignore")
                    found_urls = re.findall(URL_REGEX, content)
                    found_ips = re.findall(IP_REGEX, content)
                    for u in found_urls:
                        if not u.endswith((".png", ".xml", ".schemas.android.com")):
                            urls.add(u)
                    for ip in found_ips:
                        if not ip.startswith(("0.", "127.", "255.")):
                            ips.add(ip)
    except Exception:
        pass
    return list(urls)[:10], list(ips)[:10]

def parse_plain_xml_manifest(file_path):
    permissions = []
    package_name = "Unknown"
    target_sdk = "Unknown"
    app_name = "Sample Application"
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            manifest_data = z.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
            pkg_match = re.search(r'package="([^"]+)"', manifest_data)
            if pkg_match:
                package_name = pkg_match.group(1)
            sdk_match = re.search(r'android:targetSdkVersion="([^"]+)"', manifest_data)
            if sdk_match:
                target_sdk = sdk_match.group(1)
            perm_matches = re.findall(r'<uses-permission\s+[^>]*android:name="([^"]+)"', manifest_data)
            permissions.extend(perm_matches)
    except Exception:
        pass
    return package_name, app_name, target_sdk, permissions

def generate_threat_explanations(permissions):
    insights = []
    perm_set = set(permissions)

    if "android.permission.READ_SMS" in perm_set or "android.permission.SEND_SMS" in perm_set:
        insights.append("🔴 **SMS Interception Risk:** App ke paas SMS access hai, jo sensitive banking OTP intercept karne ya unauthorised messages bhejne ke liye leverage ho sakti hai.")
    
    if "android.permission.RECORD_AUDIO" in perm_set:
        insights.append("🟠 **Audio Eavesdropping:** App ke paas microphone access hai, jisse background audio surveillance ka risk rehta hai.")
        
    if "android.permission.ACCESS_FINE_LOCATION" in perm_set:
        insights.append("🟡 **Precise Location Tracking:** High-precision GPS access enabled hai, jo user coordinate tracking ke liye sensitive hota hai.")

    if "android.permission.CAMERA" in perm_set:
        insights.append("🟠 **Visual Surveillance:** Camera hardware access request kiya gaya hai.")

    if not insights:
        insights.append("🟢 **Standard Profile:** Koi explicit high-risk behavior trigger nahi hua.")

    return insights

def analyze_apk(file_path):
    package_name = None
    app_name = None
    target_sdk = None
    permissions = []

    try:
        app = APK(file_path)
        package_name = app.get_package()
        app_name = app.get_app_name()
        target_sdk = app.get_target_sdk_version()
        permissions = app.get_permissions() or []
    except Exception:
        pass

    if not package_name or len(permissions) == 0:
        fb_pkg, fb_app, fb_sdk, fb_perms = parse_plain_xml_manifest(file_path)
        package_name = package_name or fb_pkg
        app_name = app_name or fb_app
        target_sdk = target_sdk or fb_sdk
        if not permissions:
            permissions = fb_perms

    detected_dangerous = []
    calculated_score = 0

    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            detected_dangerous.append(perm)
            calculated_score += DANGEROUS_PERMISSIONS[perm]

    extracted_urls, extracted_ips = extract_iocs_from_apk(file_path)
    if extracted_urls or extracted_ips:
        calculated_score += 15

    risk_score = min(calculated_score, 100)

    if risk_score >= 60:
        risk_level = "High Risk (Critical)"
    elif risk_score >= 30:
        risk_level = "Moderate Risk (Suspicious)"
    else:
        risk_level = "Low Risk (Likely Safe)"

    # AI/Heuristic explanation generation
    explanations = generate_threat_explanations(permissions)

    return {
        "app_name": app_name,
        "package_name": package_name,
        "target_sdk": target_sdk,
        "total_permissions": len(permissions),
        "dangerous_permissions": detected_dangerous,
        "extracted_urls": extracted_urls,
        "extracted_ips": extracted_ips,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanations": explanations
    }