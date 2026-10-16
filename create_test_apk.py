import zipfile
import os

# Ek standard dummy AndroidManifest.xml (with dangerous permissions)
dummy_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.truthguard.testapp"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />

    <!-- Dangerous permissions for testing scanner -->
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:label="TruthGuard Test Sample"
        android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

output_apk_path = "test_malicious.apk"

# Android APK asal mein ek Zip file hoti hai jisme AndroidManifest.xml hota hai
with zipfile.ZipFile(output_apk_path, 'w', zipfile.ZIP_DEFLATED) as apk_zip:
    apk_zip.writestr("AndroidManifest.xml", dummy_manifest)
    apk_zip.writestr("classes.dex", b"DUMMY_DEX_BYTES_FOR_FORENSIC_PARSING")

print(f"Success! Test APK generated at: {os.path.abspath(output_apk_path)}")