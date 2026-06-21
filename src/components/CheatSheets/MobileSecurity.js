import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaMobile, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { toast } from 'react-toastify';

const MobileSecurity = () => {
  const [expandedSection, setExpandedSection] = useState(null);
  const { addToHistory } = useCommandHistory();

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const handleCopy = (command) => {
    copyToClipboard(command);
    addToHistory(command);
    toast.success('Copied to clipboard!');
  };

  const sections = [
    {
      id: 'walkthrough',
      title: '📱 Mobile Pentest Walkthrough (Android Focus)',
      content: [
        {
          type: 'markdown',
          value: `Mobile app security testing covers both the **app itself** (code, storage, authentication) and the **network traffic** it generates. This walkthrough covers Android — for iOS substitute APKTool/jadx with class-dump/Frida on a jailbroken device.`
        },
        {
          type: 'step',
          title: '1. Obtain & Decompile the APK',
          description: 'Get the APK file and decompile it to inspect the source code and resources.',
          commands: [
            { value: 'adb devices', description: 'List connected Android devices' },
            { value: 'adb shell pm list packages | grep target', description: 'Find the target app package name' },
            { value: 'adb shell pm path com.target.app', description: 'Get APK file path on device' },
            { value: 'adb pull /data/app/com.target.app/base.apk .', description: 'Pull APK from device' },
            { value: 'apktool d base.apk -o output/', description: 'Decompile APK (smali code + resources)' },
            { value: 'jadx -d jadx_output/ base.apk', description: 'Decompile to readable Java code (better for code review)' },
          ]
        },
        {
          type: 'step',
          title: '2. Static Analysis — Find Secrets & Misconfigurations',
          description: 'Search decompiled code for hardcoded secrets, API keys, and insecure configurations.',
          commands: [
            { value: 'grep -r "api_key\\|apikey\\|secret\\|password\\|token" jadx_output/ --include="*.java"', description: 'Find hardcoded credentials' },
            { value: 'grep -r "http://" jadx_output/ --include="*.java"', description: 'Find hardcoded HTTP (cleartext) URLs' },
            { value: 'grep -r "allowBackup\\|debuggable\\|usesCleartextTraffic" output/AndroidManifest.xml', description: 'Check for dangerous manifest settings' },
            { value: 'cat output/AndroidManifest.xml | grep -i "exported\\|permission"', description: 'Find exported components (attack surface)' },
          ]
        },
        {
          type: 'step',
          title: '3. Set Up Traffic Interception (Burp Suite)',
          description: 'Intercept and manipulate API traffic from the app.',
          commands: [
            { value: 'adb shell settings put global http_proxy 192.168.1.100:8080', description: 'Set proxy on Android device (manual)' },
            { value: 'adb push burp_ca.der /sdcard/', description: 'Push Burp CA cert to device' },
            { value: 'adb shell "su -c \'cp /sdcard/burp_ca.der /system/etc/security/cacerts/\'"', description: 'Install CA cert (requires root)' },
          ]
        },
        {
          type: 'step',
          title: '4. Bypass Certificate Pinning with Frida',
          description: 'If the app validates server certificates, use Frida to bypass the check at runtime.',
          commands: [
            { value: 'frida-ps -U', description: 'List running processes on connected device' },
            { value: 'frida -U -f com.target.app -l ssl_bypass.js', description: 'Inject Frida script at app startup' },
            { value: 'objection -g com.target.app explore', description: 'Use objection for interactive bypasses' },
            { value: 'objection -g com.target.app explore --startup-command "android sslpinning disable"', description: 'Auto-disable SSL pinning on launch' },
          ]
        },
        {
          type: 'step',
          title: '5. Check Insecure Local Storage',
          description: 'Look for sensitive data stored insecurely on the device.',
          commands: [
            { value: 'adb shell "run-as com.target.app ls /data/data/com.target.app/"', description: 'List app data directory' },
            { value: 'adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml"', description: 'Read SharedPreferences (often stores tokens)' },
            { value: 'adb pull /data/data/com.target.app/ ./app_data/', description: 'Pull entire app data directory (root required)' },
            { value: 'sqlite3 app_data/databases/main.db ".tables"', description: 'Inspect SQLite databases for sensitive data' },
          ]
        }
      ]
    },
    {
      id: 'android-static',
      title: '🤖 Android Static Analysis',
      content: [
        {
          type: 'markdown',
          value: `### AndroidManifest.xml — Key Checks
\`\`\`xml
<!-- Dangerous Settings to Look For -->

<!-- 1. Backup allowed (extracts all app data via ADB) -->
<application android:allowBackup="true" ...>

<!-- 2. Debuggable (attach debuggers to release builds) -->
<application android:debuggable="true" ...>

<!-- 3. Cleartext HTTP traffic allowed -->
<application android:usesCleartextTraffic="true" ...>

<!-- 4. Exported components (external access without permission) -->
<activity android:name=".AdminActivity" android:exported="true">
<provider android:name=".DataProvider" android:exported="true" android:readPermission="">

<!-- 5. Custom permissions that are too permissive -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Automated Static Analysis
\`\`\`bash
# MobSF (Mobile Security Framework) — best all-in-one tool
# Docker setup:
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Access at http://localhost:8000 and upload APK

# QARK — quick android review kit
pip install qark
qark --apk base.apk --report-type html

# apkleaks — scan APK for leaked credentials/URLs
pip install apkleaks
apkleaks -f base.apk -o report.json

# androbugs framework
python androbugs.py -f base.apk
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Manual Code Review Checklist
\`\`\`
High Priority Findings:
☐ Hardcoded secrets (API keys, passwords, tokens)
☐ HTTP cleartext traffic (http:// vs https://)
☐ Disabled SSL/TLS verification
  - TrustManager that accepts all certs
  - HostnameVerifier that returns true always
☐ Insecure SharedPreferences storage
☐ Insecure SQLite storage (unencrypted)
☐ World-readable files
☐ Log statements exposing sensitive data (Log.d)
☐ Exported activities/providers without permission
☐ Implicit intents for sensitive actions
☐ WebView JavaScript enabled + loadUrl from intent
☐ Backup enabled (android:allowBackup="true")

Frida/Dynamic Check Points:
☐ SSL pinning bypass possible?
☐ Root detection bypass possible?
☐ Anti-emulator checks present?
\`\`\``
        }
      ]
    },
    {
      id: 'frida',
      title: '💉 Frida — Dynamic Instrumentation',
      content: [
        {
          type: 'markdown',
          value: `### Frida Setup
\`\`\`bash
# Install on host
pip install frida-tools

# Push frida-server to Android device (root required)
# Download from: https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify connection
frida-ps -U  # List running processes on USB device
frida-ps -U -a  # List all (including background) apps
\`\`\``
        },
        {
          type: 'markdown',
          value: `### SSL Pinning Bypass Scripts
\`\`\`javascript
// Universal SSL pinning bypass (most common)
// Save as ssl_bypass.js and run with: frida -U -f com.target.app -l ssl_bypass.js

Java.perform(function() {
    // Bypass OkHttp3 certificate pinning
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[+] OkHttp3 SSL Pinning bypassed!');
        };
    } catch(e) {}

    // Bypass TrustManager
    try {
        var TrustManager = [{
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }];
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManagerImpl = Java.array('javax.net.ssl.TrustManager', TrustManager);
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').call(this, km, TrustManagerImpl, sr);
        };
        console.log('[+] TrustManager bypassed!');
    } catch(e) {}
});
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Frida — Hook & Inspect Functions
\`\`\`javascript
// Hook a specific function and log arguments/return value
Java.perform(function() {
    var MainActivity = Java.use('com.target.app.MainActivity');
    
    // Hook method and print args
    MainActivity.validateCredentials.implementation = function(username, password) {
        console.log('[*] validateCredentials called!');
        console.log('[*] Username: ' + username);
        console.log('[*] Password: ' + password);
        
        // Call original function
        var result = this.validateCredentials(username, password);
        console.log('[*] Return value: ' + result);
        return result;  // Or: return true; to bypass!
    };
});

// Hook native function
Interceptor.attach(Module.findExportByName('libnative.so', 'check_root'), {
    onEnter: function(args) {
        console.log('[*] check_root called');
    },
    onLeave: function(retval) {
        console.log('[*] Return value: ' + retval);
        retval.replace(0);  // Replace return value with 0 (not rooted)
    }
});
\`\`\``
        }
      ]
    },
    {
      id: 'ios',
      title: '🍎 iOS Security Testing',
      content: [
        {
          type: 'markdown',
          value: `### iOS Setup (Requires Jailbroken Device)
\`\`\`bash
# Install required packages (via Cydia/Sileo on jailbroken device)
# - OpenSSH
# - Frida (via Frida repo)
# - Liberty Lite or SSL Kill Switch 2 (for pinning bypass)

# SSH into device
ssh root@<device-ip>
# Default password: alpine (CHANGE THIS!)

# Find installed apps
find /var/containers/Bundle/Application/ -name "Info.plist" -maxdepth 3

# Copy IPA from device
scp root@<device-ip>:/var/containers/Bundle/Application/<UUID>/App.app ./
\`\`\``
        },
        {
          type: 'markdown',
          value: `### iOS Static Analysis
\`\`\`bash
# Extract IPA
unzip App.ipa -d ipa_contents

# Detect encryption (Mach-O binary analysis)
otool -l ipa_contents/Payload/App.app/App | grep -A 4 LC_ENCRYPTION_INFO

# Class dumping (reveals all Obj-C classes and methods)
class-dump App.app/App -H -o headers/

# Search for hardcoded secrets
grep -r "password\|secret\|api_key\|token" headers/ --include="*.h"
strings App.app/App | grep -i "api\|key\|pass\|secret\|http://"

# Check for insecure HTTP
otool -L App.app/App | grep -i ssl  # Check linked SSL libraries
\`\`\``
        },
        {
          type: 'markdown',
          value: `### iOS Dynamic Analysis with objection
\`\`\`bash
# Install objection
pip3 install objection

# Attach to running iOS app
objection -g "AppName" explore

# Inside objection shell:
ios sslpinning disable              # Disable SSL pinning
ios keychain dump                   # Dump keychain entries
ios nsuserdefaults get              # Dump NSUserDefaults storage
ios pasteboard monitor              # Monitor clipboard
ios plist cat Info.plist            # Read plist files
ios cookies get                     # Get HTTP cookies
ios ui screenshot                   # Take screenshot
memory dump all dump.bin            # Dump process memory
\`\`\``
        }
      ]
    },
    {
      id: 'storage',
      title: '💾 Insecure Storage Testing',
      content: [
        {
          type: 'markdown',
          value: `### Android Storage Locations
\`\`\`bash
# App internal storage (private by default)
/data/data/com.target.app/
├── shared_prefs/   ← Often contains tokens, settings
├── databases/      ← SQLite databases
├── cache/          ← Cached data (may contain sensitive info)
├── files/          ← General file storage
└── lib/            ← Native libraries

# External storage (public — any app can read!)
/sdcard/Android/data/com.target.app/

# Check SharedPreferences for sensitive data
adb shell "run-as com.target.app find /data/data/com.target.app/shared_prefs -name '*.xml'"
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/prefs.xml"

# Check SQLite databases
adb shell "run-as com.target.app ls /data/data/com.target.app/databases/"
adb shell "run-as com.target.app sqlite3 /data/data/com.target.app/databases/app.db '.tables'"
adb shell "run-as com.target.app sqlite3 /data/data/com.target.app/databases/app.db 'SELECT * FROM users;'"
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaMobile /> Mobile Security Cheat Sheet
      </h2>

      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Mobile app security testing for Android and iOS — covers APK decompilation, static analysis
          with MobSF, dynamic analysis with Frida/objection, SSL pinning bypass, insecure storage 
          testing, and certificate interception. Suitable for beginners through advanced testers.
        </p>
      </div>

      <div className="sections-container">
        {sections.map((section) => (
          <div key={section.id} className="section">
            <motion.div
              className="section-header"
              onClick={() => toggleSection(section.id)}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <h3>{section.title}</h3>
              <motion.div animate={{ rotate: expandedSection === section.id ? 180 : 0 }}>
                <FaChevronDown />
              </motion.div>
            </motion.div>

            <motion.div
              className="section-content"
              initial={{ opacity: 0, height: 0 }}
              animate={{
                opacity: expandedSection === section.id ? 1 : 0,
                height: expandedSection === section.id ? 'auto' : 0
              }}
              transition={{ duration: 0.3 }}
            >
              {expandedSection === section.id && (
                <div className="content-inner">
                  {section.content.map((item, index) => {
                    if (item.type === 'step') {
                      return (
                        <div key={index} className="content-item walkthrough-step">
                          <div className="step-header"><strong>{item.title}</strong></div>
                          <div className="step-description">{item.description}</div>
                          <div className="step-commands">
                            {item.commands.map((cmd, i) => (
                              <div key={i} className="command-item">
                                <div className="command-header">
                                  <code>{cmd.value}</code>
                                  <button onClick={() => handleCopy(cmd.value)} className="copy-button small">Copy</button>
                                </div>
                                <p className="command-description">{cmd.description}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    } else {
                      return (
                        <div key={index} className="content-item">
                          <div className="markdown-content">
                            <ReactMarkdown>{item.value}</ReactMarkdown>
                          </div>
                        </div>
                      );
                    }
                  })}
                </div>
              )}
            </motion.div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default MobileSecurity;
