---
title: "समाधान: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "कॉर्पोरेट प्रॉक्सी, गायब सर्टिफिकेट या पुराने Python इंस्टॉलेशन के कारण होने वाली pip SSL CERTIFICATE_VERIFY_FAILED त्रुटि को ठीक करें। कई समाधान शामिल हैं।"
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "समाधान: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "Windows, Linux और macOS पर pip की SSL CERTIFICATE_VERIFY_FAILED त्रुटि को कैसे ठीक करें।",
    "proficiencyLevel": "Beginner",
    "inLanguage": "hi"
  }
---

## त्रुटि

आप `pip install` चलाते हैं और इनमें से कोई एक त्रुटि प्राप्त होती है:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

या एक छोटा संस्करण:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

पैकेज डाउनलोड विफल हो जाता है क्योंकि pip PyPI (Python का पैकेज रजिस्ट्री) के SSL सर्टिफिकेट को सत्यापित नहीं कर पाता। यह लगभग हमेशा HTTPS ट्रैफिक को इंटरसेप्ट करने वाले कॉर्पोरेट प्रॉक्सी, गायब सिस्टम सर्टिफिकेट, या पुराने Python/pip इंस्टॉलेशन के कारण होता है।

---

## त्वरित समाधान

### समाधान 1: SSL सत्यापन को बायपास करें (तत्काल वर्कअराउंड)

pip को सर्टिफिकेट सत्यापन के बिना PyPI होस्ट पर भरोसा करने के लिए कहें:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

इसे स्थायी बनाने के लिए, अपनी pip कॉन्फिग में जोड़ें:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### समाधान 2: सर्टिफिकेट अपडेट करें (सही समाधान)

असली समाधान यह सुनिश्चित करना है कि आपके सिस्टम में अद्यतन CA सर्टिफिकेट हैं:

```bash
# Update pip itself first
python -m pip install --upgrade pip

# Install/update the certifi package (Python's certificate bundle)
pip install --upgrade certifi

# On macOS: Run the certificate installer
# (Navigate to Applications/Python X.X/ and run "Install Certificates.command")
# Or from terminal:
/Applications/Python\ 3.x/Install\ Certificates.command
```

### समाधान 3: कॉर्पोरेट प्रॉक्सी सर्टिफिकेट

यदि आप HTTPS को इंटरसेप्ट करने वाले कॉर्पोरेट प्रॉक्सी (MITM) के पीछे हैं, तो आपको अपनी कंपनी का CA सर्टिफिकेट Python के ट्रस्ट स्टोर में जोड़ना होगा:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

या कस्टम CA बंडल की ओर इंगित करने के लिए एनवायरनमेंट वेरिएबल सेट करें:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## विस्तृत व्याख्या

जब pip `https://pypi.org` से कनेक्ट होता है, तो यह TLS हैंडशेक करता है और विश्वसनीय सर्टिफिकेट अथॉरिटीज (CAs) के बंडल के विरुद्ध सर्वर के SSL सर्टिफिकेट को सत्यापित करता है। यदि सर्टिफिकेट चेन को मान्य नहीं किया जा सकता — क्योंकि CA बंडल गायब है, पुराना है, या प्रॉक्सी अपना सर्टिफिकेट इंजेक्ट कर रहा है — तो pip मैन-इन-द-मिडल हमलों से बचाने के लिए कनेक्शन को अस्वीकार कर देता है।

### सामान्य कारण

| कारण | लक्षण | समाधान |
|------|-------|--------|
| **कॉर्पोरेट प्रॉक्सी/फ़ायरवॉल** | सभी HTTPS pip इंस्टॉलेशन विफल होते हैं | कॉर्पोरेट CA सर्टिफिकेट को certifi बंडल में जोड़ें |
| **पुराना Python** | पुराना CA बंडल आधुनिक सर्टिफिकेट सत्यापित नहीं कर सकता | Python और certifi अपडेट करें |
| **macOS नया इंस्टॉलेशन** | Python इंस्टॉल है लेकिन सर्टिफिकेट इनिशियलाइज़ नहीं हुए | `Install Certificates.command` चलाएं |
| **Windows एंटीवायरस** | AV सॉफ्टवेयर HTTPS ट्रैफिक को इंटरसेप्ट करता है | AV CA सर्टिफिकेट जोड़ें या pip को व्हाइटलिस्ट करें |
| **Conda एनवायरनमेंट** | Conda अपना OpenSSL/सर्टिफिकेट साथ लाता है | `conda install certifi` या `SSL_CERT_FILE` सेट करें |

### `--trusted-host` फ्लैग की व्याख्या

`--trusted-host` का उपयोग pip को उस विशिष्ट होस्ट के लिए सर्टिफिकेट सत्यापन छोड़ने के लिए कहता है। यह SSL को पूरी तरह से अक्षम **नहीं** करता — कनेक्शन अभी भी एन्क्रिप्टेड रहता है, pip बस यह सत्यापित नहीं करता कि वह किससे बात कर रहा है। यह डेवलपमेंट मशीनों के लिए स्वीकार्य है, लेकिन CI/CD पाइपलाइनों या प्रोडक्शन एनवायरनमेंट में उपयोग नहीं किया जाना चाहिए जहां सप्लाई-चेन सुरक्षा महत्वपूर्ण है।

---

## संबंधित संसाधन

अपनी Python स्क्रिप्ट्स को सुरक्षित करें और सुरक्षा कार्यों को सही ढंग से स्वचालित करें। [Python सुरक्षा स्क्रिप्टिंग चीटशीट](/cheatsheets/python-security-scripts/) देखें — जिसमें सॉकेट प्रोग्रामिंग, Scapy, और `requests` लाइब्रेरी के साथ HTTP रिक्वेस्ट शामिल हैं।
