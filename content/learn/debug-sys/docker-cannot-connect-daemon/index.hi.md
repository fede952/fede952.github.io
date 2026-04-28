---
title: "समाधान: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "'Cannot connect to the Docker daemon' त्रुटि को सेकंडों में हल करें। जानें कि यह सर्विस की समस्या है या अनुमतियों की, और इसे स्थायी रूप से ठीक करें।"
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "समाधान: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Linux पर Docker daemon कनेक्शन त्रुटि का चरण-दर-चरण समाधान।",
    "proficiencyLevel": "Beginner",
    "inLanguage": "hi"
  }
---

## त्रुटि

आप एक Docker कमांड चलाते हैं और यह त्रुटि मिलती है:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

या इसका एक रूपांतर:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

यह Linux पर सबसे आम Docker त्रुटियों में से एक है। इसका मतलब है कि आपका शेल Docker इंजन से संवाद नहीं कर पा रहा है। इसका कारण हमेशा दो में से एक होता है: Docker सर्विस नहीं चल रही है, या आपके उपयोगकर्ता के पास Docker सॉकेट तक पहुँचने की अनुमति नहीं है।

---

## त्वरित समाधान

### 1. Docker सर्विस शुरू करें

हो सकता है कि डेमन बस चल नहीं रहा हो। इसे शुरू करें:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

यदि `status` में `active (running)` दिखाई दे, तो सर्विस चल रही है। अपना Docker कमांड फिर से आज़माएँ।

### 2. उपयोगकर्ता अनुमतियाँ ठीक करें

यदि सर्विस चल रही है लेकिन आपको अभी भी "permission denied" मिल रहा है, तो आपका उपयोगकर्ता `docker` ग्रुप में नहीं है:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

इसके बाद, आप `sudo` के बिना `docker ps` चला सकने में सक्षम होने चाहिए।

---

## विस्तृत व्याख्या

Docker एक Unix सॉकेट (`/var/run/docker.sock`) का उपयोग CLI क्लाइंट और Docker डेमन (बैकग्राउंड सर्विस) के बीच संवाद के लिए करता है। इसके काम करने के लिए दो शर्तें पूरी होनी चाहिए:

**1. Docker डेमन चल रहा होना चाहिए।** systemd सर्विस `docker.service` डेमन को प्रबंधित करती है। यदि मशीन अभी बूट हुई है और Docker स्टार्टअप पर सक्षम नहीं है, या यदि सर्विस क्रैश हो गई है, तो सॉकेट फ़ाइल या तो मौजूद नहीं है या कनेक्शन स्वीकार नहीं कर रही है।

**2. आपके उपयोगकर्ता के पास सॉकेट तक पहुँच होनी चाहिए।** डिफ़ॉल्ट रूप से, Docker सॉकेट का स्वामी `root:docker` है और अनुमतियाँ `srw-rw----` हैं। इसका मतलब है कि केवल root और `docker` ग्रुप के सदस्य ही इसे पढ़/लिख सकते हैं। यदि आपका उपयोगकर्ता `docker` ग्रुप में नहीं है, तो हर कमांड के लिए `sudo` की आवश्यकता होती है।

### कौन सी समस्या है?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

यदि `systemctl is-active` `inactive` लौटाता है → यह एक **सर्विस समस्या** है (समाधान #1)।
यदि सर्विस `active` है लेकिन आपको permission denied मिलता है → यह एक **अनुमति समस्या** है (समाधान #2)।

---

## सामान्य गलतियाँ

- **Snap से इंस्टॉल किया गया Docker**: यदि आपने आधिकारिक रिपॉजिटरी के बजाय Snap से Docker इंस्टॉल किया है, तो सॉकेट पथ और सर्विस नाम भिन्न हो सकते हैं। Snap संस्करण अनइंस्टॉल करें और आधिकारिक Docker CE पैकेज का उपयोग करें।
- **Windows पर WSL2**: Docker डेमन WSL2 में मूल रूप से नहीं चलता। आपको Docker Desktop for Windows चलाना होगा, या अपने WSL2 डिस्ट्रो के अंदर डेमन को मैन्युअल रूप से इंस्टॉल और शुरू करना होगा।
- **Mac/Linux पर Docker Desktop**: यदि आप Docker Desktop का उपयोग कर रहे हैं, तो डेमन Desktop ऐप द्वारा प्रबंधित होता है, systemd द्वारा नहीं। सुनिश्चित करें कि Docker Desktop खुला और चल रहा है।

---

## संबंधित संसाधन

इस त्रुटि को दोबारा होने से रोकें। हमारी पूरी [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) को बुकमार्क करें — यह उपयोगकर्ता अनुमतियाँ, सर्विस प्रबंधन और प्रोडक्शन में आवश्यक हर `docker` कमांड को कवर करती है।

Linux सर्विसेज़ और उपयोगकर्ताओं को प्रबंधित करने की आवश्यकता है? [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/) देखें।
