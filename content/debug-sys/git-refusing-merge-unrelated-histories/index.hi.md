---
title: "समाधान: fatal: refusing to merge unrelated histories"
description: "pull या merge करते समय Git की 'refusing to merge unrelated histories' त्रुटि को ठीक करें। समझें कि यह क्यों होता है और दो स्वतंत्र रिपॉजिटरी को सुरक्षित रूप से कैसे जोड़ें।"
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "समाधान: fatal: refusing to merge unrelated histories",
    "description": "स्वतंत्र रिपॉजिटरी को जोड़ते समय Git की refusing to merge unrelated histories त्रुटि को कैसे ठीक करें।",
    "proficiencyLevel": "Beginner",
    "inLanguage": "hi"
  }
---

## त्रुटि

आप रिमोट रिपॉजिटरी से pull करने या ब्रांच को मर्ज करने का प्रयास करते हैं और Git मना कर देता है:

```
fatal: refusing to merge unrelated histories
```

यह आमतौर पर तब होता है जब आप चलाते हैं:

```bash
git pull origin main
```

और लोकल और रिमोट रिपॉजिटरी में कोई सामान्य पूर्वज कमिट नहीं है — Git उन्हें दो पूरी तरह से अलग प्रोजेक्ट के रूप में देखता है और उन्हें स्वचालित रूप से जोड़ने से मना कर देता है।

---

## त्वरित समाधान

Git को दो स्वतंत्र इतिहासों को मर्ज करने के लिए बाध्य करने हेतु `--allow-unrelated-histories` फ्लैग जोड़ें:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

या यदि आप एक ब्रांच मर्ज कर रहे हैं:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git मर्ज का प्रयास करेगा। यदि फ़ाइल विवाद हैं, तो उन्हें सामान्य रूप से हल करें:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## यह क्यों होता है

यह त्रुटि तब होती है जब दो Git रिपॉजिटरी में कोई सामान्य कमिट इतिहास नहीं होता। सबसे सामान्य परिदृश्य:

### परिदृश्य 1: README विवाद वाला नया रिपो

आपने `git init` के साथ एक लोकल रिपॉजिटरी बनाई और कुछ कमिट किए। फिर आपने GitHub पर **README.md** (या `.gitignore` या `LICENSE`) **के साथ** एक रिपो बनाया। अब जब आप pull करने का प्रयास करते हैं, तो रिमोट में एक रूट कमिट है जिसके बारे में आपकी लोकल रिपो को कुछ नहीं पता।

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**रोकथाम:** जब मौजूदा लोकल प्रोजेक्ट को push करने के लिए नया GitHub रिपो बनाएं, तो रिमोट रिपो को इनिशियलाइज़ **किए बिना** बनाएं (कोई README नहीं, कोई .gitignore नहीं, कोई लाइसेंस नहीं)। फिर सीधे push करें।

### परिदृश्य 2: दो स्वतंत्र रिपॉजिटरी को मर्ज करना

आप दो अलग-अलग प्रोजेक्ट को एक रिपॉजिटरी में जोड़ना चाहते हैं। चूंकि वे स्वतंत्र रूप से बनाए गए थे, उनके कमिट ट्री पूरी तरह से अलग हैं।

### परिदृश्य 3: पुनर्लिखित इतिहास

किसी ने रिमोट पर `git rebase` या `git filter-branch` चलाया, जिसने रूट कमिट को फिर से लिखा। रिमोट का इतिहास अब आपकी लोकल कॉपी के साथ कोई पूर्वज साझा नहीं करता।

---

## क्या यह सुरक्षित है?

हाँ — `--allow-unrelated-histories` बस Git को बताता है कि दो ब्रांच में कोई सामान्य आधार न होने पर भी मर्ज जारी रखें। यह कुछ भी डिलीट, ओवरराइट या रीबेस नहीं करता। यदि विवादित फ़ाइलें हैं, तो Git उन्हें विवाद के रूप में चिह्नित करेगा और आपको सामान्य मर्ज की तरह ही मैन्युअल रूप से हल करने देगा।

यह फ्लैग **Git 2.9** (जून 2016) में जोड़ा गया था। उस संस्करण से पहले, Git डिफ़ॉल्ट रूप से असंबंधित मर्ज की अनुमति देता था।

---

## संबंधित संसाधन

हमारी [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) के साथ उन्नत मर्ज, रीबेस और विवाद समाधान में महारत हासिल करें — हर Git कमांड जो एक डेवलपर को चाहिए, वर्कफ़्लो के अनुसार व्यवस्थित।
