---
title: "Git डिजास्टर रिकवरी: गलतियाँ पलटना और हिस्ट्री ठीक करना"
description: "डेवलपर्स के लिए इमरजेंसी किट। सीखें कैसे कमिट पलटें, मर्ज कॉन्फ्लिक्ट सुलझाएं, डिलीट हुई ब्रांच रिकवर करें, और git rebase vs merge में महारत हासिल करें।"
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git डिजास्टर रिकवरी: गलतियाँ पलटना और हिस्ट्री ठीक करना",
    "description": "डेवलपर्स के लिए इमरजेंसी किट। सीखें कैसे कमिट पलटें, मर्ज कॉन्फ्लिक्ट सुलझाएं, डिलीट हुई ब्रांच रिकवर करें, और git rebase vs merge में महारत हासिल करें।",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "hi"
  }
---

## बदलाव पलटना

"मैंने गड़बड़ कर दी" के तीन स्तंभ: reset, revert, और restore। हर एक का दायरा और खतरे का स्तर अलग है।

### git restore — अनस्टेज्ड बदलाव हटाना

```bash
# एक फ़ाइल में बदलाव हटाएं (केवल वर्किंग डायरेक्टरी)
git restore file.txt

# सभी अनस्टेज्ड बदलाव हटाएं
git restore .

# फ़ाइल को अनस्टेज करें (वर्किंग डायरेक्टरी में बदलाव रखें)
git restore --staged file.txt

# फ़ाइल को किसी विशेष कमिट के वर्शन पर वापस लाएं
git restore --source=abc1234 file.txt
```

### git reset — HEAD को पीछे ले जाना

```bash
# Soft reset: कमिट पलटें, बदलाव स्टेज्ड रखें
git reset --soft HEAD~1

# Mixed reset (डिफ़ॉल्ट): कमिट पलटें, अनस्टेज करें, फ़ाइलें रखें
git reset HEAD~1

# Hard reset: कमिट पलटें, सभी बदलाव स्थायी रूप से हटाएं
git reset --hard HEAD~1

# किसी विशेष कमिट पर रीसेट करें
git reset --hard abc1234
```

> **--soft** सब कुछ स्टेज्ड रखता है। **--mixed** अनस्टेज करता है लेकिन फ़ाइलें रखता है। **--hard** सब कुछ नष्ट कर देता है। संदेह होने पर `--soft` इस्तेमाल करें।

### git revert — कमिट को सुरक्षित रूप से पलटना (पब्लिक हिस्ट्री)

```bash
# एक नया कमिट बनाएं जो किसी विशेष कमिट को पलटता है
git revert abc1234

# ऑटो-कमिट के बिना पलटें (केवल बदलाव स्टेज करें)
git revert --no-commit abc1234

# मर्ज कमिट को पलटें (पैरेंट #1 रखें)
git revert -m 1 <merge-commit-hash>
```

> शेयर्ड ब्रांच पर `reset` की जगह `revert` इस्तेमाल करें — यह हिस्ट्री को दोबारा नहीं लिखता।

---

## हिस्ट्री दोबारा लिखना

जब आपके कमिट मैसेज शर्मनाक हों या ब्रांच हिस्ट्री अस्त-व्यस्त हो।

### git commit --amend

```bash
# आखिरी कमिट मैसेज बदलें
git commit --amend -m "better message"

# भूली हुई फ़ाइलें आखिरी कमिट में जोड़ें
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (इंटरैक्टिव रीबेस)

```bash
# आखिरी 3 कमिट दोबारा लिखें
git rebase -i HEAD~3
```

एडिटर में आप यह कर सकते हैं:

| कमांड   | प्रभाव                            |
|----------|-----------------------------------|
| `pick`   | कमिट को जैसा है वैसा रखें         |
| `reword` | कमिट मैसेज बदलें                  |
| `edit`   | कमिट संशोधित करने के लिए रुकें     |
| `squash` | पिछले कमिट में मिलाएं              |
| `fixup`  | squash जैसा, लेकिन मैसेज हटाएं    |
| `drop`   | कमिट पूरी तरह हटाएं               |

```bash
# वर्तमान ब्रांच को main पर रीबेस करें (लीनियर हिस्ट्री)
git rebase main

# कॉन्फ्लिक्ट सुलझाने के बाद जारी रखें
git rebase --continue

# गलत हो रहे रीबेस को रद्द करें
git rebase --abort
```

> **Rebase vs Merge:** Rebase लीनियर हिस्ट्री बनाता है (साफ़ लॉग)। Merge ब्रांच टोपोलॉजी सुरक्षित रखता है (शेयर्ड ब्रांच के लिए सुरक्षित)। जो कमिट दूसरों ने पुल किए हैं, उन्हें कभी रीबेस न करें।

---

## रिकवरी

जब सब कुछ आग में हो, ये कमांड आपकी अग्निशामक हैं।

### git reflog — जीवनरक्षक

Reflog हर HEAD मूवमेंट को रिकॉर्ड करता है। Hard reset के बाद भी, आपके कमिट अभी वहीं हैं।

```bash
# Reflog देखें (सभी हालिया HEAD पोजीशन)
git reflog

# उदाहरण आउटपुट:
# abc1234 HEAD@{0}: reset: moving to HEAD~3
# def5678 HEAD@{1}: commit: add feature X
# 9ab0123 HEAD@{2}: commit: fix login bug

# Reflog एंट्री पर रीसेट करके रिकवर करें
git reset --hard HEAD@{1}

# या खोई हुई कमिट को cherry-pick करें
git cherry-pick def5678
```

### git fsck — डैंगलिंग ऑब्जेक्ट खोजना

```bash
# अनरीचेबल कमिट और ब्लॉब खोजें
git fsck --unreachable

# खोई हुई कमिट विशेष रूप से खोजें
git fsck --lost-found
# परिणाम .git/lost-found/ में सेव होते हैं
```

### डिलीट हुई ब्रांच रिकवर करना

```bash
# चरण 1: डिलीट हुई ब्रांच की आखिरी कमिट खोजें
git reflog | grep "branch-name"
# या कमिट मैसेज से खोजें
git reflog | grep "feature I was working on"

# चरण 2: उस कमिट पर ब्रांच फिर से बनाएं
git branch recovered-branch abc1234

# वैकल्पिक: एक ही शॉट में खोजें और रिस्टोर करें
git checkout -b recovered-branch HEAD@{5}
```

---

## आम आपदा परिदृश्य

### "मैंने गलत ब्रांच पर कमिट कर दिया"

```bash
# चरण 1: कमिट हैश नोट करें
git log --oneline -1
# abc1234 accidental commit

# चरण 2: गलत ब्रांच पर कमिट पलटें (बदलाव रखें)
git reset --soft HEAD~1

# चरण 3: Stash करें, स्विच करें, और अप्लाई करें
git stash
git checkout correct-branch
git stash pop
git add . && git commit -m "feature in the right place"
```

### "मुझे फ़ाइल को ट्रैक करना बंद करना है लेकिन लोकली रखना है"

```bash
# Git ट्रैकिंग से हटाएं लेकिन फ़ाइल डिस्क पर रखें
git rm --cached secret-config.env

# भविष्य में ट्रैकिंग रोकने के लिए .gitignore में जोड़ें
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "मुझे एक पुश पलटनी है"

```bash
# सुरक्षित तरीका: कमिट को revert करें (नई कमिट बनती है)
git revert abc1234
git push

# परमाणु विकल्प: फ़ोर्स पुश (शेयर्ड ब्रांच पर खतरनाक)
git reset --hard HEAD~1
git push --force-with-lease
```

### "मेरे मर्ज में हर जगह कॉन्फ्लिक्ट हैं"

```bash
# देखें किन फ़ाइलों में कॉन्फ्लिक्ट हैं
git status

# हर कॉन्फ्लिक्टेड फ़ाइल में कॉन्फ्लिक्ट मार्कर खोजें:
# <<<<<<< HEAD
# your changes
# =======
# their changes
# >>>>>>> branch-name

# सभी कॉन्फ्लिक्ट सुलझाने के बाद:
git add .
git commit

# या मर्ज पूरी तरह रद्द करें
git merge --abort
```

### git cherry-pick — विशेष कमिट लेना

```bash
# दूसरी ब्रांच से एक कमिट लागू करें
git cherry-pick abc1234

# कई कमिट लागू करें
git cherry-pick abc1234 def5678

# बिना कमिट किए cherry-pick करें (केवल स्टेज)
git cherry-pick --no-commit abc1234
```

---

## त्वरित संदर्भ तालिका

| स्थिति | कमांड |
|---------|--------|
| आखिरी कमिट पलटें (बदलाव रखें) | `git reset --soft HEAD~1` |
| आखिरी कमिट पलटें (बदलाव हटाएं) | `git reset --hard HEAD~1` |
| पुश हुई कमिट पलटें | `git revert <hash>` |
| फ़ाइल में बदलाव हटाएं | `git restore <file>` |
| फ़ाइल अनस्टेज करें | `git restore --staged <file>` |
| डिलीट हुई ब्रांच रिकवर करें | `git reflog` + `git branch name <hash>` |
| आखिरी कमिट मैसेज ठीक करें | `git commit --amend -m "new msg"` |
| आखिरी N कमिट स्क्वॉश करें | `git rebase -i HEAD~N` |
| कमिट सही ब्रांच पर ले जाएं | `git reset --soft HEAD~1` + stash + switch |
| फ़ाइल ट्रैक करना बंद करें | `git rm --cached <file>` |
