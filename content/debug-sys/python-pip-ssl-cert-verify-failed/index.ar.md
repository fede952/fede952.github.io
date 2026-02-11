---
title: "إصلاح: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "أصلح خطأ pip SSL CERTIFICATE_VERIFY_FAILED الناتج عن بروكسيات الشركات أو الشهادات المفقودة أو تثبيتات Python القديمة. تتضمن حلولاً متعددة."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "إصلاح: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "كيفية إصلاح خطأ SSL CERTIFICATE_VERIFY_FAILED في pip على Windows وLinux وmacOS.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ar"
  }
---

## الخطأ

تقوم بتشغيل `pip install` وتحصل على أحد هذه الأخطاء:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

أو نسخة أقصر:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

يفشل تنزيل الحزمة لأن pip لا يستطيع التحقق من شهادة SSL الخاصة بـ PyPI (سجل حزم Python). يحدث هذا دائماً تقريباً بسبب بروكسي شركة يعترض حركة مرور HTTPS، أو شهادات نظام مفقودة، أو تثبيت Python/pip قديم.

---

## الإصلاح السريع

### الإصلاح 1: تجاوز التحقق من SSL (حل فوري مؤقت)

أخبر pip بالوثوق بمضيفي PyPI بدون التحقق من الشهادة:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

لجعل هذا دائماً، أضفه إلى إعدادات pip:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### الإصلاح 2: تحديث الشهادات (الإصلاح الصحيح)

الحل الحقيقي هو التأكد من أن نظامك يحتوي على شهادات CA محدّثة:

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

### الإصلاح 3: شهادة بروكسي الشركة

إذا كنت خلف بروكسي شركة يعترض HTTPS (هجوم الوسيط MITM)، تحتاج إلى إضافة شهادة CA الخاصة بشركتك إلى مخزن الثقة في Python:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

أو قم بتعيين متغير البيئة للإشارة إلى حزمة CA المخصصة:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## الشرح

عندما يتصل pip بـ `https://pypi.org`، يقوم بإجراء مصافحة TLS والتحقق من شهادة SSL الخاصة بالخادم مقابل حزمة من سلطات الشهادات الموثوقة (CAs). إذا لم يكن بالإمكان التحقق من سلسلة الشهادات — لأن حزمة CA مفقودة أو قديمة، أو لأن بروكسي يقوم بحقن شهادته الخاصة — يرفض pip الاتصال لحمايتك من هجمات الوسيط (man-in-the-middle).

### الأسباب الشائعة

| السبب | العَرَض | الإصلاح |
|-------|---------|---------|
| **بروكسي/جدار حماية الشركة** | فشل جميع تثبيتات pip عبر HTTPS | أضف شهادة CA الخاصة بالشركة إلى حزمة certifi |
| **Python قديم** | حزمة CA القديمة لا تستطيع التحقق من الشهادات الحديثة | قم بتحديث Python وcertifi |
| **تثبيت macOS جديد** | Python مثبت لكن الشهادات لم تتم تهيئتها | شغّل `Install Certificates.command` |
| **مضاد فيروسات Windows** | برنامج مضاد الفيروسات يعترض حركة مرور HTTPS | أضف شهادة CA الخاصة بمضاد الفيروسات أو أضف pip إلى القائمة البيضاء |
| **بيئة Conda** | Conda تأتي مع OpenSSL/شهادات خاصة بها | `conda install certifi` أو عيّن `SSL_CERT_FILE` |

### شرح علامة `--trusted-host`

استخدام `--trusted-host` يخبر pip بتخطي التحقق من الشهادة لذلك المضيف المحدد. هذا **لا** يعطل SSL بالكامل — يظل الاتصال مشفراً، لكن pip لا يتحقق من هوية الطرف الآخر. هذا مقبول لأجهزة التطوير، لكن لا ينبغي استخدامه في خطوط أنابيب CI/CD أو بيئات الإنتاج حيث تكون أمان سلسلة التوريد مهمة.

---

## موارد ذات صلة

قم بتأمين سكربتات Python الخاصة بك وأتمت مهام الأمان بشكل صحيح. اطلع على [ورقة مرجعية لسكربتات أمان Python](/cheatsheets/python-security-scripts/) — تغطي برمجة المقابس (sockets) وScapy وطلبات HTTP باستخدام مكتبة `requests`.
