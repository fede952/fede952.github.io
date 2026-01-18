---
title: "Zendesk SOC Hunter"
date: 2026-01-18
draft: false
description: "The browser extension for SOC Analysts and Helpdesk support using Zendesk"
tags: ["Javascript", "WebExtension", "Automation", "ShadowDOM", "CrossBrowser", "JSON", "Zendesk", "IncidentResponse"]
categories: ["Projects", "Coding", "Cybersecurity Tools", "Browser Extensions", "Threat Intelligence", "Productivity"]
externalLink: "https://github.com/fede952/Zendesk-SOC-Hunter"
---

```markdown
# Hunter - Zendesk SOC Assistant

**Hunter** is a lightweight, high-performance browser extension designed to assist Security Operation Center (SOC) analysts and IT Support teams. It acts as a passive scanner that highlights critical context directly within your ticketing system interface.

## 🔗 Links
- [**GitHub Repository**](https://github.com/fede952/Zendesk-SOC-Hunter)
- [**Download for Chrome**](#) *(soon)*
- [**Download for Firefox**](#) *(soon)*

---

## 🎯 The Problem
Analysts handling hundreds of tickets often miss context. Is this ticket from a VIP client? Is the IP address mentioned in the description part of a known incident? Checking external lists manually for every ticket is time-consuming and prone to error.

## 💡 The Solution
Hunter sits quietly in your browser. When you open a ticket in **Zendesk** (or any web page), it scans the visible text against your local database of rules.

If it finds a match (Organization Name, IP Address, CIDR Range, or specific String), it displays a **non-intrusive alert overlay** in the bottom-right corner.

---

## ✨ Features Overview

### 1. The "Tower Stack" Interface
Unlike standard browser alerts that block your view, Hunter uses a smart "Tower Stack" system.
- Alerts appear in the bottom-right corner.
- Multiple detections stack upwards.
- **Shadow DOM Technology**: The alerts are isolated from the website's CSS. This means Zendesk updates won't break the extension's look, and the extension won't break Zendesk's layout.

### 2. Drag & Drop
Is an alert covering the "Submit" button? No problem.
- **Click & Drag**: Move any alert window anywhere on the screen.
- **Auto-Alignment**: The other alerts will automatically slide to fill the gap or follow the master alert.
- **Position Memory**: The extension remembers where you like your alerts.

### 3. Smart Detection
Hunter supports three types of indicators:
* **Organization Name**: Matches the client name on the page.
* **IP / CIDR**: Matches specific IPs (e.g., `192.168.1.5`) or checks if an IP belongs to a monitored subnet (e.g., `192.168.0.0/24`).
* **Strings**: Case-insensitive search for specific terms (e.g., `confidential`, `malware`).

### 4. Team Sharing
You don't need to configure every analyst's machine manually.
1.  Configure the rules on one machine.
2.  Click **Export Rules** (saves a `.json` file).
3.  Share the file with your team.
4.  They click **Import Rules** to sync instantly.

---

## 📖 User Guide

### Initial Setup
1.  Click the **Hunter icon** in your browser toolbar.
2.  If the interface is red, click the toggle to set it to **ACTIVE**.
3.  You will see a warning: *"No rules configured"*.

### Adding a Rule
1.  **Organization Name**: Enter the name (e.g., `Ferrari`).
2.  **Reason**: Why is this monitored? (e.g., `Project X in progress`).
3.  **Indicators**: Add comma-separated values (e.g., `10.0.0.1, server-log`).
4.  Click **Add Rule**.

### Managing Rules
- **Edit**: Click the pencil icon ✏️ next to a rule.
- **Delete**: Click the trash icon 🗑️ to remove a rule.
- **Delete All**: Use the red `All` button to wipe the configuration.

---

## ❓ FAQ

**Q: Does Hunter send data to the cloud?**
A: **No.** Hunter is 100% local. Your rules and the text scanning happen entirely within your browser (Client-side). No data is sent to external servers.

**Q: Why isn't the popup appearing?**
A: Ensure you have added at least one rule. If the yellow banner "No rules configured" is not visible, try refreshing the page.

**Q: Can I use it outside of Zendesk?**
A: Yes, Hunter scans the DOM of the active tab. While optimized for Zendesk, it works on any text-based website.

---

*Project developed by Federico Sella. Released under MIT License.*