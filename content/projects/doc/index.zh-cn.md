---
title: "Personal Portfolio & Blog"
description: "Development of a high-performance static site using Hugo and GitHub Actions."
date: 2025-12-25
tags: ["Hugo", "Go", "CI/CD", "Web Development", "Open Source"]
---

_注意：为了保持技术准确性，此内容显示为原始语言（英语）。_

---

### 🛠 Tech Stack

The project is built on **Hugo**, one of the fastest open-source frameworks for building websites, written in **Go**.

* **Core Framework:** [Hugo](https://gohugo.io/) (Static Site Generator).
* **Languages:** HTML5, CSS3, Markdown (for content).
* **Templating:** Go Templates (for layout logic and partials).
* **Content Management:** Projects and articles are written in **Markdown**, ensuring portability and easy version control.

### 🚀 Architecture and Deployment (CI/CD)

The site infrastructure is completely *serverless* and automated.

1. **Version Control:** Source code is hosted on **GitHub** in the public repository `fede952/fede952.github.io`.
2. **Hosting:** The site is served via **GitHub Pages**, ensuring very fast response times and high uptime.
3. **Custom Domain:** Custom DNS configuration via `CNAME` file pointing to `www.federicosella.com`.
4. **Automation (CI/CD):**
   I implemented a Continuous Deployment pipeline using **GitHub Actions** (located in the `.github/workflows` folder).
   * **Workflow:** On every *push* to the `main` branch, GitHub starts a container, installs Hugo, builds the static site from Markdown files, and automatically deploys the new version to production.

### 💡 Why Hugo?
The choice of Hugo over JavaScript-based solutions (like Next.js or React) for this specific use case was driven by the desire to achieve maximum **Core Web Vitals** scores. By avoiding heavy client-side JavaScript bundles, the site offers an instant browsing experience.

---
*The source code for this site is open source and available on [GitHub](https://github.com/fede952/fede952.github.io).*
