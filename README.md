
# Federico Sella - Personal Portfolio & Blog

![Build Status](https://github.com/fede952/fede952.github.io/actions/workflows/hugo.yaml/badge.svg)
![Hugo Version](https://img.shields.io/badge/Hugo-Extended-blue)
![License](https://img.shields.io/github/license/fede952/fede952.github.io)

This repository contains the source code for my personal website and portfolio, available at [www.federicosella.com](https://www.federicosella.com).

The site is built with **Hugo** (Static Site Generator) and deployed automatically via **GitHub Actions**.

## 🛠 Tech Stack

- **Framework:** [Hugo](https://gohugo.io/)
- **Hosting:** GitHub Pages
- **Deployment:** GitHub Actions (CI/CD)
- **Styling:** SCSS / CSS
- **Content:** Markdown

## 🚀 Getting Started

If you want to run this project locally to test changes or view the code structure:

### Prerequisites

You need to have **Git** and **Hugo** installed on your machine.
*Note: Make sure to install the "extended" version of Hugo if the theme requires SCSS processing.*

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/fede952/fede952.github.io.git
   cd fede952.github.io

2. **Initialize Submodules (if you use a theme as a submodule):**
```bash
git submodule update --init --recursive

```


3. **Run the local server:**
```bash
hugo server -D

```


The `-D` flag ensures that drafts are also rendered locally.
4. **View the site:**
Open your browser and navigate to `http://localhost:1313/`.

## 📂 Project Structure

* `content/`: Contains all the markdown files for pages and blog posts.
* `layouts/`: Custom HTML templates and overrides.
* `static/`: Images, CSS, JS, and other static assets.
* `.github/workflows/`: Configuration for the CI/CD pipeline.

## 🔄 Deployment

The deployment is fully automated. Every time a commit is pushed to the `main` branch, a GitHub Action workflow triggers:

1. It builds the static site using Hugo.
2. It deploys the generated files to the `gh-pages` branch (or directly to the environment depending on config).

## 📄 License

This project is open source and available under the [MIT License](https://www.google.com/search?q=LICENSE).