---
title: "Freelance Hourly Rate Calculator"
description: "Work out the hourly and daily rate you need as a freelancer from your target net income, billable days and hours, tax rate and expenses. Free and private."
intro: "**RateMate** turns the income you want to take home into the rate you need to charge. Enter your target net salary, billable days and hours, tax rate and monthly expenses, and get your hourly rate, daily rate and monthly gross target instantly."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["freelance rate calculator", "hourly rate calculator", "how much should i charge as a freelancer", "day rate calculator", "contractor rate calculator", "freelance pricing", "consultant rate calculator", "self employed hourly rate"]
tags: ["freelance", "finance", "business", "tool"]
app_category: "FinanceApplication"
tool_file: "/tools/freelance-calculator/"
tool_title: "RateMate freelance rate calculator"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Pick your currency ($, € or £) and enter the **Desired Annual Net Salary**: what you want to keep after tax and business costs."
  - "Set **Billable Days per Year**. 220 is the default; subtract holidays, sick days, admin and sales time honestly."
  - "Set **Daily Billable Hours**: the hours you can actually invoice, usually 5–7 rather than 8."
  - "Move the **Tax Rate** slider to your effective tax and social-contribution rate, and enter your **Monthly Expenses** (software, equipment, insurance, coworking, accountant)."
  - "Read **Your Hourly Rate**, the **Daily Rate** and the **Monthly Gross** you need to invoice. The doughnut chart shows how each invoiced euro or dollar splits into income, taxes and expenses."
faq:
  - q: "How do I calculate my freelance hourly rate?"
    a: "Start from the income you need, not from what others charge. Add your yearly business expenses, gross the total up for tax, then divide by the hours you can realistically bill. With the defaults (60,000 net, 500 a month in expenses, 25% tax, 220 days of 6 billable hours) that is (60,000 + 6,000) ÷ 0.75 = 88,000 a year, 400 a day, about 67 an hour."
  - q: "How many billable days per year should I assume?"
    a: "A year has about 260 working days. Remove public holidays (8–14 depending on the country), 20–25 days of vacation, a few sick days and the time spent on sales, admin and learning. Most freelancers end up between 180 and 220 billable days; new freelancers without a steady pipeline often bill fewer."
  - q: "Why are billable hours lower than working hours?"
    a: "Emails, invoicing, proposals, meetings that cannot be charged and context switching all take time. Six billable hours in an eight-hour day is a common, sustainable figure. If you bill eight hours every day, you are probably working ten."
  - q: "What tax rate should I enter?"
    a: "Enter your *effective* rate: total income tax plus social contributions divided by gross revenue, not your top marginal bracket. It varies widely by country and regime; for a first estimate use last year's figures or ask your accountant, then try a few values to see how sensitive your rate is."
  - q: "Does the calculator treat expenses as tax-deductible?"
    a: "No. It applies the tax rate to the whole gross amount, expenses included, which gives a slightly higher, safer rate. Where expenses are fully deductible, the required gross is net ÷ (1 − tax rate) + expenses instead: with the defaults that is 86,000 rather than 88,000, about 65 an hour instead of 67."
  - q: "Should I charge hourly or a daily or project rate?"
    a: "Use the hourly figure as your floor. Many freelancers quote a daily rate (shown here) or a fixed project price derived from it, which rewards efficiency instead of hours. Whatever you quote, check that it never works out below the hourly rate from this calculator."
  - q: "Is my financial data stored?"
    a: "No. The calculation runs in your browser and nothing is saved or sent. Close the page and the numbers are gone."
---

## How it works

RateMate works backwards from the money you want to keep.

1. **Annual expenses** = monthly expenses × 12.
2. **Required annual gross** = (net salary + annual expenses) ÷ (1 − tax rate).
   The tax rate is treated as a flat share of everything you invoice, so the formula grosses up both your salary and your costs.
3. **Annual taxes** = gross − net salary − expenses.
4. **Daily rate** = gross ÷ billable days.
5. **Hourly rate** = daily rate ÷ billable hours per day.
6. **Monthly gross** = gross ÷ 12, the amount you need to invoice on average each month.

The doughnut chart, drawn with Chart.js, shows the three shares of your gross: net income, taxes and expenses. Every field recalculates on input, so you can drag the tax slider (0–60%) and watch the rate move.

### Worked example

| Input | Value |
|---|---|
| Desired net salary | 60,000 |
| Monthly expenses | 500 (6,000 a year) |
| Tax rate | 25% |
| Billable days | 220 |
| Billable hours per day | 6 |

Gross = 66,000 ÷ 0.75 = **88,000** a year → **400** a day → **≈ 67** an hour → **≈ 7,333** invoiced per month. Of each 100 invoiced, about 68 is income, 25 is tax and 7 covers expenses.

Change just one assumption and see why rates differ so much. At 180 billable days the hourly rate rises to about 81; at 5 billable hours a day instead of 6, to 80. The biggest lever is usually not the tax rate but how much of your time you can actually bill.

### What the model leaves out

The calculator deliberately keeps to one effective tax rate. It does not model progressive tax brackets, VAT/sales tax (which you add on top of your rate and pass on), pension contributions beyond what you include in "net", or unpaid gaps between contracts. Add a margin for those, or raise the net figure, if they apply to you.

## Use cases

- **Going freelance.** Translate your current employee salary into the rate you need, and see quickly why freelancers must charge far more than salary ÷ 2,080 hours.
- **Preparing a quote.** Check that a project price, divided by the days it will take, stays above your daily rate.
- **Raising your rates.** Plug in this year's real expenses and tax rate and see whether your current rate still covers them.
- **Comparing offers.** Compare a contract's day rate with a permanent salary on equal terms.
- **Planning a sabbatical or training.** Reduce billable days and see how much your rate must rise to keep the same income.
