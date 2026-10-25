---
title: "Cron Expression Generator & Explainer"
description: "Build cron schedules visually, translate any cron expression into plain English and see the next 5 run times. Free crontab generator for Linux and CI jobs."
intro: "**EasyCron** builds a cron expression by clicking, translates an existing one into plain English and lists its next five run times. It covers the standard five-field crontab syntax used by Linux cron, Kubernetes CronJobs and most CI schedulers."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["cron expression generator", "crontab generator", "cron job builder", "cron expression explained", "cron schedule examples", "every 5 minutes cron", "crontab guru alternative", "cron next run time"]
tags: ["linux", "devops", "cron", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/easy-cron/"
tool_title: "EasyCron cron expression generator"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Start from a **preset** (every 5 minutes, weekdays at 9 AM, monthly on the 1st…) or from the default `* * * * *`."
  - "Use the tabs **Minute, Hour, Day, Month, Weekday** to set each field: every value, an interval such as every 15 minutes, or specific values picked on a grid. Quick buttons cover common choices like business hours or weekdays."
  - "Watch the expression, its plain-English description and the **Next 5 runs** update as you click."
  - "Press **Copy** and paste the expression into your crontab, CronJob manifest or CI file."
  - "To understand an existing schedule, paste it into the **Reverse Translator** and press **Parse**: you get the description, the next runs, and the builder loads it for editing."
faq:
  - q: "What do the five fields of a cron expression mean?"
    a: "In order: minute (0–59), hour (0–23), day of the month (1–31), month (1–12) and day of the week (0–6, Sunday = 0). `30 2 * * 1` therefore means 02:30 every Monday. An asterisk means \"every value\" for that field."
  - q: "How do I run a cron job every 5 minutes?"
    a: "`*/5 * * * *`. The `*/5` in the minute field means every fifth minute starting at 0: 00, 05, 10 … 55. Similarly, `0 */2 * * *` runs at the top of every second hour and `*/15 9-17 * * 1-5` every 15 minutes during office hours on weekdays."
  - q: "What happens when both day-of-month and day-of-week are set?"
    a: "Standard (Vixie) cron runs the job when *either* matches, not when both match. `0 9 1 * 1` runs at 09:00 on the 1st of every month *and* on every Monday. EasyCron's next-run calculation follows the same rule, which surprises many people."
  - q: "Which time zone do the next run times use?"
    a: "The time zone of your browser. A cron daemon uses the time zone of the machine it runs on, often UTC on servers and in containers. Kubernetes CronJobs default to the controller's time zone unless you set `spec.timeZone`. If your server runs in UTC, convert before trusting the list."
  - q: "Does EasyCron support seconds, names like MON or JAN, or @daily?"
    a: "No. It targets the portable five-field syntax: numbers, `*`, ranges like `1-5`, lists like `1,15`, steps like `*/10` and stepped ranges like `0-30/10`. Quartz-style seconds and `L`, `W`, `#`, `?` are not supported. Write `0 0 * * *` instead of `@daily` and use `0` (not `7`) for Sunday."
  - q: "Is anything sent to a server?"
    a: "No. The builder, the description and the next-run calculation are plain JavaScript in this page. The only thing it stores is your light or dark theme preference, in your browser's localStorage."
---

## How it works

### Building the expression

Each of the five fields has its own state: **every** (`*`), **interval** (`*/n`, with sensible choices per field such as 5, 10, 15 or 30 minutes and 2, 3, 4, 6, 8 or 12 hours) or **specific** values picked on a grid. In specific mode the selected numbers are sorted and joined with commas (`0,15,30,45`). If every possible value is selected, the field collapses back to `*`. The five parts are joined with spaces into the final expression.

### Parsing and explaining

The reverse translator splits an expression on whitespace and requires exactly five fields. Each field is expanded into the set of values it matches:

| Syntax | Example | Expands to |
|---|---|---|
| `*` | `*` in hours | 0, 1, 2 … 23 |
| `*/n` | `*/15` in minutes | 0, 15, 30, 45 |
| `a-b` | `1-5` in weekdays | Mon … Fri |
| `a-b/n` | `0-30/10` in minutes | 0, 10, 20, 30 |
| list | `1,15` in days | 1st and 15th |

The description is assembled from rules that read like a person would say them: `*/5 * * * *` becomes "Every 5 minutes", `0 9 * * 1-5` becomes "At 09:00, Monday through Friday", `0 0 1 1 *` becomes "At 00:00, on day 1 of the month, in January".

### Calculating the next runs

Starting one minute from now, the calculator walks forward through time and skips whole units that cannot match: a month not in the month set jumps to the 1st of the next month, a non-matching day jumps to midnight of the next day, a non-matching hour to the next hour. When month, day, hour and minute all match, the time is recorded, until five runs are found or four years have been searched. That is why impossible schedules such as `0 0 31 2 *` (31 February) report that no upcoming run exists.

The day test follows cron's real semantics: if only one of the two day fields is restricted, that one decides; if both are restricted, either may match.

## Use cases

- **Writing a crontab entry** for backups, log rotation, certificate renewal or a cleanup script without looking up the field order again.
- **Kubernetes CronJobs and CI pipelines.** GitHub Actions `schedule:`, GitLab pipeline schedules and Kubernetes `spec.schedule` all use the same five fields.
- **Reviewing someone else's schedule.** Paste the cryptic `15 3 */2 * *` from a config and read "At 03:15, every 2nd day of the month".
- **Catching mistakes before they hit production**, such as a job meant for "weekdays at 9" that also runs on the 1st of the month because both day fields were set.
- **Planning maintenance windows.** Check exactly when the next five runs fall, then adjust for the server's time zone.
