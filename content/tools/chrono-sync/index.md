---
title: "Unix Timestamp Converter (Epoch to Date)"
description: "Convert Unix timestamps to dates and dates to epoch time, in UTC and local time. Seconds or milliseconds are detected automatically. Live epoch clock."
intro: "**ChronoSync** converts **Unix epoch timestamps** to readable dates and back. It shows the current timestamp ticking live, accepts seconds or milliseconds, and gives every result in both UTC and your local time zone."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["unix timestamp converter", "epoch converter", "timestamp to date", "date to timestamp", "epoch time now", "unix time", "milliseconds to date", "convert epoch"]
tags: ["developer-tools", "time", "converter", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/chrono-sync/"
tool_title: "ChronoSync Unix timestamp converter"
tool_height: 700
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Read the **current Unix timestamp** at the top: it updates every second, with the same instant in UTC below it."
  - "To turn a timestamp into a date, paste it into **Timestamp → Date** and press **Convert**. 10-digit values are read as seconds, 13-digit values as milliseconds."
  - "Read the result: first the date in UTC, then the same instant in your browser's local time zone."
  - "To get a timestamp, pick a date and time in **Date → Timestamp** (local time, to the second) and press **Convert**."
  - "Use the small copy button next to any result to put it on the clipboard."
faq:
  - q: "What is a Unix timestamp?"
    a: "The number of seconds elapsed since 00:00:00 UTC on 1 January 1970, the \"Unix epoch\", not counting leap seconds. It is the same everywhere on Earth at a given instant, which is why servers, databases and logs use it: 1700000000 is 14 November 2023 at 22:13:20 UTC whatever your time zone."
  - q: "Seconds or milliseconds?"
    a: "Unix tools, PHP, Python's `time.time()` (as an integer) and most databases use seconds, currently 10 digits. JavaScript's `Date.now()`, Java's `System.currentTimeMillis()` and many APIs use milliseconds, 13 digits. ChronoSync treats inputs of 13 or more digits as milliseconds and marks the result with (ms)."
  - q: "Why does my converted date look one or two hours off?"
    a: "Because a timestamp has no time zone; only its display does. Compare the UTC line, not the local one, with your server or log, which are usually in UTC. Daylight-saving changes explain differences that appear only part of the year."
  - q: "What is the year 2038 problem?"
    a: "Systems that store timestamps as signed 32-bit integers overflow at 2147483647, which is 03:14:07 UTC on 19 January 2038. After that the value wraps to a negative number and dates jump back to 1901. Modern systems use 64-bit values, but embedded devices and old file formats are still affected."
  - q: "Can it handle dates before 1970?"
    a: "Yes. Negative timestamps count seconds before the epoch: -86400 is 31 December 1969 at 00:00 UTC. Enter the minus sign and convert as usual."
  - q: "How do I get the current timestamp in code?"
    a: "Bash: `date +%s`. Python: `int(time.time())`. JavaScript: `Math.floor(Date.now() / 1000)`. PHP: `time()`. SQL (PostgreSQL): `extract(epoch from now())`. PowerShell: `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()`."
---

## How it works

Everything is plain JavaScript using the browser's built-in `Date` object, which stores time internally as milliseconds since the epoch.

**Live clock.** Once a second the page computes `Math.floor(Date.now() / 1000)` and shows it next to `toISOString()` of the same instant, formatted as `YYYY-MM-DD HH:MM:SS UTC`.

**Timestamp → date.** The input must be an integer, optionally negative. If it has 13 digits or more it is taken as milliseconds; otherwise it is multiplied by 1000. The resulting `Date` is printed twice:

1. in **UTC**, from `toISOString()`, the unambiguous form to compare with logs and servers;
2. in **local time**, from `toLocaleString()`, which uses your browser's time zone and date format.

**Date → timestamp.** The date picker is an `<input type="datetime-local">`, which has no time zone of its own; the browser interprets it in your local zone. `getTime() / 1000`, rounded down, gives the epoch seconds. The picker is pre-filled with the current local time.

| Timestamp | UTC date | Note |
|---|---|---|
| `0` | 1970-01-01 00:00:00 | The epoch |
| `1000000000` | 2001-09-09 01:46:40 | First 10-digit timestamp |
| `1700000000` | 2023-11-14 22:13:20 | |
| `2000000000` | 2033-05-18 03:33:20 | |
| `2147483647` | 2038-01-19 03:14:07 | Largest signed 32-bit value |
| `-86400` | 1969-12-31 00:00:00 | One day before the epoch |

Leap seconds are not part of Unix time, so a timestamp maps to exactly one UTC instant (apart from the rare leap-second itself) and two timestamps differ by exactly their number of seconds.

## Use cases

- **Reading logs and JWTs.** Turn `exp`, `iat` and log fields such as `1729771200` into a date you can reason about.
- **Debugging time zones.** See at a glance whether a stored value is UTC midnight or local midnight.
- **Writing queries.** Get the timestamp for "1 March 2026 00:00" to paste into a SQL `WHERE` clause or an API filter.
- **Converting between languages.** Check whether a value coming from JavaScript (ms) and one from Python (s) describe the same moment.
- **Cron and scheduling.** Verify when a job scheduled in epoch time will actually run.
