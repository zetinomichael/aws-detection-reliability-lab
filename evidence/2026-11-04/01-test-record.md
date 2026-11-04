# AWS-PREFLIGHT-001 — first live preflight

Michael ran `python3 ~/preflight.py --live` in AWS CloudShell and supplied the [terminal transcript](01-cloudshell-preflight.txt). The report filename records 2026-11-04 17:40:29 UTC (12:40:29 PM EST). The generated Markdown and JSON files remain in CloudShell and were not independently retrieved for this archive.

All five checks passed for the access-key rule: non-root session, enabled rule, exact saved pattern, expected SNS target in the active account and region, and one confirmed email subscription. This was a read-only configuration check. Fresh alert delivery, publish permissions, and subscription filters were outside this run.
