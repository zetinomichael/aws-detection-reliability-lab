# November 4 fresh access-key alert test

Michael ran the controlled CloudShell test against `security-lab-test-user` after the [zero-key baseline](02-fresh-test-baseline.md). The test terminal showed `RemainingKeys: 0`. Codex independently repeated the IAM count through CloudShell and observed zero keys.

| Field | Observed |
| --- | --- |
| SNS payload action | CreateAccessKey |
| SNS payload source | iam.amazonaws.com |
| SNS payload target | security-lab-test-user |
| SNS payload event ID | 6bc30a2c-6f00-4519-871d-547585169755 |
| Event time in SNS payload (UTC) | 2026-11-04T17:47:57Z |
| Top mail-server Received timestamp (UTC) | 2026-11-04T17:47:59Z |
| Difference between those timestamps | 2 seconds in this run |
| Final access-key count | 0 |

The original SNS message was read in Gmail. Only selected fields are preserved. The independent CloudTrail lookup was initially empty. After retrying, CloudTrail in us-east-1 returned the same creation event ID, action, and event time. Event History visibility came after the email in this run.

| CloudTrail action | Event time (UTC) | Event ID | Error code |
| --- | --- | --- | --- |
| CreateAccessKey | 2026-11-04T17:47:57Z | 6bc30a2c-6f00-4519-871d-547585169755 | null |
| DeleteAccessKey | 2026-11-04T17:47:58Z | fad9c30f-9c6f-4df2-8970-530f0448c119 | null |

CloudShell compared the key identifier returned by creation with the one targeted by deletion and returned `SameKey: True`. The identifiers were omitted from the output. The final IAM inventory independently returned zero keys. The two-second gap is a difference between recorded timestamps for this test only.

## Screenshots captured November 4

- [CloudTrail and IAM](04-cloudtrail-and-cleanup.png) shows both API records, the same-key comparison, and zero remaining keys.
- [Original SNS email, redacted](05-sns-email-redacted.png) preserves the sender, displayed time, and matching event ID. The rest of the payload is masked.
