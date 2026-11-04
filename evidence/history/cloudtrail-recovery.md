# Recovered September CloudTrail records

Retrieved November 4, 2026 through the signed-in AWS CloudShell console in us-east-1. The two alert events were looked up by exact event ID and matched the [original SNS emails](sns-email-correlation.md). Cleanup was checked in CloudTrail using the disposable IAM user and the relevant time windows. The policy cleanup also matched the exact AdministratorAccess policy. The access-key cleanup below is a successful deletion on the same user; key identifiers were not compared in this extract.

| Event | UTC timestamp | CloudTrail event ID |
| --- | --- | --- |
| CreateAccessKey | 2026-09-26T21:18:38Z | d0b206d8-af40-47c4-af92-d54f217b86b9 |
| DeleteAccessKey | 2026-09-26T21:19:37Z | 8cf1d253-c37c-4c74-a73e-bc293361dbd2 |
| AttachUserPolicy | 2026-09-27T00:45:31Z | 03d1d1c9-2e44-49f4-b2e2-ada862146878 |
| DetachUserPolicy | 2026-09-27T00:45:35Z | b1ef20a7-b99e-438e-92d6-f7ece96b5ed0 |

These are redacted extracts retrieved from CloudTrail after the fact. The original screenshots remain outstanding.

[CloudShell screenshot of the recovered September records](cloudtrail-september-lookup.png), captured November 4.
