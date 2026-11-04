# September SNS email evidence

Recovered November 4, 2026 from the original Gmail messages. The table extracts fields from the SNS message payload, the message Date header, and the top Received header. The CloudTrail event IDs and times agree with the [historical test records](test-reports.md). Full messages remain in Gmail. This extract omits account and email addresses, header routing identifiers, source IPs, key identifiers, and subscription links.

| Action | Matching CloudTrail event ID | CloudTrail event time (UTC) | Message Date header (UTC) | Top Received header (UTC) | Event to Received header |
| --- | --- | --- | --- | --- | --- |
| `CreateAccessKey` | `d0b206d8-af40-47c4-af92-d54f217b86b9` | 2026-09-26 21:18:38 | 2026-09-26 21:18:40 | 2026-09-26 21:18:41 | 3 s |
| `AttachUserPolicy` | `03d1d1c9-2e44-49f4-b2e2-ada862146878` | 2026-09-27 00:45:31 | 2026-09-27 00:45:33 | 2026-09-27 00:45:34 | 3 s |

Both payloads identified `iam.amazonaws.com` and the lab SNS topic. The top Received header gives an observed mail-server timestamp at one-second precision. The three-second differences describe these two runs and do not measure when the user opened the inbox or establish typical latency.

A targeted search for the lab topic and logging-change action names returned no later matching message in the connected inbox that held these two alerts. Logging-change delivery remains unconfirmed. The original CloudTrail and cleanup screenshots are still outstanding.
