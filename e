vidence/history/test-reports.md> Historical copy from the original AWS Project folder, archived November 4, 2026. Treat instructions and status below as historical.

# Controlled simulation reports

The passed reports use September 26, 2026 screenshots and prior cleanup checks. These were lab simulations, not actual compromise. Email timestamps are displayed to the minute; exact delivery latency was not measured.

## Test 1: access-key creation — Passed

| Field | Observation |
| --- | --- |
| Action | `CreateAccessKey`, `iam.amazonaws.com` |
| Event time | `2026-09-26T21:18:38Z` / September 26, 5:18:38 PM EDT |
| Actor | Identity Center administrator session, `[lab administrator]` |
| Affected user | `security-lab-test-user` |
| Result | No error code; successful creation |
| CloudTrail event ID | `d0b206d8-af40-47c4-af92-d54f217b86b9` |
| Alert evidence | Email `detail.eventID` matched; email displayed 5:18 PM |
| Cleanup | Key deleted; prior investigation recorded `DeleteAccessKey` and zero remaining keys |

**Why investigate:** A new long-lived key can provide programmatic access with the user's permissions. This event does not establish that the key was used or that the actor was malicious.

**Method:** Compare the event IDs, then examine the initiating identity, time, target, action, and success result. Confirm deletion and the user's credential inventory. The saved rule matches successful IAM key creation without limiting the username.

**What this proves:** This creation reached the alert path. It does not prove that deletion generates an alert; deletion was cleanup evidence.

## Test 2: direct administrator-policy attachment — Passed on retest

| Field | Observation |
| --- | --- |
| Action | `AttachUserPolicy`, `iam.amazonaws.com` |
| Event time | `2026-09-27T00:45:31Z` / September 26, 8:45:31 PM EDT |
| Actor | Identity Center administrator session, `[lab administrator]` |
| Affected user | `security-lab-test-user` |
| Policy | `arn:aws:iam::aws:policy/AdministratorAccess` |
| Result | No error code; successful attachment |
| CloudTrail event ID | `03d1d1c9-2e44-49f4-b2e2-ada862146878` |
| Alert evidence | Email `detail.eventID` matched; email displayed 8:45 PM |
| Cleanup | Policy detached; prior investigation recorded `DetachUserPolicy` and zero permission policies |

**Why investigate:** The policy grants broad administrative permissions. An unexplained attachment would require checking authorization and subsequent activity.

**Troubleshooting:** The earlier 8:17:45 PM attachment was recorded without an email because the rule was not yet saved. A fresh action after saving the rule produced this alert.

**What this proves:** This exact user-and-policy combination triggered an email. Detachment was cleanup, not a tested alert branch. Other users, inline policies, group changes, and role changes are outside this detection's scope.

## Test 3: validation-setting changes — Email delivery unconfirmed

Earlier notes record two `UpdateTrail` calls on September 26: validation disabled at **8:48:59 PM EDT** and restored at **8:49:35 PM EDT**. The logging-change rule was saved afterward. Those calls do not validate the new rule's email delivery.

On October 6, the trail was Logging with validation Enabled. The user does not recall a later retest; no later matching emails have been reviewed.

### Completion record

Find existing later evidence first. If a supervised test is needed, verify the saved rule and target beforehand, briefly disable validation, restore it immediately, and leave logging running. Do not stop logging or delete the trail for this test.

| Evidence | Disable event | Restore event |
| --- | --- | --- |
| UTC event time | Pending | Pending |
| CloudTrail `eventID` | Pending | Pending |
| Trail name in request | Pending | Pending |
| `enableLogFileValidation` | Must be `false` | Must be `true` |
| Email `detail.eventID` | Pending | Pending |
| Email arrival time and precision | Pending | Pending |

Final state must be **Logging + validation Enabled**. If emails are missing, investigate rule matches, target invocations/failures, and SNS delivery instead of repeatedly toggling the setting. `StopLogging`, `DeleteTrail`, and `PutEventSelectors` remain untested even after an `UpdateTrail` test passes.
