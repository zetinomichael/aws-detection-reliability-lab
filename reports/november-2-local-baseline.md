# Event-pattern contract results

Engine: **local**
Run time (UTC): 2026-11-02T22:52:28.871873+00:00

Expected outcomes satisfied: **16/16**.

These are synthetic fixtures. This report does not verify saved rules, target permissions, SNS delivery, or resource cleanup.

| Case | Expected match | Observed match | Contract |
| --- | --- | --- | --- |
| key-created | True | True | PASS |
| key-denied | False | False | PASS |
| key-deleted | False | False | PASS |
| key-wrong-service | False | False | PASS |
| admin-exact-target | True | True | PASS |
| admin-denied | False | False | PASS |
| admin-other-user | False | False | PASS |
| admin-lookalike-policy | False | False | PASS |
| admin-role-attachment | False | False | PASS |
| validation-off | True | True | PASS |
| validation-restored | True | True | PASS |
| trail-stop-request | True | True | PASS |
| trail-delete-request | True | True | PASS |
| trail-selectors-change | True | True | PASS |
| trail-change-denied | False | False | PASS |
| trail-read-status | False | False | PASS |

## Deliberately broken local pattern variants

A mutation is caught when at least one fixture no longer satisfies its expected result.

- CAUGHT: Misspelled access-key action — key-created
- CAUGHT: Missing failed-request exclusion — key-denied
- CAUGHT: Wrong monitored username — admin-exact-target
- CAUGHT: Accidentally widened username scope — admin-other-user
- CAUGHT: Missing UpdateTrail coverage — validation-off, validation-restored

## Evidence stages

- Historical pattern files: available; last saved configuration review was October 6, 2026.
- Local contract check: run here.
- AWS TestEventPattern: not run.
- Current deployed configuration: not checked by this command.
- End-to-end delivery: not checked by this command.

Local matching implements only the literal comparisons and exists conditions needed by the supplied patterns. It rejects unsupported features.
