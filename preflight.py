"""Read-only checks for the access-key alert path. Standard library + AWS CLI.

python3 preflight.py --demo  # fictional configuration; no AWS requests
python3 preflight.py --live  # four read-only AWS CLI operations
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_PATTERN = {
    "source": ["aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {"eventSource": ["iam.amazonaws.com"], "eventName": ["CreateAccessKey"],
               "errorCode": [{"exists": False}]},
}
ALLOWED_READS = {
    ("sts", "get-caller-identity"): set(),
    ("events", "describe-rule"): {"name", "event_bus_name"},
    ("events", "list-targets-by-rule"): {"rule", "event_bus_name"},
    ("sns", "list-subscriptions-by-topic"): {"topic_arn"},
}
CHECK_NAMES = ["session", "rule_enabled", "saved_pattern", "expected_target", "confirmed_email"]


class ReadError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class AwsCLI:
    def __init__(self, region, profile=None):
        self.region, self.profile = region, profile

    def __call__(self, service, operation, **parameters):
        allowed = ALLOWED_READS.get((service, operation))
        if allowed is None or set(parameters) != allowed:
            raise ValueError("This checker only permits its four declared read operations.")
        command = ["aws", service, operation, "--region", self.region, "--output", "json",
                   "--no-cli-pager", "--cli-connect-timeout", "5", "--cli-read-timeout", "15"]
        if self.profile:
            command.extend(["--profile", self.profile])
        for name, value in parameters.items():
            command.extend(["--" + name.replace("_", "-"), str(value)])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=35,
                                    env={**os.environ, "AWS_PAGER": "", "AWS_MAX_ATTEMPTS": "1"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReadError("CLI_UNAVAILABLE_OR_TIMEOUT") from exc
        if result.returncode:
            # Do not copy raw CLI errors, ARNs, account IDs, or endpoints to a report.
            error = result.stderr.lower()
            if "resourcenotfound" in error or "notfoundexception" in error:
                code = "NOT_FOUND"
            elif "accessdenied" in error or "not authorized" in error:
                code = "ACCESS_DENIED"
            else:
                code = "SESSION_OR_REQUEST_ERROR"
            raise ReadError(code)
        try:
            response = json.loads(result.stdout)
        except ValueError as exc:
            raise ReadError("INVALID_RESPONSE") from exc
        if not isinstance(response, dict):
            raise ReadError("INVALID_RESPONSE")
        return response


def inspect(fetch, region="us-east-1", rule="security-lab-ac", topic="security-lab-alerts"):
    """Normalize only useful check results; never persist complete AWS responses."""
    checks = []

    def add(name, status, detail):
        checks.append({"check": name, "status": status, "detail": detail})

    def finish():
        present = {row["check"] for row in checks}
        for name in CHECK_NAMES:
            if name not in present:
                add(name, "UNKNOWN", "Not checked because a prerequisite was unavailable.")
        return {"region": region, "rule": rule, "topic_name": topic, "checks": checks,
                "delivery": "NOT_TESTED",
                "not_checked": ["Effective IAM/SNS publishing permissions", "Subscription filter policy",
                                "CloudTrail logging state", "Fresh event-to-email delivery"]}

    try:
        identity = fetch("sts", "get-caller-identity")
    except ReadError as exc:
        add("session", "ERROR", "Caller identity could not be read: " + exc.code)
        return finish()
    account, arn = identity.get("Account"), identity.get("Arn")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(arn, str):
        add("session", "ERROR", "Caller identity response was incomplete.")
        return finish()
    if arn.endswith(":root"):
        add("session", "FAIL", "Use the normal lab role or IAM Identity Center session.")
        return finish()
    add("session", "PASS", "A non-root AWS session is available; account identifier omitted.")

    try:
        saved = fetch("events", "describe-rule", name=rule, event_bus_name="default")
    except ReadError as exc:
        add("rule_enabled", "FAIL" if exc.code == "NOT_FOUND" else "ERROR",
            "Rule could not be read: " + exc.code)
        return finish()
    state = saved.get("State")
    if state == "ENABLED":
        add("rule_enabled", "PASS", "The deployed rule is enabled.")
    elif state == "DISABLED":
        add("rule_enabled", "FAIL", "The deployed rule is disabled.")
    else:
        add("rule_enabled", "UNKNOWN", "Rule state is missing or outside this initial checker's supported states.")
    try:
        pattern = json.loads(saved["EventPattern"])
    except (KeyError, TypeError, ValueError):
        add("saved_pattern", "UNKNOWN", "The saved event pattern could not be interpreted.")
    else:
        add("saved_pattern", "PASS" if pattern == EXPECTED_PATTERN else "FAIL",
            "Saved JSON equals the expected creation-only pattern." if pattern == EXPECTED_PATTERN
            else "Saved JSON differs from the expected pattern; review the difference before changing it.")

    try:
        response = fetch("events", "list-targets-by-rule", rule=rule, event_bus_name="default")
    except ReadError as exc:
        add("expected_target", "ERROR", "Targets could not be read: " + exc.code)
        return finish()
    targets = response.get("Targets")
    if not isinstance(targets, list) or not all(isinstance(t, dict) for t in targets):
        add("expected_target", "ERROR", "Target response was incomplete.")
        return finish()
    if len(targets) != 1:
        add("expected_target", "FAIL", f"This lab expects exactly one target; found {len(targets)}.")
        return finish()
    expected_arn = f"arn:aws:sns:{region}:{account}:{topic}"
    if targets[0].get("Arn") != expected_arn:
        add("expected_target", "FAIL", "Target differs from the expected SNS service/account/region/topic.")
        return finish()
    add("expected_target", "PASS", "One SNS target matches the active account, region, and expected topic name.")

    try:
        response = fetch("sns", "list-subscriptions-by-topic", topic_arn=expected_arn)
    except ReadError as exc:
        add("confirmed_email", "ERROR", "Subscriptions could not be read: " + exc.code)
        return finish()
    subscriptions = response.get("Subscriptions")
    if not isinstance(subscriptions, list) or not all(isinstance(s, dict) for s in subscriptions):
        add("confirmed_email", "ERROR", "Subscription response was incomplete.")
        return finish()
    confirmed = sum(s.get("Protocol") == "email" and isinstance(s.get("SubscriptionArn"), str)
                    and s["SubscriptionArn"].startswith(expected_arn + ":") for s in subscriptions)
    add("confirmed_email", "PASS" if confirmed else "FAIL",
        f"Found {confirmed} confirmed email subscription(s); endpoint addresses omitted.")
    return finish()


def demo_data():
    topic = "arn:aws:sns:us-east-1:000000000000:security-lab-alerts"
    return {
        ("sts", "get-caller-identity"): {"Account": "000000000000", "Arn": "arn:aws:sts::000000000000:assumed-role/DemoRole/session"},
        ("events", "describe-rule"): {"State": "ENABLED", "EventPattern": json.dumps(EXPECTED_PATTERN)},
        ("events", "list-targets-by-rule"): {"Targets": [{"Id": "demo", "Arn": topic}]},
        ("sns", "list-subscriptions-by-topic"): {"Subscriptions": [{"Protocol": "email", "SubscriptionArn": topic + ":fictional-subscription", "Endpoint": "fictional@example.invalid"}]},
    }


def write_report(report, directory):
    directory.mkdir(parents=True, exist_ok=True)
    stem = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + report["mode"]
    json_path, md_path = directory / (stem + ".json"), directory / (stem + ".md")
    with json_path.open("x") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    lines = ["# Access-key alert configuration check", "", "Mode: **" + report["mode"] + "**",
             "Observation: " + report["observed_at"], "", "| Check | Status | Detail |", "| --- | --- | --- |"]
    lines.extend(f"| {c['check']} | {c['status']} | {c['detail']} |" for c in report["checks"])
    lines.extend(["", "Delivery: **NOT TESTED**", "", "Not checked:"])
    lines.extend("- " + value for value in report["not_checked"])
    lines.extend(["", "Scope: active AWS account, default event bus, commercial AWS SNS, plain email subscriptions.",
                  "Pattern comparison is exact JSON equality, not complete semantic equivalence.",
                  "DEMO uses fictional data. PASS establishes only the named configuration check."])
    with md_path.open("x") as handle:
        handle.write("\n".join(lines) + "\n")
    return md_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--profile", help="Optional normal lab profile; CloudShell does not need this")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "reports/preflight")
    args = parser.parse_args()
    if args.demo and args.profile:
        parser.error("--profile applies only to --live")
    if args.demo:
        data = demo_data()
        fetch = lambda service, operation, **params: copy.deepcopy(data[(service, operation)])
    else:
        fetch = AwsCLI(args.region, args.profile)
    report = inspect(fetch, region=args.region)
    report.update(mode="DEMO" if args.demo else "LIVE", observed_at=datetime.now(timezone.utc).isoformat())
    output = write_report(report, args.output_dir)
    print("DEMO — fictional data, no AWS requests" if args.demo else "LIVE — read-only AWS configuration checks")
    for check in report["checks"]:
        print(f"{check['status']:7} {check['check']}: {check['detail']}")
    print("Delivery: NOT TESTED")
    print(f"Report: {output}")
    statuses = {c["status"] for c in report["checks"]}
    return 2 if statuses & {"ERROR", "UNKNOWN"} else 1 if "FAIL" in statuses else 0


if __name__ == "__main__":
    raise SystemExit(main())
