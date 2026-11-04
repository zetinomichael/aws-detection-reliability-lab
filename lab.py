"""Milestone 1: event-pattern contracts, with an optional AWS reference engine.

No actions are emitted. No AWS resources are created or changed.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MISSING = object()


class UnsupportedPattern(ValueError):
    pass


def validate_pattern(pattern, path=""):
    if not isinstance(pattern, dict) or not pattern:
        raise UnsupportedPattern("Use a nonempty pattern object.")
    for key, expected in pattern.items():
        location = f"{path}.{key}".strip(".")
        if not isinstance(key, str) or "." in key or key.startswith("$"):
            raise UnsupportedPattern(f"Unsupported pattern field at {location}.")
        if isinstance(expected, dict):
            validate_pattern(expected, location)
        elif isinstance(expected, list) and expected:
            for option in expected:
                if isinstance(option, dict):
                    if set(option) != {"exists"} or not isinstance(option["exists"], bool):
                        raise UnsupportedPattern(f"Only the exists operator is supported locally: {location}.")
                elif not isinstance(option, (str, bool, int, float)) and option is not None:
                    raise UnsupportedPattern(f"Unsupported comparison at {location}.")
        else:
            raise UnsupportedPattern(f"Expected a nested object or nonempty alternatives list at {location}.")


def match_pattern(pattern, event):
    """Limited local contract checker; not a complete EventBridge implementation."""
    validate_pattern(pattern)
    if not isinstance(event, dict):
        raise ValueError("Event must be an object.")

    def walk(node, value, path=""):
        failures = []
        for key, expected in node.items():
            location = f"{path}.{key}".strip(".")
            actual = value.get(key, MISSING) if isinstance(value, dict) else MISSING
            if isinstance(expected, dict):
                if not isinstance(actual, dict):
                    failures.append(f"{location}: required nested object missing")
                else:
                    failures.extend(walk(expected, actual, location))
                continue
            if isinstance(actual, (dict, list)):
                raise UnsupportedPattern(f"Complex event values at compared fields are not supported locally: {location}.")
            matched = False
            for option in expected:
                if isinstance(option, dict):
                    matched |= (actual is not MISSING) == option["exists"]
                elif actual is not MISSING:
                    matched |= type(actual) is type(option) and actual == option
            if not matched:
                if any(isinstance(option, dict) for option in expected):
                    failures.append(f"{location}: field presence does not satisfy exists condition")
                elif actual is MISSING:
                    failures.append(f"{location}: required field missing")
                else:
                    failures.append(f"{location}: value is outside the allowed alternatives")
        return failures

    failures = walk(pattern, event)
    return not failures, failures


def aws_json(arguments, profile):
    # Argument arrays avoid shell interpolation; captured errors are not persisted.
    command = ["aws", *arguments, "--profile", profile, "--region", "us-east-1", "--output", "json", "--no-cli-pager", "--cli-connect-timeout", "5", "--cli-read-timeout", "15"]
    env = {**os.environ, "AWS_PAGER": "", "AWS_MAX_ATTEMPTS": "1"}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=25, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("AWS CLI could not complete the request. Check installation, sign-in, and connectivity.") from exc
    if result.returncode:
        raise RuntimeError("AWS rejected the request or the session is unavailable. Check your sign-in and events:TestEventPattern permission.")
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError("AWS CLI returned an unreadable response.") from exc


def check_aws_identity(profile):
    identity = aws_json(["sts", "get-caller-identity"], profile)
    if identity.get("Arn", "").endswith(":root"):
        raise RuntimeError("Use your normal lab role or IAM Identity Center session for these tests.")
    # Only fingerprints of patterns/fixtures are saved; no caller identity is saved.


def aws_match(pattern, event, profile):
    result = aws_json(["events", "test-event-pattern", "--event-pattern", json.dumps(pattern), "--event", json.dumps(event)], profile)
    if not isinstance(result.get("Result"), bool):
        raise RuntimeError("AWS response did not include a boolean Result.")
    return result["Result"], []


def load_inputs():
    patterns = {p.stem: json.loads(p.read_text()) for p in (ROOT / "patterns").glob("*.json")}
    cases = json.loads((ROOT / "fixtures/cases.json").read_text())
    return patterns, cases


def run_cases(patterns, cases, matcher):
    results = []
    for case in cases:
        actual, trace = matcher(patterns[case["rule"]], case["event"])
        results.append({"id": case["id"], "rule": case["rule"], "expected_match": case["expected_match"],
                        "actual_match": actual, "passed": actual == case["expected_match"],
                        "reason": case["reason"], "trace": trace})
    return results


def mutations(patterns):
    variants = []
    modified = copy.deepcopy(patterns); modified["access-key"]["detail"]["eventName"] = ["CreateAccessKeys"]
    variants.append(("Misspelled access-key action", modified))
    modified = copy.deepcopy(patterns); del modified["access-key"]["detail"]["errorCode"]
    variants.append(("Missing failed-request exclusion", modified))
    modified = copy.deepcopy(patterns); modified["admin-policy"]["detail"]["requestParameters"]["userName"] = ["wrong-user"]
    variants.append(("Wrong monitored username", modified))
    modified = copy.deepcopy(patterns); del modified["admin-policy"]["detail"]["requestParameters"]["userName"]
    variants.append(("Accidentally widened username scope", modified))
    modified = copy.deepcopy(patterns); modified["trail-change"]["detail"]["eventName"].remove("UpdateTrail")
    variants.append(("Missing UpdateTrail coverage", modified))
    return variants


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def save_report(report):
    path = ROOT / "reports"
    path.mkdir(exist_ok=True)
    name = report["engine"]
    (path / f"{name}-baseline.json").write_text(json.dumps(report, indent=2) + "\n")
    results = report["cases"]
    passed = sum(case["passed"] for case in results)
    lines = ["# Event-pattern contract results", "", f"Engine: **{name}**", f"Run time (UTC): {report['run_time']}",
             "", f"Expected outcomes satisfied: **{passed}/{len(results)}**.", "",
             "These are synthetic fixtures. This report does not verify saved rules, target permissions, SNS delivery, or resource cleanup.",
             "", "| Case | Expected match | Observed match | Contract |", "| --- | --- | --- | --- |"]
    for case in results:
        lines.append(f"| {case['id']} | {case['expected_match']} | {case['actual_match']} | {'PASS' if case['passed'] else 'FAIL'} |")
    if report.get("mutation_tests"):
        lines.extend(["", "## Deliberately broken local pattern variants", "", "A mutation is caught when at least one fixture no longer satisfies its expected result.", ""])
        for mutation in report["mutation_tests"]:
            lines.append(f"- {'CAUGHT' if mutation['caught'] else 'MISSED'}: {mutation['name']} — {', '.join(mutation['failing_cases'])}")
    lines.extend(["", "## Evidence stages", "", "- Historical pattern files: available; last saved configuration review was October 6, 2026.",
                  f"- Local contract check: {'run here' if name == 'local' else 'separate report'}.",
                  f"- AWS TestEventPattern: {'run here against supplied JSON' if name == 'aws' else 'not run'}.",
                  "- Current deployed configuration: not checked by this command.", "- End-to-end delivery: not checked by this command.",
                  "", "Local matching implements only the literal comparisons and exists conditions needed by the supplied patterns. It rejects unsupported features."])
    (path / f"{name}-baseline.md").write_text("\n".join(lines) + "\n")
    return path / f"{name}-baseline.md"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["local", "aws"], default="local")
    parser.add_argument("--profile", help="Your normal AWS lab profile; required for AWS reference testing")
    args = parser.parse_args()
    patterns, cases = load_inputs()
    if args.engine == "aws":
        if not args.profile:
            parser.error("--engine aws requires --profile; use your normal lab sign-in")
        check_aws_identity(args.profile)
        matcher = lambda pattern, event: aws_match(pattern, event, args.profile)
    else:
        matcher = match_pattern
    results = run_cases(patterns, cases, matcher)
    mutation_tests = []
    if args.engine == "local":
        for name, variant in mutations(patterns):
            failed = [case["id"] for case in run_cases(variant, cases, match_pattern) if not case["passed"]]
            mutation_tests.append({"name": name, "caught": bool(failed), "failing_cases": failed})
    report = {"run_time": datetime.now(timezone.utc).isoformat(), "engine": args.engine,
              "fixture_fingerprint": fingerprint(cases), "pattern_fingerprint": fingerprint(patterns),
              "cases": results, "mutation_tests": mutation_tests}
    output = save_report(report)
    print(f"Pattern contracts: {sum(case['passed'] for case in results)}/{len(results)} passed ({args.engine}).")
    if mutation_tests:
        print(f"Deliberately broken variants caught: {sum(test['caught'] for test in mutation_tests)}/{len(mutation_tests)}.")
    print("Delivery status: not tested by this command.")
    print(f"Report: {output}")
    return 0 if all(case["passed"] for case in results) and all(test["caught"] for test in mutation_tests) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc))
