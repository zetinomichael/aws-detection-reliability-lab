import copy
import json
import tempfile
import unittest
from pathlib import Path

from preflight import ALLOWED_READS, EXPECTED_PATTERN, AwsCLI, ReadError, demo_data, inspect, write_report


class PreflightTests(unittest.TestCase):
    def run_config(self, data, failure=None):
        calls = []

        def fetch(service, operation, **parameters):
            key = service, operation
            calls.append(key)
            if key == failure:
                raise ReadError("ACCESS_DENIED")
            return copy.deepcopy(data[key])

        return inspect(fetch), calls

    @staticmethod
    def status(report, name):
        return next(c["status"] for c in report["checks"] if c["check"] == name)

    def test_expected_config_passes_without_claiming_delivery(self):
        report, calls = self.run_config(demo_data())
        self.assertTrue(all(c["status"] == "PASS" for c in report["checks"]))
        self.assertEqual(report["delivery"], "NOT_TESTED")
        self.assertEqual(set(calls), set(ALLOWED_READS))

    def test_disabled_rule_remains_a_failure(self):
        data = demo_data(); data[("events", "describe-rule")]["State"] = "DISABLED"
        report, _ = self.run_config(data)
        self.assertEqual(self.status(report, "rule_enabled"), "FAIL")

    def test_unknown_state_is_not_called_disabled(self):
        data = demo_data(); data[("events", "describe-rule")]["State"] = "A_FUTURE_STATE"
        report, _ = self.run_config(data)
        self.assertEqual(self.status(report, "rule_enabled"), "UNKNOWN")

    def test_missing_or_multiple_targets_block_downstream_inference(self):
        for count in [0, 2]:
            data = demo_data(); target = data[("events", "list-targets-by-rule")]["Targets"][0]
            data[("events", "list-targets-by-rule")]["Targets"] = [target] * count
            report, calls = self.run_config(data)
            self.assertEqual(self.status(report, "expected_target"), "FAIL")
            self.assertEqual(self.status(report, "confirmed_email"), "UNKNOWN")
            self.assertNotIn(("sns", "list-subscriptions-by-topic"), calls)

    def test_same_name_in_another_account_or_region_does_not_pass(self):
        for arn in ["arn:aws:sns:us-east-1:111111111111:security-lab-alerts", "arn:aws:sns:us-west-2:000000000000:security-lab-alerts"]:
            data = demo_data(); data[("events", "list-targets-by-rule")]["Targets"][0]["Arn"] = arn
            report, calls = self.run_config(data)
            self.assertEqual(self.status(report, "expected_target"), "FAIL")
            self.assertNotIn(("sns", "list-subscriptions-by-topic"), calls)

    def test_pending_subscription_does_not_count_as_confirmed(self):
        data = demo_data(); data[("sns", "list-subscriptions-by-topic")]["Subscriptions"][0]["SubscriptionArn"] = "PendingConfirmation"
        report, _ = self.run_config(data)
        self.assertEqual(self.status(report, "confirmed_email"), "FAIL")

    def test_access_denied_is_error_not_missing_target(self):
        report, _ = self.run_config(demo_data(), failure=("events", "list-targets-by-rule"))
        self.assertEqual(self.status(report, "expected_target"), "ERROR")
        self.assertEqual(self.status(report, "confirmed_email"), "UNKNOWN")

    def test_root_session_stops_before_reading_resources(self):
        data = demo_data(); data[("sts", "get-caller-identity")]["Arn"] = "arn:aws:iam::000000000000:root"
        report, calls = self.run_config(data)
        self.assertEqual(self.status(report, "session"), "FAIL")
        self.assertEqual(len(calls), 1)

    def test_removed_error_filter_is_reported_as_pattern_drift(self):
        data = demo_data(); pattern = copy.deepcopy(EXPECTED_PATTERN); del pattern["detail"]["errorCode"]
        data[("events", "describe-rule")]["EventPattern"] = json.dumps(pattern)
        report, _ = self.run_config(data)
        self.assertEqual(self.status(report, "saved_pattern"), "FAIL")

    def test_missing_response_fields_are_not_passes(self):
        data = demo_data(); data[("sns", "list-subscriptions-by-topic")] = {}
        report, _ = self.run_config(data)
        self.assertEqual(self.status(report, "confirmed_email"), "ERROR")

    def test_reports_omit_sensitive_response_fields_and_preserve_runs(self):
        report, _ = self.run_config(demo_data())
        report.update(mode="DEMO", observed_at="2026-11-02T00:00:00Z")
        with tempfile.TemporaryDirectory() as folder:
            first = write_report(report, Path(folder)); second = write_report(report, Path(folder))
            self.assertNotEqual(first, second)
            self.assertEqual(len(list(Path(folder).glob("*.json"))), 2)
            for file in Path(folder).iterdir():
                self.assertNotIn("000000000000", file.read_text())
                self.assertNotIn("fictional@example.invalid", file.read_text())

    def test_expected_pattern_agrees_with_project_baseline(self):
        path = Path(__file__).resolve().parents[1] / "patterns/access-key.json"
        self.assertEqual(json.loads(path.read_text()), EXPECTED_PATTERN)

    def test_cli_rejects_undeclared_write_operation(self):
        with self.assertRaises(ValueError):
            AwsCLI("us-east-1")("events", "disable-rule", name="security-lab-ac")


if __name__ == "__main__":
    unittest.main()
