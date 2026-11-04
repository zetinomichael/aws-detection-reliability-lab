import copy
import unittest

from lab import UnsupportedPattern, load_inputs, match_pattern, mutations, run_cases


class PatternContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns, cls.cases = load_inputs()

    def test_authored_fixture_expectations(self):
        for result in run_cases(self.patterns, self.cases, match_pattern):
            with self.subTest(case=result["id"]):
                self.assertTrue(result["passed"], result)

    def test_explicit_null_is_present_for_exists(self):
        event = copy.deepcopy(self.cases[0]["event"])
        event["detail"]["errorCode"] = None
        actual, trace = match_pattern(self.patterns["access-key"], event)
        self.assertFalse(actual)
        self.assertTrue(any("detail.errorCode" in reason for reason in trace))

    def test_unrelated_fields_do_not_change_match(self):
        event = copy.deepcopy(self.cases[0]["event"])
        event["detail"]["unrelated"] = {"nested": ["extra"]}
        self.assertTrue(match_pattern(self.patterns["access-key"], event)[0])

    def test_unknown_operator_fails_loudly(self):
        pattern = {"source": [{"prefix": "aws."}]}
        with self.assertRaises(UnsupportedPattern):
            match_pattern(pattern, self.cases[0]["event"])

    def test_complex_compared_event_value_fails_loudly(self):
        event = copy.deepcopy(self.cases[0]["event"])
        event["source"] = ["aws.iam"]
        with self.assertRaises(UnsupportedPattern):
            match_pattern(self.patterns["access-key"], event)

    def test_missing_nested_object_is_a_mismatch(self):
        event = copy.deepcopy(self.cases[0]["event"])
        event.pop("detail")
        self.assertFalse(match_pattern(self.patterns["access-key"], event)[0])

    def test_fixture_suite_catches_each_known_mutation(self):
        for name, variant in mutations(self.patterns):
            with self.subTest(mutation=name):
                self.assertTrue(any(not case["passed"] for case in run_cases(variant, self.cases, match_pattern)))


if __name__ == "__main__":
    unittest.main()
