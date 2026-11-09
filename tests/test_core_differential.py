import unittest

from proofcms.core.differential import confirm_shortcode_output, evidence_from


def _extract(body):
    import re

    match = re.search(r'data-url="([^"]*)"', body)
    return match.group(1) if match else None


class TestConfirmShortcodeOutput(unittest.TestCase):
    def test_evaluated_when_marker_and_handler_output_present(self):
        body = '<div>Module ID attribute is required!<div data-url="http://proofcmsabc">'
        result = confirm_shortcode_output(
            lambda url: body,
            _extract,
            "proofcmsabc",
            probe_tag="forminator_quiz",
            expected_output="Module ID attribute is required!",
        )
        self.assertTrue(result.evaluated)
        self.assertEqual(result.reflection, "http://proofcmsabc")
        self.assertTrue(result.marker_present)

    def test_not_evaluated_when_handler_output_missing(self):
        body = '<div data-url="http://proofcmsabc">'
        result = confirm_shortcode_output(
            lambda url: body,
            _extract,
            "proofcmsabc",
            probe_tag="forminator_quiz",
            expected_output="Module ID attribute is required!",
        )
        self.assertFalse(result.evaluated)

    def test_not_evaluated_when_sink_absent(self):
        result = confirm_shortcode_output(
            lambda url: "<div>no share block here</div>",
            _extract,
            "proofcmsabc",
            probe_tag="forminator_quiz",
            expected_output="Module ID attribute is required!",
        )
        self.assertFalse(result.evaluated)
        self.assertIsNone(result.reflection)

    def test_reflection_alone_is_not_evaluation(self):
        # The murrez-style false positive: marker reflected, nothing evaluated.
        body = '<div data-url="http://proofcmsabc[forminator_quiz]">'
        result = confirm_shortcode_output(
            lambda url: body,
            _extract,
            "proofcmsabc",
            probe_tag="forminator_quiz",
            expected_output="Module ID attribute is required!",
        )
        self.assertFalse(result.evaluated)

    def test_evidence_from_merges_extra(self):
        result = confirm_shortcode_output(
            lambda url: "x",
            lambda body: None,
            "proofcmsabc",
            probe_tag="gallery",
            expected_output="yes",
        )
        evidence = evidence_from(result, {"form_id": "5"})
        self.assertEqual(evidence["form_id"], "5")
        self.assertFalse(evidence["shortcode_evaluated"])
        self.assertIsNone(evidence["reflection"])


if __name__ == "__main__":
    unittest.main()
