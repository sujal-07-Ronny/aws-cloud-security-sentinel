
import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError

from ai_reporter import generate_security_report


SAMPLE_RESULTS = {
    "scan_time_utc": "2026-10-27T00:00:00+00:00",
    "region": "ap-south-1",
    "read_only": True,
    "summary": {
        "checks_total": 4,
        "checks_by_status": {
            "PASS": 2,
            "FAIL": 2,
            "WARNING": 0,
            "ERROR": 0,
        },
        "findings_total": 1,
        "errors_total": 0,
    },
    "checks": [
        {
            "check_id": "NETWORK",
            "name": "Network Security",
            "status": "FAIL",
            "summary": "One finding requires review.",
            "findings": [
                {
                    "resource": "sg-test",
                    "severity": "HIGH",
                    "title": "Publicly exposed SSH (22)",
                    "details": "SSH is exposed to 0.0.0.0/0.",
                    "remediation": "Restrict access to trusted IPs.",
                }
            ],
            "errors": [],
        }
    ],
}


class AIReporterTests(unittest.TestCase):

    def test_valid_bedrock_response(self):
        client = Mock()
        client.converse.return_value = {
            "output": {
                "message": {
                    "content": [
                        {"text": "# Security Report\n\nReview SSH access."}
                    ]
                }
            }
        }

        report = generate_security_report(
            SAMPLE_RESULTS,
            region="ap-south-1",
            bedrock_client=client,
        )

        self.assertIn("# Security Report", report)
        client.converse.assert_called_once()
        print("PASS: Mocked Bedrock response generated a report.")

    def test_bedrock_access_denied(self):
        client = Mock()
        client.converse.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Mocked access denied",
                }
            },
            "Converse",
        )

        with self.assertRaisesRegex(
            RuntimeError, "AccessDeniedException"
        ):
            generate_security_report(
                SAMPLE_RESULTS,
                region="ap-south-1",
                bedrock_client=client,
            )

        print("PASS: Bedrock access failure was handled.")

    def test_invalid_scan_input(self):
        with self.assertRaises(ValueError):
            generate_security_report(
                {"summary": {}, "checks": "invalid"},
                region="ap-south-1",
                bedrock_client=Mock(),
            )

        print("PASS: Invalid scan input was rejected.")

    def test_empty_bedrock_response(self):
        client = Mock()
        client.converse.return_value = {
            "output": {
                "message": {
                    "content": []
                }
            }
        }

        with self.assertRaisesRegex(
            RuntimeError, "empty or invalid"
        ):
            generate_security_report(
                SAMPLE_RESULTS,
                region="ap-south-1",
                bedrock_client=client,
            )

        print("PASS: Empty Bedrock response was handled.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
