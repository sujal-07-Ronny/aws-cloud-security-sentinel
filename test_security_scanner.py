
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError

from aws_security_scanner import (
    check_network_security,
    check_s3_public_access,
    check_iam_mfa,
    check_ebs_encryption,
)


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return iter(self.pages)


class FakeEC2:
    def get_paginator(self, operation):
        if operation == "describe_security_groups":
            return FakePaginator([{
                "SecurityGroups": [{
                    "GroupId": "sg-test",
                    "GroupName": "test-group",
                    "IpPermissions": [{
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                    }],
                }]
            }])

        if operation == "describe_volumes":
            return FakePaginator([{
                "Volumes": [{
                    "VolumeId": "vol-test",
                    "Encrypted": False,
                }]
            }])

        raise ValueError(f"Unexpected EC2 operation: {operation}")


class FakeS3:
    def get_paginator(self, operation):
        if operation == "list_buckets":
            return FakePaginator([{
                "Buckets": [{"Name": "test-bucket"}]
            }])
        raise ValueError(f"Unexpected S3 operation: {operation}")

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": "ap-south-1"}


class FakeRegionalS3:
    def get_public_access_block(self, Bucket):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": False}}

    def get_bucket_acl(self, Bucket):
        return {"Grants": []}


class FakeIAM:
    def get_paginator(self, operation):
        if operation == "list_users":
            return FakePaginator([{
                "Users": [{"UserName": "test-user"}]
            }])

        if operation == "list_mfa_devices":
            return FakePaginator([{"MFADevices": []}])

        raise ValueError(f"Unexpected IAM operation: {operation}")


class ErrorEC2:
    def get_paginator(self, operation):
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "Mock permission denied",
                }
            },
            "DescribeSecurityGroups",
        )


class SecurityScannerTests(unittest.TestCase):

    def test_public_ssh_is_detected(self):
        result = check_network_security(FakeEC2())

        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(
            any(
                "SSH" in finding["title"]
                for finding in result["findings"]
            )
        )
        print("PASS: Public SSH was detected.")

    def test_s3_secure_configuration_passes(self):
        fake_s3 = FakeS3()

        with patch(
            "aws_security_scanner.boto3.client",
            return_value=FakeRegionalS3(),
        ):
            result = check_s3_public_access(fake_s3)

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["findings"], [])
        print("PASS: Secure S3 configuration passed.")

    def test_iam_user_without_mfa_is_detected(self):
        result = check_iam_mfa(FakeIAM())

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(len(result["findings"]), 1)
        print("PASS: IAM user without MFA was detected.")

    def test_unencrypted_ebs_is_detected(self):
        result = check_ebs_encryption(FakeEC2())

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(
            result["findings"][0]["resource"],
            "vol-test",
        )
        print("PASS: Unencrypted EBS volume was detected.")

    def test_permission_error_is_not_pass(self):
        result = check_network_security(ErrorEC2())

        self.assertEqual(result["status"], "ERROR")
        self.assertGreater(len(result["errors"]), 0)
        print("PASS: Permission error correctly returned ERROR.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
