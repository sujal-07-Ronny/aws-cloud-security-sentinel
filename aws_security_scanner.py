
import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError


WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
RISKY_PORTS = {22: "SSH", 3389: "RDP"}


def new_check(check_id, name):
    return {
        "check_id": check_id,
        "name": name,
        "status": "PASS",
        "summary": "",
        "findings": [],
        "errors": [],
    }


def add_finding(check, resource, severity, title, details, remediation):
    check["findings"].append({
        "resource": resource,
        "severity": severity,
        "title": title,
        "details": details,
        "remediation": remediation,
    })


def add_error(check, resource, exc):
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        message = f'{error.get("Code", "AWSClientError")}: {error.get("Message", "AWS request failed")}'
    else:
        message = str(exc)

    check["errors"].append({
        "resource": resource,
        "message": message,
    })


def finish_check(check, clean_message):
    # An incomplete check must never be reported as PASS.
    if check["errors"]:
        check["status"] = "ERROR"
    elif any(f["severity"] == "HIGH" for f in check["findings"]):
        check["status"] = "FAIL"
    elif check["findings"]:
        check["status"] = "WARNING"
    else:
        check["status"] = "PASS"

    if check["errors"]:
        check["summary"] = (
            f"{len(check['findings'])} finding(s); "
            f"{len(check['errors'])} error(s). Check may be incomplete."
        )
    elif check["findings"]:
        check["summary"] = f"{len(check['findings'])} finding(s) require review."
    else:
        check["summary"] = clean_message


def is_world_open(rule):
    ipv4 = [
        item.get("CidrIp")
        for item in rule.get("IpRanges", [])
    ]
    ipv6 = [
        item.get("CidrIpv6")
        for item in rule.get("Ipv6Ranges", [])
    ]
    return any(cidr in WORLD_CIDRS for cidr in ipv4 + ipv6)


def check_network_security(ec2):
    check = new_check("NETWORK", "Network Security")

    try:
        paginator = ec2.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for group in page.get("SecurityGroups", []):
                group_id = group.get("GroupId", "unknown")
                group_name = group.get("GroupName", "unknown")

                for rule in group.get("IpPermissions", []):
                    if not is_world_open(rule):
                        continue

                    protocol = str(rule.get("IpProtocol", ""))
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")

                    all_ports = (
                        protocol == "-1"
                        or (
                            protocol in {"tcp", "udp"}
                            and from_port == 0
                            and to_port == 65535
                        )
                    )

                    if all_ports:
                        title = "All ports exposed to the internet"
                        details = (
                            f"Security group {group_id} ({group_name}) "
                            "allows inbound traffic on all ports from "
                            "0.0.0.0/0 or ::/0."
                        )
                    else:
                        matched_ports = [
                            port for port in RISKY_PORTS
                            if (
                                (from_port is not None and to_port is not None)
                                and from_port <= port <= to_port
                            )
                        ]

                        if not matched_ports:
                            continue

                        port_names = ", ".join(
                            f"{RISKY_PORTS[p]} ({p})"
                            for p in matched_ports
                        )
                        title = f"Publicly exposed {port_names}"
                        details = (
                            f"Security group {group_id} ({group_name}) "
                            f"allows inbound {port_names} from "
                            "0.0.0.0/0 or ::/0."
                        )

                    add_finding(
                        check,
                        group_id,
                        "HIGH",
                        title,
                        details,
                        "Restrict inbound rules to trusted IP addresses "
                        "or approved network ranges. Remove unnecessary "
                        "public access after reviewing dependencies.",
                    )

    except (ClientError, BotoCoreError) as exc:
        add_error(check, "EC2 security groups", exc)

    finish_check(check, "No matching publicly exposed inbound rules found.")
    return check


def check_s3_public_access(s3):
    check = new_check("S3_PUBLIC_ACCESS", "S3 Public Access")

    try:
        paginator = s3.get_paginator("list_buckets")

        for page in paginator.paginate():
            for bucket in page.get("Buckets", []):
                bucket_name = bucket["Name"]
                bucket_resource = f"s3://{bucket_name}"

                # Resolve the bucket's Region before checking its settings.
                try:
                    location = s3.get_bucket_location(
                        Bucket=bucket_name
                    ).get("LocationConstraint")
                    bucket_region = location or "us-east-1"
                    if bucket_region == "EU":
                        bucket_region = "eu-west-1"

                    regional_s3 = boto3.client(
                        "s3",
                        region_name=bucket_region,
                    )
                except (ClientError, BotoCoreError) as exc:
                    add_error(check, bucket_resource, exc)
                    continue

                # Bucket-level Block Public Access.
                try:
                    response = regional_s3.get_public_access_block(
                        Bucket=bucket_name
                    )
                    config = response.get(
                        "PublicAccessBlockConfiguration", {}
                    )

                    expected_settings = [
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    ]
                    missing_or_disabled = [
                        key for key in expected_settings
                        if config.get(key) is not True
                    ]

                    if missing_or_disabled:
                        add_finding(
                            check,
                            bucket_resource,
                            "MEDIUM",
                            "S3 Block Public Access is not fully enabled",
                            "These bucket-level settings are missing or "
                            "disabled: "
                            + ", ".join(missing_or_disabled)
                            + ". Account-level settings may provide "
                            "additional protection.",
                            "Review the bucket and account requirements, "
                            "then enable all four Block Public Access "
                            "settings where appropriate.",
                        )

                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")

                    if code in {
                        "NoSuchPublicAccessBlockConfiguration",
                        "NoSuchConfiguration",
                    }:
                        add_finding(
                            check,
                            bucket_resource,
                            "MEDIUM",
                            "Bucket-level Block Public Access not configured",
                            "No bucket-level Block Public Access "
                            "configuration was returned. This alone does "
                            "not prove the bucket is publicly accessible.",
                            "Review account-level protection and enable "
                            "all four bucket-level Block Public Access "
                            "settings where appropriate.",
                        )
                    else:
                        add_error(check, bucket_resource, exc)

                except BotoCoreError as exc:
                    add_error(check, bucket_resource, exc)

                # Check whether AWS classifies the bucket policy as public.
                try:
                    policy_status = regional_s3.get_bucket_policy_status(
                        Bucket=bucket_name
                    )
                    if policy_status.get("PolicyStatus", {}).get(
                        "IsPublic", False
                    ):
                        add_finding(
                            check,
                            bucket_resource,
                            "HIGH",
                            "Bucket policy is classified as public",
                            "AWS reports that the bucket policy permits "
                            "public access.",
                            "Review the bucket policy and remove "
                            "unintended public access. Preserve any "
                            "intentionally approved access only after "
                            "review.",
                        )

                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code in {"NoSuchBucketPolicy", "NoSuchPolicy"}:
                        pass
                    else:
                        add_error(check, bucket_resource, exc)
                except BotoCoreError as exc:
                    add_error(check, bucket_resource, exc)

                # Check bucket ACL for public or broadly accessible grants.
                try:
                    acl = regional_s3.get_bucket_acl(Bucket=bucket_name)

                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        uri = grantee.get("URI", "")

                        if uri.endswith("/AllUsers"):
                            audience = "Everyone (AllUsers)"
                        elif uri.endswith("/AuthenticatedUsers"):
                            audience = "All authenticated AWS users"
                        else:
                            continue

                        permission = grant.get("Permission", "UNKNOWN")
                        add_finding(
                            check,
                            bucket_resource,
                            "HIGH",
                            "Broad S3 bucket ACL grant",
                            f"Bucket ACL grants {permission} to {audience}.",
                            "Review the ACL and remove unintended broad "
                            "grants. Check application requirements before "
                            "changing access settings.",
                        )

                except (ClientError, BotoCoreError) as exc:
                    add_error(check, bucket_resource, exc)

    except (ClientError, BotoCoreError) as exc:
        add_error(check, "S3 bucket listing", exc)

    finish_check(check, "No S3 public-access configuration concerns found.")
    return check


def check_iam_mfa(iam):
    check = new_check("IAM_MFA", "IAM User MFA")

    try:
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]

                try:
                    devices = iam.get_paginator("list_mfa_devices")
                    has_mfa = any(
                        device_page.get("MFADevices", [])
                        for device_page in devices.paginate(
                            UserName=username
                        )
                    )

                    if not has_mfa:
                        add_finding(
                            check,
                            username,
                            "HIGH",
                            "IAM user has no MFA device",
                            f"IAM user {username} has no MFA device "
                            "registered in the inspected account.",
                            "Enable MFA for the user and review whether "
                            "long-term IAM user credentials are necessary. "
                            "Prefer temporary credentials where possible.",
                        )

                except (ClientError, BotoCoreError) as exc:
                    add_error(check, f"IAM user: {username}", exc)

    except (ClientError, BotoCoreError) as exc:
        add_error(check, "IAM user listing", exc)

    finish_check(check, "All inspected IAM users have MFA devices.")
    return check


def check_ebs_encryption(ec2):
    check = new_check("EBS_ENCRYPTION", "EBS Encryption")

    try:
        paginator = ec2.get_paginator("describe_volumes")

        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                if volume.get("Encrypted") is False:
                    volume_id = volume.get("VolumeId", "unknown")

                    add_finding(
                        check,
                        volume_id,
                        "HIGH",
                        "EBS volume is unencrypted",
                        f"EBS volume {volume_id} is not encrypted.",
                        "Plan an appropriate migration or replacement "
                        "with an encrypted volume. Review backups, "
                        "attachments, and application downtime before "
                        "making changes.",
                    )

    except (ClientError, BotoCoreError) as exc:
        add_error(check, "EBS volumes", exc)

    finish_check(check, "No unencrypted EBS volumes found.")
    return check


def run_security_scan(region=None, session=None):
    """Run the four read-only checks and return JSON-serializable results."""
    session = session or boto3.Session()

    region = region or session.region_name
    if not region:
        raise ValueError(
            "AWS Region is not configured. Set AWS_DEFAULT_REGION "
            "or pass region explicitly."
        )

    ec2 = session.client("ec2", region_name=region)
    s3 = session.client("s3", region_name=region)
    iam = session.client("iam")

    checks = [
        check_network_security(ec2),
        check_s3_public_access(s3),
        check_iam_mfa(iam),
        check_ebs_encryption(ec2),
    ]

    counts = {
        "PASS": sum(c["status"] == "PASS" for c in checks),
        "FAIL": sum(c["status"] == "FAIL" for c in checks),
        "WARNING": sum(c["status"] == "WARNING" for c in checks),
        "ERROR": sum(c["status"] == "ERROR" for c in checks),
    }

    return {
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "region": region,
        "read_only": True,
        "summary": {
            "checks_total": len(checks),
            "checks_by_status": counts,
            "findings_total": sum(
                len(c["findings"]) for c in checks
            ),
            "errors_total": sum(len(c["errors"]) for c in checks),
        },
        "checks": checks,
    }


if __name__ == "__main__":
    try:
        results = run_security_scan()
        print(json.dumps(results, indent=2))
    except (ValueError, BotoCoreError, ClientError) as exc:
        print(f"Scan could not start or complete: {exc}")
