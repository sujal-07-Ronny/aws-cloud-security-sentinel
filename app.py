
import os
import pandas as pd
import streamlit as st

from aws_security_scanner import run_security_scan
from ai_reporter import generate_security_report


DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")

st.set_page_config(
    page_title="AWS Cloud Security Sentinel",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AWS Cloud Security Sentinel")
st.caption(
    "Read-only AWS security assessment with an AI-generated report"
)

st.info(
    "This dashboard inspects AWS resources and generates recommendations. "
    "It does not modify security settings or execute AI-generated commands."
)

with st.sidebar:
    st.header("Audit Configuration")
    region = st.text_input(
        "AWS Region",
        value=DEFAULT_REGION,
        help="Region for EC2 and the Bedrock Runtime request. "
             "IAM and S3 resources are inspected using their applicable APIs.",
    )

    st.markdown("**Security checks**")
    st.markdown(
        "- Network Security\n"
        "- S3 Public Access\n"
        "- IAM User MFA\n"
        "- EBS Encryption"
    )

    st.caption("Credentials are obtained through the AWS SDK credential chain.")

if "scan_results" not in st.session_state:
    st.session_state.scan_results = None

if "ai_report" not in st.session_state:
    st.session_state.ai_report = None

if "ai_error" not in st.session_state:
    st.session_state.ai_error = None

if "scan_error" not in st.session_state:
    st.session_state.scan_error = None


if st.button(
    "Run Security Audit",
    type="primary",
    use_container_width=True,
):
    st.session_state.scan_results = None
    st.session_state.ai_report = None
    st.session_state.ai_error = None
    st.session_state.scan_error = None

    if not region.strip():
        st.session_state.scan_error = "Enter a valid AWS Region."
    else:
        try:
            with st.spinner("Scanning AWS resources..."):
                results = run_security_scan(region=region.strip())

            st.session_state.scan_results = results

            try:
                with st.spinner("Generating the AI security report..."):
                    report = generate_security_report(
                        results,
                        region=region.strip(),
                    )
                st.session_state.ai_report = report

            except (RuntimeError, ValueError) as exc:
                st.session_state.ai_error = str(exc)

        except Exception as exc:
            # Show a useful error without printing credentials or
            # environment configuration.
            st.session_state.scan_error = (
                f"Audit could not complete: {type(exc).__name__}: {exc}"
            )


results = st.session_state.scan_results

if st.session_state.scan_error:
    st.error(st.session_state.scan_error)

if results:
    summary = results.get("summary", {})
    counts = summary.get("checks_by_status", {})

    st.subheader("Audit Overview")

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Checks", summary.get("checks_total", 0))
    c2.metric("PASS", counts.get("PASS", 0))
    c3.metric("FAIL", counts.get("FAIL", 0))
    c4.metric("WARNING", counts.get("WARNING", 0))
    c5.metric("ERROR", counts.get("ERROR", 0))

    st.caption(
        f"Region: {results.get('region')} · "
        f"Scan time (UTC): {results.get('scan_time_utc')} · "
        f"Read-only: {results.get('read_only')}"
    )

    st.subheader("Security Check Results")

    check_rows = []

    for check in results.get("checks", []):
        check_rows.append({
            "Check": check.get("name"),
            "Status": check.get("status"),
            "Findings": len(check.get("findings", [])),
            "Errors": len(check.get("errors", [])),
            "Summary": check.get("summary"),
        })

    st.dataframe(
        pd.DataFrame(check_rows),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Security Findings")

    finding_rows = []

    for check in results.get("checks", []):
        for finding in check.get("findings", []):
            finding_rows.append({
                "Check": check.get("name"),
                "Status": check.get("status"),
                "Severity": finding.get("severity"),
                "Resource": finding.get("resource"),
                "Finding": finding.get("title"),
                "Details": finding.get("details"),
                "Remediation": finding.get("remediation"),
            })

    if finding_rows:
        st.dataframe(
            pd.DataFrame(finding_rows),
            use_container_width=True,
            hide_index=True,
            column_config={
                "Status": st.column_config.TextColumn("Status"),
                "Severity": st.column_config.TextColumn("Severity"),
                "Details": st.column_config.TextColumn("Details"),
                "Remediation": st.column_config.TextColumn("Remediation"),
            },
        )
    else:
        st.success(
            "No findings were returned by the implemented checks. "
            "Review check statuses and errors before drawing conclusions."
        )

    st.subheader("Check Details")

    for check in results.get("checks", []):
        with st.expander(
            f"{check.get('status', 'UNKNOWN')} — {check.get('name')}"
        ):
            st.write(check.get("summary", ""))

            for finding in check.get("findings", []):
                st.markdown(f"**{finding.get('title')}**")
                st.write(finding.get("details", ""))
                st.write(
                    f"Severity: {finding.get('severity', 'UNKNOWN')}"
                )
                st.write(
                    f"Resource: {finding.get('resource', 'Unknown')}"
                )
                st.write(
                    f"Recommended action: {finding.get('remediation', '')}"
                )
                st.divider()

            for error in check.get("errors", []):
                st.error(
                    f"{error.get('resource', 'Resource')}: "
                    f"{error.get('message', 'Unknown error')}"
                )

    st.subheader("AI-Generated Security Report")

    if st.session_state.ai_report:
        st.markdown(st.session_state.ai_report)
        st.download_button(
            "Download AI Report (.md)",
            data=st.session_state.ai_report,
            file_name="aws_security_report.md",
            mime="text/markdown",
        )
    elif st.session_state.ai_error:
        st.warning(
            "The AWS scan completed, but AI report generation failed. "
            "The findings above are still available."
        )
        st.code(st.session_state.ai_error)
        st.caption(
            "Check Bedrock model access, Region, IAM permissions, "
            "and request limits before retrying."
        )

    # Download the structured findings separately from the AI report.
    st.download_button(
        "Download Scan Results (.json)",
        data=__import__("json").dumps(results, indent=2),
        file_name="aws_security_scan.json",
        mime="application/json",
    )

else:
    st.markdown("### Ready to scan")
    st.write(
        "Select your AWS Region in the sidebar and click "
        "**Run Security Audit** to inspect resources and generate a report."
    )

st.divider()
st.caption(
    "AWS Cloud Security Sentinel · Read-only checks · "
    "AI recommendations require human review"
)
