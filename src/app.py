import html
import re
from dataclasses import dataclass
from typing import Callable, Optional

import streamlit as st


st.set_page_config(
    page_title="Shadow AI Privacy Auditor",
    page_icon="🛡️",
    layout="wide",
)


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    text: str
    category: str
    label: str
    explanation: str
    severity: str


CATEGORY_STYLES = {
    "Names & contact information": ("#DBEAFE", "#1E3A8A"),
    "Government or financial identifiers": ("#FEE2E2", "#7F1D1D"),
    "Passwords, API keys or credentials": ("#FFEDD5", "#7C2D12"),
    "Medical or sensitive personal information": ("#F3E8FF", "#581C87"),
    "Employee, client or volunteer information": ("#DCFCE7", "#14532D"),
    "Confidential organizational or project information": ("#FEF9C3", "#713F12"),
}

SEVERITY_RANK = {"High": 3, "Medium": 2, "Low": 1}


def add_finding(
    findings: list[Finding],
    text: str,
    start: int,
    end: int,
    category: str,
    label: str,
    explanation: str,
    severity: str,
) -> None:
    if start < end:
        findings.append(
            Finding(
                start=start,
                end=end,
                text=text[start:end],
                category=category,
                label=label,
                explanation=explanation,
                severity=severity,
            )
        )


def luhn_valid(candidate: str) -> bool:
    digits = [int(char) for char in re.sub(r"\D", "", candidate)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    ranked = sorted(
        findings,
        key=lambda item: (
            item.start,
            -SEVERITY_RANK[item.severity],
            -(item.end - item.start),
        ),
    )
    accepted: list[Finding] = []

    for candidate in ranked:
        overlaps = any(
            candidate.start < existing.end and candidate.end > existing.start
            for existing in accepted
        )
        if not overlaps:
            accepted.append(candidate)

    return sorted(accepted, key=lambda item: item.start)


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Names and contact information
    for match in re.finditer(
        r"(?<![\w.-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])",
        text,
    ):
        add_finding(
            findings,
            text,
            match.start(),
            match.end(),
            "Names & contact information",
            "EMAIL",
            "Email addresses can identify or directly contact a person.",
            "High",
        )

    for match in re.finditer(
        r"(?<!\w)(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\w)",
        text,
    ):
        add_finding(
            findings,
            text,
            match.start(),
            match.end(),
            "Names & contact information",
            "PHONE",
            "Phone numbers are direct contact information.",
            "High",
        )

    for match in re.finditer(
    r"(?m)^(?i:employee name|client name|volunteer name|contact person|name)"
    r"[ \t]*[:=-][ \t]*"
    r"([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2})[ \t]*$",
    text,
):
        add_finding(
            findings,
            text,
            match.start(1),
            match.end(1),
            "Names & contact information",
            "NAME",
            "A labeled full name can identify a specific person.",
            "Medium",
        )

    # 2. Government and financial identifiers
    for match in re.finditer(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", text):
        add_finding(
            findings,
            text,
            match.start(),
            match.end(),
            "Government or financial identifiers",
            "SSN",
            "A Social Security number can enable identity theft and fraud.",
            "High",
        )

    for match in re.finditer(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", text):
        if luhn_valid(match.group()):
            add_finding(
                findings,
                text,
                match.start(),
                match.end(),
                "Government or financial identifiers",
                "PAYMENT_CARD",
                "A valid payment-card-like number is highly sensitive financial data.",
                "High",
            )

    financial_patterns = [
        (
            r"(?i)\b(?:routing number|bank routing)\s*[:=-]\s*(\d{9})\b",
            "ROUTING_NUMBER",
            "Bank routing numbers can expose financial-account details.",
        ),
        (
            r"(?i)\b(?:bank account|account number)\s*[:=-]\s*([A-Za-z0-9-]{6,20})\b",
            "BANK_ACCOUNT",
            "Bank account identifiers can enable financial fraud.",
        ),
    ]
    for pattern, label, explanation in financial_patterns:
        for match in re.finditer(pattern, text):
            add_finding(
                findings,
                text,
                match.start(1),
                match.end(1),
                "Government or financial identifiers",
                label,
                explanation,
                "High",
            )

    # 3. Passwords, API keys, and credentials
    credential_pattern = re.compile(
        r"(?i)\b(?:password|passcode|api[_ -]?key|access[_ -]?token|auth[_ -]?token|"
        r"client[_ -]?secret|secret)\s*[:=]\s*[\"']?"
        r"([A-Za-z0-9_\-./+=]{4,})[\"']?"
    )
    for match in credential_pattern.finditer(text):
        add_finding(
            findings,
            text,
            match.start(1),
            match.end(1),
            "Passwords, API keys or credentials",
            "CREDENTIAL",
            "Credentials can grant unauthorized access to systems or accounts.",
            "High",
        )

    for match in re.finditer(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{16,}(?![A-Za-z0-9])", text):
        add_finding(
            findings,
            text,
            match.start(),
            match.end(),
            "Passwords, API keys or credentials",
            "API_KEY",
            "This resembles an API key that could provide access to a paid service.",
            "High",
        )

    # 4. Medical or sensitive personal information
    medical_patterns = [
        (
            r"(?i)\b(?:patient id|medical record(?: number)?|mrn)\s*[:=-]\s*([A-Za-z0-9-]{4,20})\b",
            "PATIENT_ID",
            "Patient identifiers can connect a person to private health records.",
        ),
        (
            r"(?i)\b(?:date of birth|dob)\s*[:=-]\s*"
            r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})",
            "DATE_OF_BIRTH",
            "A date of birth is sensitive identity information.",
        ),
        (
            r"(?i)\b(?:diagnosis|diagnosed with|medical condition)\s*[:=-]?\s*"
            r"([A-Za-z][A-Za-z0-9 ,'-]{2,50})(?=[.;\n]|$)",
            "MEDICAL_CONDITION",
            "A diagnosis or medical condition is sensitive health information.",
        ),
        (
            r"(?i)\b(?:medication|prescription)\s*[:=-]\s*"
            r"([A-Za-z][A-Za-z0-9 -]{2,40})(?=[.;\n]|$)",
            "MEDICATION",
            "Medication information can reveal a person's health status.",
        ),
    ]
    for pattern, label, explanation in medical_patterns:
        for match in re.finditer(pattern, text):
            add_finding(
                findings,
                text,
                match.start(1),
                match.end(1),
                "Medical or sensitive personal information",
                label,
                explanation,
                "High",
            )

    # 5. Employee, client, or volunteer information
    for match in re.finditer(
        r"(?i)\b(employee|client|volunteer)\s*(?:id|number|#)\s*[:=-]?\s*([A-Za-z0-9-]{3,20})\b",
        text,
    ):
        label = f"{match.group(1).upper()}_ID"
        add_finding(
            findings,
            text,
            match.start(2),
            match.end(2),
            "Employee, client or volunteer information",
            label,
            "Internal personnel or client identifiers can expose private records.",
            "Medium",
        )

    # 6. Confidential organizational or project information
    confidential_patterns = [
        (
            r"(?i)\b(?:project codename|internal project|secret project)\s*[:=-]\s*"
            r"([A-Za-z][A-Za-z0-9 _-]{2,40})(?=[.;\n]|$)",
            "PROJECT_CODENAME",
            "An internal project name may reveal confidential company work.",
        ),
        (
            r"(?i)\b(?:acquisition target|confidential client|unreleased feature|roadmap item)\s*[:=-]\s*"
            r"([A-Za-z][A-Za-z0-9 &,_-]{2,60})(?=[.;\n]|$)",
            "CONFIDENTIAL_PROJECT_INFO",
            "This may disclose non-public organizational or project information.",
        ),
        (
            r"(?i)\b(?:confidential budget|internal budget)\s*[:=-]\s*"
            r"(\$?\d[\d,]*(?:\.\d{2})?)",
            "CONFIDENTIAL_BUDGET",
            "Non-public budget information can be commercially sensitive.",
        ),
    ]
    for pattern, label, explanation in confidential_patterns:
        for match in re.finditer(pattern, text):
            add_finding(
                findings,
                text,
                match.start(1),
                match.end(1),
                "Confidential organizational or project information",
                label,
                explanation,
                "Medium",
            )

    for match in re.finditer(
        r"(?i)\b(confidential|internal only|do not distribute|under NDA|not for public release)\b",
        text,
    ):
        add_finding(
            findings,
            text,
            match.start(),
            match.end(),
            "Confidential organizational or project information",
            "CONFIDENTIAL_MARKER",
            "This phrase indicates that the surrounding information may not be public.",
            "Medium",
        )

    return resolve_overlaps(findings)


def build_redacted_text(text: str, findings: list[Finding]) -> str:
    redacted = text
    for finding in sorted(findings, key=lambda item: item.start, reverse=True):
        redacted = redacted[: finding.start] + f"[{finding.label}]" + redacted[finding.end :]
    return redacted


def build_highlighted_html(text: str, findings: list[Finding]) -> str:
    pieces: list[str] = []
    cursor = 0

    for finding in findings:
        pieces.append(html.escape(text[cursor : finding.start]))
        background, foreground = CATEGORY_STYLES[finding.category]
        tooltip = html.escape(f"{finding.category}: {finding.explanation}", quote=True)
        pieces.append(
            f'<mark title="{tooltip}" style="background:{background};color:{foreground};'
            f'padding:2px 4px;border-radius:4px;font-weight:600;">'
            f"{html.escape(finding.text)}</mark>"
        )
        cursor = finding.end

    pieces.append(html.escape(text[cursor:]))
    return (
        '<div style="white-space:pre-wrap;line-height:1.8;padding:1rem;'
        'border:1px solid #D1D5DB;border-radius:0.5rem;">'
        + "".join(pieces)
        + "</div>"
    )


def load_sample() -> None:
    st.session_state["input_text"] = (
        "Employee name: Maya Patel\n"
        "Email: maya.patel@example.com\n"
        "Phone: (415) 555-0184\n"
        "Employee ID: EMP-2048\n"
        "SSN: 123-45-6789\n"
        "API key: sk-EXAMPLE1234567890ABC\n"
        "Diagnosis: fictional migraine condition.\n"
        "Project codename: Silver Lantern.\n"
        "The project meeting is scheduled for 3:00 PM."
    )


def clear_text() -> None:
    st.session_state["input_text"] = ""


st.title("🛡️ Shadow AI Privacy Auditor")
st.write(
    "Check text before sharing it with an AI tool. The auditor identifies possible "
    "sensitive information, explains the risk, and creates a safer redacted version."
)

st.info(
    "Privacy-first design: this prototype uses local rule-based detection and does not "
    "intentionally store your text or send it to an external AI provider. Use only "
    "fictional or synthetic examples during this hackathon."
)

button_col1, button_col2, spacer = st.columns([1, 1, 5])
with button_col1:
    st.button("Load fictional example", on_click=load_sample)
with button_col2:
    st.button("Clear", on_click=clear_text)

user_text = st.text_area(
    "Text to audit",
    key="input_text",
    height=220,
    placeholder="Paste the text you plan to send to an AI tool...",
)

scan_clicked = st.button("Scan for privacy risks", type="primary", use_container_width=True)

if scan_clicked:
    if not user_text.strip():
        st.warning("Enter some text before scanning.")
    else:
        findings = scan_text(user_text)
        redacted_text = build_redacted_text(user_text, findings)

        st.divider()

        if not findings:
            st.success(
                "No supported sensitive-information patterns were detected. "
                "The text remains unchanged."
            )
            st.code(user_text, language=None)
        else:
            high_count = sum(item.severity == "High" for item in findings)
            categories_found = len({item.category for item in findings})

            metric_col1, metric_col2, metric_col3 = st.columns(3)
            metric_col1.metric("Findings", len(findings))
            metric_col2.metric("Categories", categories_found)
            metric_col3.metric("High-risk findings", high_count)

            left, right = st.columns(2)

            with left:
                st.subheader("Highlighted review")
                st.markdown(
                    build_highlighted_html(user_text, findings),
                    unsafe_allow_html=True,
                )

            with right:
                st.subheader("Safer redacted version")
                st.code(redacted_text, language=None)
                st.download_button(
                    "Download safe text",
                    data=redacted_text,
                    file_name="redacted_text.txt",
                    mime="text/plain",
                    use_container_width=True,
                )

            st.subheader("Why these items may be risky")
            for index, finding in enumerate(findings, start=1):
                with st.expander(
                    f"{index}. {finding.label} — {finding.severity} risk",
                    expanded=index <= 3,
                ):
                    st.write(f"**Detected text:** `{finding.text}`")
                    st.write(f"**Category:** {finding.category}")
                    st.write(f"**Explanation:** {finding.explanation}")

            st.caption(
                "This is a rule-based prototype. Review every finding before using the "
                "redacted result because false positives and missed items are possible."
            )
else:
    st.caption(
        "Tip: load the fictional example to see all six detection categories in action."
    )
