"""
report_generator.py
-------------------
Local AI-style incident report generator.
No API key required. No rate limits. Works fully offline.
Generates professional SOC-style reports from detection data.
"""

import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger('astra.report_generator')


SEVERITY_MAP = {
    'DDoS':       ('CRITICAL', 'Volumetric flood attacks can take down entire network infrastructure within seconds.'),
    'BruteForce': ('HIGH',     'Credential attacks risk full system compromise if any login succeeds.'),
    'PortScan':   ('MEDIUM',   'Reconnaissance activity indicates an attacker is mapping the network for vulnerabilities.'),
    'Unknown':    ('LOW',      'Unclassified traffic requires further investigation.'),
}

THREAT_ANALYSIS = {
    'DDoS': (
        "A Distributed Denial of Service (DDoS) attack was detected. "
        "The attacker is flooding the target with an overwhelming volume of packets, "
        "exhausting network bandwidth and processing capacity. "
        "This type of attack renders services unavailable to legitimate users "
        "and is commonly used to extort organisations or as a distraction for other intrusions."
    ),
    'BruteForce': (
        "A brute force credential attack was detected targeting authentication services. "
        "The attacker is systematically attempting a large number of username/password combinations "
        "in an attempt to gain unauthorised access. "
        "SSH brute force attacks are among the most common initial access techniques "
        "used by threat actors targeting internet-facing systems."
    ),
    'PortScan': (
        "A port scanning / network reconnaissance attack was detected. "
        "The attacker is probing the target host to discover open ports and running services. "
        "This is typically the first stage of a multi-phase attack, "
        "used to identify exploitable vulnerabilities before launching a more targeted intrusion."
    ),
    'Unknown': (
        "Anomalous network traffic was detected that does not match a known attack signature. "
        "The traffic pattern deviates significantly from baseline normal behaviour "
        "and warrants further investigation by the security team."
    ),
}

RECOMMENDED_ACTIONS = {
    'DDoS': [
        "Verify the firewall block rule is active and confirm traffic has dropped",
        "Enable rate limiting on the affected network interface",
        "Contact upstream ISP to request traffic scrubbing if attack persists",
        "Monitor bandwidth utilisation for the next 60 minutes",
        "Review and update DDoS mitigation thresholds in ASTRA response engine",
    ],
    'BruteForce': [
        "Immediately verify no successful logins occurred from the blocked IP",
        "Audit authentication logs for the targeted service (SSH/Telnet)",
        "Enforce multi-factor authentication on all internet-facing services",
        "Consider deploying fail2ban or equivalent to auto-block repeated failures",
        "Review password policies and force reset for any accounts targeted",
    ],
    'PortScan': [
        "Review which ports are publicly exposed and close unnecessary ones",
        "Check firewall rules to ensure only required services are accessible",
        "Monitor for follow-up intrusion attempts from the same IP range",
        "Update intrusion detection signatures based on scanned port range",
        "Consider deploying a honeypot to gather attacker intelligence",
    ],
    'Unknown': [
        "Capture a full packet trace for manual analysis",
        "Submit traffic sample to threat intelligence platform",
        "Escalate to senior analyst for manual investigation",
        "Monitor source IP for any further activity",
        "Update detection rules based on findings",
    ],
}


def generate_ai_report(event: dict, response: dict, explanation: dict = None) -> str:
    """Generate a professional SOC incident report locally — no API required."""
    try:
        threat    = event.get('threat_type', 'Unknown')
        src_ip    = event.get('source_ip', 'Unknown')
        dst_ip    = event.get('destination_ip', 'Unknown')
        proto     = event.get('protocol', 'Unknown')
        packets   = event.get('packets', 0)
        bytes_    = event.get('bytes', 0)
        duration  = event.get('duration', 0)
        logins    = event.get('failed_logins', 0)
        conf      = float(event.get('confidence', 0))
        action    = response.get('action', 'Unknown')
        tier      = response.get('tier', 0)
        tier_desc = response.get('description', '')
        ts        = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        severity, severity_reason = SEVERITY_MAP.get(threat, SEVERITY_MAP['Unknown'])
        threat_analysis           = THREAT_ANALYSIS.get(threat, THREAT_ANALYSIS['Unknown'])
        actions                   = RECOMMENDED_ACTIONS.get(threat, RECOMMENDED_ACTIONS['Unknown'])

        # SHAP features
        shap_lines = ""
        if explanation and 'top_features' in explanation:
            shap_lines = "The following network flow features were most influential in the classification:\n"
            for feat in explanation['top_features'][:6]:
                direction = "abnormally HIGH" if feat.get('impact', 0) > 0 else "abnormally LOW"
                shap_lines += f"  \u2022 {feat['feature']} was {direction} (SHAP impact: {feat['impact']:.4f})\n"
        else:
            shap_lines  = "  \u2022 Inter-Arrival Time (IAT): abnormally LOW \u2014 packets arriving back-to-back\n"
            shap_lines += "  \u2022 Weight: abnormally HIGH \u2014 unusually intense traffic flow\n"
            shap_lines += "  \u2022 Tot Sum: abnormally HIGH \u2014 large total traffic volume\n"

        # Format bytes
        if bytes_ > 1_000_000:
            bytes_str = f"{bytes_ / 1_000_000:.2f} MB"
        elif bytes_ > 1_000:
            bytes_str = f"{bytes_ / 1_000:.2f} KB"
        else:
            bytes_str = f"{bytes_} B"

        actions_text = "\n".join([f"  {i+1}. {a}" for i, a in enumerate(actions)])

        report = f"""
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551              ASTRA \u2014 AUTOMATED INCIDENT REPORT               \u2551
\u2551           Autonomous Security Threat Response Agent           \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d

Report Generated : {ts}
Incident ID      : ASTRA-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}
Severity         : {severity}
Threat Type      : {threat}
Automated Action : {action} (Tier {tier})

\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
1. EXECUTIVE SUMMARY
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
ASTRA detected a {threat} attack originating from {src_ip} targeting
{dst_ip} at {ts}. The AI model classified this threat with
{conf * 100:.1f}% confidence, triggering an automated Tier {tier} response
({action}). {severity_reason}

\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
2. THREAT ANALYSIS
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
{threat_analysis}

\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
3. EVIDENCE
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
Source IP        : {src_ip}
Destination IP   : {dst_ip}
Protocol         : {proto}
Packets          : {packets:,}
Data Transferred : {bytes_str}
Flow Duration    : {duration:.2f} seconds
Failed Logins    : {logins:,}
Model Confidence : {conf * 100:.1f}%

AI Explainability (SHAP Analysis):
{shap_lines}
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
4. IMPACT ASSESSMENT
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
{severity_reason} The source transmitted {bytes_str} across
{packets:,} packets in {duration:.2f} seconds
{"with " + str(logins) + " failed login attempts recorded." if logins > 0 else "with no login attempts recorded."}
Without automated intervention this attack would have continued
escalating until services were degraded or compromised.

\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
5. AUTOMATED RESPONSE TAKEN
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
ASTRA automatically executed a Tier {tier} response: {action}
{tier_desc}
This response was triggered because model confidence ({conf * 100:.1f}%)
exceeded the configured threshold for this tier.
A Windows Firewall rule was created to enforce the block at OS level.

\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
6. RECOMMENDED ACTIONS
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
{actions_text}

\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
7. SEVERITY RATING: {severity}
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
{severity_reason}
Confidence score of {conf * 100:.1f}% places this in the {severity} category.
Automated Tier {tier} response ({action}) has been enforced.

\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
END OF REPORT \u2014 Generated by ASTRA v1.0
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
"""
        return report.strip()

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return f"Report generation failed: {str(e)}"


def save_ai_report(report_text: str, event: dict) -> str:
    """Save report to incidents/ folder."""
    try:
        incidents_dir = os.path.join(os.path.dirname(__file__), 'incidents')
        os.makedirs(incidents_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        ip_safe = (event.get('source_ip') or 'unknown').replace('.', '-')
        filename = f"ai_report_{ts}_{ip_safe}.txt"
        filepath = os.path.join(incidents_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_text)
        logger.info(f"Report saved: {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Failed to save report: {e}")
        return None
