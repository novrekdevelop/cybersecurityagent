"""Evaluation of the email security posture.

A cybersecurity engineer verifies that the domain cannot be spoofed
(spoofing) in phishing campaigns. This module evaluates, in a 100% passive way
(via DNS over HTTPS):

- **SPF**: whether a `v=spf1` record exists and what the `all` mechanism is
  (`-all` strict, `~all` softfail, `?all`/`+all` insecure).
- **DKIM**: detects common selectors (`google`, `selector1/2`, `k1`…).
- **DMARC**: whether it exists and what policy `p=` publishes (reject/quarantine/none).
- **MX**: if the domain does not manage email, it is reported and the alarms are lowered.

It sends no email nor touches the target's mail server.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..models import Severity
from ..utils import doh_lookup, doh_txt, host_of, info
from .base import AuditModule

# DKIM selectors most used by common email providers
DKIM_SELECTORS = (
    "google", "default", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "mail", "dkim", "mandrill", "zoho", "mailchimp", "marketingcloud",
    "verifier", "protonmail", "smtp", "20230601", "20210112",
)


def _spf_eval(spf: Optional[str]) -> Dict:
    """Returns {'present': bool, 'all': str, 'hardfail': bool} for an SPF record."""
    if not spf:
        return {"present": False, "all": None, "hardfail": False}
    m = re.search(r"[-+~?]?all\b", spf, re.I)
    if not m:
        return {"present": True, "all": None, "hardfail": False}
    token = m.group(0).lower()
    return {"present": True, "all": token, "hardfail": "-all" in token}


def _dmarc_policy(record: str) -> str:
    m = re.search(r"\bp\s*=\s*(none|quarantine|reject)", record, re.I)
    return m.group(1).lower() if m else ""


class EmailsecModule(AuditModule):
    name = "emailsec"
    description = "Email posture: SPF, DKIM and DMARC (anti-spoofing)"

    def run(self):
        domain = host_of(self.ctx.target)
        if not domain:
            return
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain) or domain == "localhost":
            return  # only domains with public DNS

        info("Evaluating SPF / DKIM / DMARC…")

        # ---------------- MX: does the domain manage email?
        mx = [r for r in doh_lookup(domain, "MX")]
        self.assets["email_mx"] = mx
        if not mx:
            self.register(
                title="Domain without MX record (does not manage email)",
                description=f"'{domain}' has no mail servers (MX). The domain "
                            "probably does not send email; the authentication policies "
                            "would still be recommended for defense in depth.",
                severity=Severity.INFO, cwe="CWE-172", owasp="A04:2021",
                url=self.ctx.target, evidence="MX: (none)",
                remediation="If the domain does not send email, consider an SPF with -all and "
                            "a DMARC p=reject to block spoofing.")
            # Without a mail server there is not much more to evaluate
            self.assets["email_spf"] = "no_mx"
            self.assets["email_dmarc"] = "no_mx"
            self.assets["email_dkim"] = "no_mx"
            return

        # ---------------- SPF
        spf_recs = [r for r in doh_txt(domain) if r and r.lower().startswith("v=spf1")]
        spf_src = spf_recs[0] if spf_recs else None
        self.assets["email_spf_records"] = spf_recs
        spf = _spf_eval(spf_src)
        self.assets["email_spf"] = "ok" if spf["present"] else "missing"

        if not spf["present"]:
            self.register(
                title="SPF record missing (allows domain spoofing)",
                description="Without SPF, any server can send email on behalf "
                            f"of '{domain}' and the gateways will accept it.",
                severity=Severity.HIGH, cwe="CWE-172", owasp="A04:2021",
                url=self.ctx.target, evidence="TXT SPF: (none)",
                remediation=f"Publish a TXT record 'v=spf1 ... -all' for '{domain}'.")
        elif spf["all"] in ("+all", "?all", None):
            is_true_all = spf["all"] == "+all" or spf["all"] is None
            self.register(
                title="SPF withinsecure or missing 'all' policy",
                description=f"El SPF '{spf_src}' usa '{spf['all']}' (o no incluye "
                            "all mechanism): it does not reject unauthorized servers.",
                severity=Severity.MEDIUM if is_true_all else Severity.LOW,
                cwe="CWE-172", owasp="A04:2021", url=self.ctx.target,
                evidence=spf_src,
                remediation="Termina el SPF con '-all' (hardfail).")

        # ---------------- DMARC
        dmarc_recs = [r for r in doh_txt(f"_dmarc.{domain}")
                      if r and r.lower().startswith("v=dmarc")]
        dmarc = dmarc_recs[0] if dmarc_recs else None
        self.assets["email_dmarc"] = "ok" if dmarc else "missing"
        if dmarc:
            policy = _dmarc_policy(dmarc)
            self.assets["dmarc_policy"] = policy
            if policy == "none":
                self.register(
                    title="DMARC with p=none policy (no protection)",
                    description="DMARC exists but only monitors (p=none): spoofing "
                                "rejections are not applied.",
                    severity=Severity.MEDIUM, cwe="CWE-172", owasp="A04:2021",
                    url=self.ctx.target, evidence=dmarc,
                    remediation="Raise the policy to p=quarantine and finally p=reject, "
                                "with SPF/DKIM alignment and report aggregation.")
        else:
            self.register(
                title="DMARC record missing (unrestricted spoofing)",
                description="Without DMARC, recipients have no defined policy for "
                            "unauthorized emails; phishing with the client's domain "
                            "will be more credible.",
                severity=Severity.HIGH, cwe="CWE-172", owasp="A04:2021",
                url=self.ctx.target, evidence="_dmarc TXT: (none)",
                remediation=f"Publish a '_dmarc.{domain}' record with p=reject.")

        # ---------------- DKIM
        present_selectors = []
        for sel in DKIM_SELECTORS:
            if len(present_selectors) >= 3:
                break
            txts = doh_txt(f"{sel}._domainkey.{domain}")
            if any("v=DKIM1" in r or "p=" in r for r in txts):
                present_selectors.append(sel)
        self.assets["email_dkim_selectors"] = present_selectors
        self.assets["email_dkim"] = "ok" if present_selectors else "missing"
        if present_selectors:
            self.log("DKIM selectors: " + ", ".join(present_selectors))
        else:
            self.register(
                title="DKIM not detected (common selectors missing)",
                description="No DKIM keys found in the most commonly used selectors. "
                            "Outbound mail is not signed, which facilitates "
                            "domain forgery in the From header.",
                severity=Severity.MEDIUM, cwe="CWE-172", owasp="A04:2021",
                url=self.ctx.target,
                evidence="Selectors tested: " + ", ".join(DKIM_SELECTORS[:14]),
                remediation=f"Configure DKIM with your email provider and publish the "
                            f"key in '<selector>._domainkey.{domain}'.")