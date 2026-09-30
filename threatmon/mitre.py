"""
ARGUS - MITRE ATT&CK technique catalogue for the detection suite.

One place that names the techniques ARGUS claims to watch, so the audit log's
tags and the SECURITY panel's coverage grid can never drift from each other:
both read this table. A technique is listed here whether or not its detector
has shipped yet -- the "provider" column says which detector supplies it, and
the coordinator (threatmon.__init__) decides at runtime whether that provider
is actually alive. That is what lets the UI grid grow from grey to green as
real detections come online instead of being a hand-maintained decoration.

Deliberately NOT an ever-expanding ruleset: this is a fixed, documented set of
the techniques the suite is scoped to. Adding a row is a deliberate act tied to
shipping a detector, not a place to accrete signatures.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.


# id -> (name, tactic, provider-key)
#
# provider-key matches the key a detector reports in threatmon.status(); the
# coordinator marks a technique "active" only when its provider is present and
# not in a failed state. "provider" None means the technique is catalogued for

TECHNIQUES = {
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access", "lsass"),
    # T1562 (unqualified) stays with tamper, which watches ARGUS's OWN
    # protection. The two sub-techniques below are the OS's protections --
    # Defender, the firewall -- and belong to a different detector, so they are
    # listed separately rather than folded into the parent. A grid row that
    # went green because a sibling detector was alive would be a lie about
    # coverage.
    "T1562":     ("Impair Defenses", "Defense Evasion", "tamper"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools",
                  "Defense Evasion", "defenses"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall",
                  "Defense Evasion", "defenses"),
    "T1548.002": ("Abuse Elevation Control Mechanism: Bypass User Account Control",
                  "Privilege Escalation", "defenses"),
    "T1083":     ("File and Directory Discovery", "Discovery", "canary"),
    "T1059":     ("Command and Scripting Interpreter", "Execution", "lolbin"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution", "lolbin"),
    "T1105":     ("Ingress Tool Transfer", "Command and Control", "lolbin"),
    "T1218":     ("System Binary Proxy Execution", "Defense Evasion", "lolbin"),
    "T1115":     ("Clipboard Data", "Collection", "clipboard"),
    "T1565.002": ("Transmitted Data Manipulation", "Impact", "clipboard"),
    "T1547.001": ("Boot or Logon Autostart: Registry Run Keys / Startup Folder",
                  "Persistence", "persistence"),
    "T1547.004": ("Boot or Logon Autostart: Winlogon Helper DLL",
                  "Persistence", "persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service",
                  "Persistence", "persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence", "persistence"),
    # Covered since 1.2.0: threatmon/wmisubs.py reads root\subscription via
    # comtypes (the dependency collect_tasks already used for the scheduler),
    # and persistence.py's collectors include it as the "wmi" surface. The
    # provider column is what turns the grid cell green -- and it stays honest
    # because the coordinator marks it active only when the surface scanned.
    "T1546.003": ("Event Triggered Execution: WMI Event Subscription",
                  "Persistence", "persistence"),
    # 1.4.1: the audit's "silently absent" persistence surfaces, each now a
    # real collector in persistence.py (diff engine, baseline, flood guard all
    # inherited). Added to the catalogue the same commit the detectors shipped,
    # so the grid never claims a row without a provider behind it.
    "T1546.012": ("Event Triggered Execution: Image File Execution Options "
                  "Injection", "Persistence", "persistence"),
    "T1546.015": ("Event Triggered Execution: Component Object Model Hijacking",
                  "Persistence", "persistence"),
    "T1037.001": ("Boot or Logon Initialization Scripts: Logon Script "
                  "(Windows)", "Persistence", "persistence"),
    "T1547.005": ("Boot or Logon Autostart Execution: Security Support Provider",
                  "Persistence", "persistence"),
    "T1546.010": ("Event Triggered Execution: AppInit DLLs",
                  "Persistence", "persistence"),
    # A listener that appeared since the baseline. T1571 is the closest honest
    # fit -- the sentinel grades on BIND SCOPE rather than on port number (see
    # threatmon/listening.py), so "non-standard port" understates it slightly,
    # but the tactic is right and inventing an id would be worse.
    "T1571":     ("Non-Standard Port (new network listener)",
                  "Command and Control", "listening"),
    "T1021":     ("Remote Services (exposed remote-access port)",
                  "Lateral Movement", "listening"),
    "T1123":     ("Audio Capture", "Collection", "privacy"),
    "T1125":     ("Video Capture", "Collection", "privacy"),
    "T1565.001": ("Stored Data Manipulation (hosts file)", "Impact", "netconfig"),
    "T1557":     ("Adversary-in-the-Middle (DNS redirection)",
                  "Credential Access", "netconfig"),
    # 1.4.1: trust-anchor watch -- a rogue root CA (HKCU needs no admin) is the
    # enabler that makes the MitM above invisible. The collector diffs the
    # thumbprint set of the user and machine certificate stores.
    "T1553.004": ("Subvert Trust Controls: Install Root Certificate",
                  "Defense Evasion", "netconfig"),
    "T1090":     ("Proxy (injected proxy / PAC file)",
                  "Command and Control", "netconfig"),
    # The resource-anomaly detector that predates this suite. No formal ATT&CK
    # id fits a "process is using far more CPU/RAM than its own baseline"
    # signal cleanly; catalogued so the grid acknowledges it exists rather than
    # implying it is unmonitored.
    "TA0040":    ("Resource Anomaly (baseline deviation)", "Impact", "anomaly"),
}


def name(tid: str) -> str:
    """Human-readable name for a technique id, or the id itself if unknown."""
    row = TECHNIQUES.get(tid)
    return row[0] if row else tid


def tactic(tid: str) -> str:
    row = TECHNIQUES.get(tid)
    return row[1] if row else ""


def provider(tid: str) -> str:
    row = TECHNIQUES.get(tid)
    return row[2] if row else ""


def for_provider(prov: str) -> list:
    """All technique ids a given detector supplies."""
    return [tid for tid, row in TECHNIQUES.items() if row[2] == prov]


def is_valid(tid: str) -> bool:
    return tid in TECHNIQUES


def grid(active_providers: set) -> list:
    """The coverage grid the SECURITY panel renders.

    Returns rows sorted by id, each {id, name, tactic, active}. active is True
    when the technique's provider is currently live (per the coordinator). The
    UI colours active green and the rest grey.
    """
    out = []
    for tid in sorted(TECHNIQUES):
        nm, tac, prov = TECHNIQUES[tid]
        out.append({
            "id": tid, "name": nm, "tactic": tac,
            "active": bool(prov) and prov in active_providers,
        })
    return out
