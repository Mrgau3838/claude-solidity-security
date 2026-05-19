#!/usr/bin/env python3
"""
Maps Slither detector findings to SCSVS domain IDs.
Usage: python3 parse-findings.py slither-output.json
"""

import json
import sys
from collections import defaultdict

# Deterministic mapping: Slither detector name → SCSVS requirement IDs
DETECTOR_TO_SCSVS = {
    # S3: Business Logic / Reentrancy
    "reentrancy-eth": ["S3.3.A4", "S3.3.A1"],
    "reentrancy-no-eth": ["S3.3.A4", "S3.3.A1"],
    "reentrancy-benign": ["S3.3.A4"],
    "reentrancy-events": ["S3.3.A4"],
    "reentrancy-unlimited-gas": ["S3.3.A4"],

    # S4: Access Control
    "tx-origin": ["S4.2.A1", "S4.1.C1"],
    "controlled-delegatecall": ["S4.2.A4", "S5.1.A3"],
    "abiencoderv2-array": ["S9.1.A4"],
    "arbitrary-send-eth": ["S4.2.A3"],
    "arbitrary-send-erc20": ["S4.2.A3"],
    "protected-vars": ["S4.1.A1"],
    "unprotected-upgrade": ["S1.2.A5"],

    # S5: Interactions
    "unchecked-lowlevel": ["S5.1.A1"],
    "unchecked-send": ["S5.1.A1"],
    "unchecked-transfer": ["S5.1.A1", "S11.1.A6"],
    "delegatecall-loop": ["S5.1.A3"],
    "msg-value-loop": ["S5.1.A1"],
    "calls-loop": ["S8.1.A3"],

    # S6: Cryptography
    "weak-prng": ["S6.3.A1", "S6.3.A2"],

    # S7: Arithmetic
    "divide-before-multiply": ["S7.2.B1"],
    "tautology": ["S7.2.A7", "S7.2.A9"],
    "integer-overflow": ["S7.1.A2"],
    "incorrect-equality": ["S7.2.A7"],
    "boolean-cst": ["S7.2.A9"],

    # S8: DoS
    "costly-loop": ["S8.1.A3", "S8.1.A4"],
    "block-gas-limit": ["S8.1.A4"],

    # S9: State Management
    "write-after-write": ["S9.1.B1"],
    "dead-code": ["S2.2.A5"],
    "unused-return": ["S5.1.A1"],
    "events-access": ["S9.3.A1"],
    "events-maths": ["S9.3.A1"],
    "missing-zero-check": ["S4.1.A2"],

    # S1: Architecture
    "suicidal": ["S1.1.A3"],
    "locked-ether": ["S9.1.A1"],
    "shadowing-state": ["S2.2.A3"],
    "shadowing-local": ["S2.2.A3"],
    "shadowing-builtin": ["S2.2.A3"],

    # S2: Code Management
    "pragma": ["S2.1.A1", "S2.1.A2"],
    "solc-version": ["S2.1.A1"],
    "low-level-calls": ["S5.1.A1"],
    "naming-convention": ["S2.2.A3"],
    "assembly": ["S2.1.A4"],

    # S11: Component-specific
    "erc20-interface": ["S11.1.A6"],
    "erc721-interface": ["S11.2.A1"],
    "erc20-indexed": ["S11.1.A6"],
    "uninitialized-local": ["S1.2.A4"],
    "uninitialized-state": ["S9.1.A1"],
    "uninitialized-storage": ["S9.1.A1"],
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Optimization": 4}

def parse_slither_output(filepath):
    with open(filepath) as f:
        data = json.load(f)

    findings = []
    results = data.get("results", {}).get("detectors", [])

    for det in results:
        detector = det.get("check", "unknown")
        description = det.get("description", "").strip()
        severity = det.get("impact", "Informational")
        confidence = det.get("confidence", "")
        elements = det.get("elements", [])

        # Collect locations
        locations = []
        for el in elements:
            src = el.get("source_mapping", {})
            filename = src.get("filename_relative", "")
            lines = src.get("lines", [])
            if filename and lines:
                locations.append(f"{filename}:{lines[0]}")

        scsvs_ids = DETECTOR_TO_SCSVS.get(detector, [])

        findings.append({
            "detector": detector,
            "severity": severity,
            "confidence": confidence,
            "scsvs": scsvs_ids,
            "description": description[:200],
            "locations": locations[:3],
        })

    return findings


def render_report(findings):
    if not findings:
        print("No findings.")
        return

    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f["severity"]].append(f)

    total = len(findings)
    print(f"\n{'='*60}")
    print(f"SLITHER → SCSVS MAPPING REPORT")
    print(f"{'='*60}")
    print(f"Total findings: {total}")
    for sev in ["High", "Medium", "Low", "Informational", "Optimization"]:
        count = len(by_severity.get(sev, []))
        if count:
            print(f"  {sev}: {count}")
    print()

    for sev in ["High", "Medium", "Low", "Informational", "Optimization"]:
        group = by_severity.get(sev, [])
        if not group:
            continue
        print(f"{'─'*60}")
        print(f"[{sev.upper()}] — {len(group)} finding(s)")
        print(f"{'─'*60}")
        for f in group:
            scsvs_str = ", ".join(f["scsvs"]) if f["scsvs"] else "No direct mapping"
            print(f"\n  Detector : {f['detector']}")
            print(f"  SCSVS    : {scsvs_str}")
            print(f"  Confidence: {f['confidence']}")
            if f["locations"]:
                print(f"  Location : {'; '.join(f['locations'])}")
            print(f"  Description: {f['description'][:120]}{'...' if len(f['description']) > 120 else ''}")
    print()

    # Summary: all unique SCSVS IDs found
    all_scsvs = sorted(set(sid for f in findings for sid in f["scsvs"]))
    if all_scsvs:
        print(f"{'='*60}")
        print("SCSVS REQUIREMENTS WITH FINDINGS:")
        print(f"{'='*60}")
        for sid in all_scsvs:
            print(f"  FAIL: {sid}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse-findings.py <slither-output.json>")
        sys.exit(1)

    filepath = sys.argv[1]
    try:
        findings = parse_slither_output(filepath)
        render_report(findings)
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}")
        sys.exit(1)
