#!/usr/bin/env python3
"""SkillGuard Audit Script - Submit URL and display results in terminal."""
import sys
import time
import requests

API_BASE = "http://localhost:8011"

def audit_skill(url: str):
    print(f"🔍 Submitting scan for: {url}")
    resp = requests.post(f"{API_BASE}/api/scan", json={"github_url": url})
    if resp.status_code != 200:
        print(f"❌ Error: {resp.text}")
        sys.exit(1)

    scan_id = resp.json()["scan_id"]
    print(f"📋 Scan ID: {scan_id}")
    print("⏳ Waiting for results...\n")

    while True:
        status_resp = requests.get(f"{API_BASE}/api/scan/{scan_id}/status")
        data = status_resp.json()
        status = data["status"]

        if status == "done":
            break
        elif status == "error":
            print(f"❌ Scan failed: {data.get('error', 'Unknown error')}")
            sys.exit(1)

        print(f"  Status: {status} ({data.get('progress', 0)}%)")
        time.sleep(2)

    scan_resp = requests.get(f"{API_BASE}/api/report/{scan_id}")
    data = scan_resp.json()

    print("\n" + "="*60)
    print(f"  SkillGuard Security Report")
    print("="*60)
    print(f"Skill: {data.get('skill_name', 'N/A')}")
    print(f"Grade: {data.get('risk_level', 'N/A')}")
    print(f"Risk Score: {data.get('risk_score', 0)}/100")

    findings = data.get("findings", [])
    print(f"Total Findings: {len(findings)}")

    risk_dist = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        risk_dist[sev] = risk_dist.get(sev, 0) + 1

    if risk_dist:
        print(f"\nRisk Breakdown:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = risk_dist.get(sev, 0)
            if count > 0:
                print(f"  {sev}: {count}")

    if findings:
        print(f"\n🔴 Top Findings:")
        for f in findings[:5]:
            print(f"  [{f['severity']}] {f['dimension']}: {f['description'][:60]}...")

    print(f"\n📊 Full report: {API_BASE}/report/{scan_id}")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 audit.py <github_or_clawhub_url>")
        sys.exit(1)
    audit_skill(sys.argv[1])
