#!/usr/bin/env python3
"""
Quick test for Threat Intelligence integration
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import config
from backend.analyzers import ThreatIntelligenceManager, AbuseIPDBAnalyzer, ShodanAnalyzer


def main():
    print("=" * 60)
    print("Threat Intelligence Integration Test")
    print("=" * 60)

    # Check configuration
    print(f"\nAbuseIPDB API Key: {'Configured' if config.ABUSEIPDB_API_KEY else 'Not configured'}")
    print(f"AbuseIPDB Enabled: {config.ABUSEIPDB_ENABLED}")
    print(f"\nShodan API Key: {'Configured' if config.SHODAN_API_KEY else 'Not configured'}")
    print(f"Shodan Enabled: {config.SHODAN_ENABLED}")

    # Test IP - Known bad IP (Tor exit node commonly reported)
    # Using a safe test IP
    test_ip = "185.220.101.1"  # Known Tor exit node

    print(f"\n{'=' * 60}")
    print(f"Testing with IP: {test_ip}")
    print("=" * 60)

    # Test AbuseIPDB
    if config.ABUSEIPDB_API_KEY:
        print("\n[Testing AbuseIPDB]")
        abuseipdb = AbuseIPDBAnalyzer(
            api_key=config.ABUSEIPDB_API_KEY,
            rate_limit=True
        )

        result = abuseipdb.check_ip(test_ip)
        if result:
            print("[OK] AbuseIPDB is working!")
            print(f"  Abuse Score: {result.get('abuse_confidence_score', 0)}%")
            print(f"  Total Reports: {result.get('total_reports', 0)}")
            print(f"  Threat Level: {result.get('threat_level', 'unknown').upper()}")
            print(f"  Is Tor Exit: {result.get('is_tor', False)}")
            print(f"  ISP: {result.get('isp', 'N/A')}")
            print(f"  Link: {result.get('abuseipdb_link', 'N/A')}")
        else:
            print("[FAIL] AbuseIPDB test failed")
    else:
        print("\n[SKIP] AbuseIPDB - No API key configured")

    # Test Shodan
    if config.SHODAN_API_KEY:
        print("\n[Testing Shodan]")
        shodan = ShodanAnalyzer(
            api_key=config.SHODAN_API_KEY,
            rate_limit=True
        )

        result = shodan.get_host_info(test_ip)
        if result:
            print("[OK] Shodan is working!")
            if result.get('found'):
                print(f"  Organization: {result.get('org', 'N/A')}")
                print(f"  ISP: {result.get('isp', 'N/A')}")
                print(f"  Country: {result.get('country', 'N/A')}")
                print(f"  Open Ports: {result.get('ports', [])}")
                print(f"  Vulnerabilities: {result.get('vuln_count', 0)}")
                print(f"  OS: {result.get('os', 'N/A')}")
                print(f"  Risk Level: {result.get('risk_level', 'unknown').upper()}")
                print(f"  Link: {result.get('shodan_link', 'N/A')}")
            else:
                print(f"  IP not found in Shodan database")
        else:
            print("[FAIL] Shodan test failed")
    else:
        print("\n[SKIP] Shodan - No API key configured")

    # Test Combined Intelligence
    if config.ABUSEIPDB_API_KEY or config.SHODAN_API_KEY:
        print("\n[Testing Combined Threat Intelligence]")
        threat_intel = ThreatIntelligenceManager(
            abuseipdb_key=config.ABUSEIPDB_API_KEY if config.ABUSEIPDB_ENABLED else None,
            shodan_key=config.SHODAN_API_KEY if config.SHODAN_ENABLED else None,
            rate_limit=True
        )

        result = threat_intel.enrich_ip(test_ip)
        if result:
            print("[OK] Combined threat intelligence is working!")
            print(f"  Sources: {', '.join(result.get('sources', []))}")

            assessment = result.get('threat_assessment', {})
            print(f"\n  Overall Assessment:")
            print(f"    Threat Level: {assessment.get('threat_level', 'unknown').upper()}")
            print(f"    Threat Score: {assessment.get('overall_score', 0)}/100")

            indicators = assessment.get('indicators', [])
            if indicators:
                print(f"    Indicators:")
                for ind in indicators:
                    print(f"      - {ind}")

            print(f"\n    Recommendation: {assessment.get('recommendation', 'N/A')}")
        else:
            print("[FAIL] Combined threat intelligence test failed")

    print("\n" + "=" * 60)
    print("Test complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
