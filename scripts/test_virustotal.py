#!/usr/bin/env python3
"""
Quick test for VirusTotal integration
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import config
from backend.analyzers import VirusTotalAnalyzer


def main():
    print("=" * 60)
    print("VirusTotal Integration Test")
    print("=" * 60)

    # Check configuration
    print(f"\nAPI Key configured: {'Yes' if config.VIRUSTOTAL_API_KEY else 'No'}")
    print(f"Integration enabled: {config.VIRUSTOTAL_ENABLED}")
    print(f"Rate limiting: {config.VIRUSTOTAL_RATE_LIMIT}")

    if not config.VIRUSTOTAL_API_KEY:
        print("\nError: No API key configured. Add VIRUSTOTAL_API_KEY to .env")
        return

    # Initialize analyzer
    vt = VirusTotalAnalyzer(
        api_key=config.VIRUSTOTAL_API_KEY,
        rate_limit=config.VIRUSTOTAL_RATE_LIMIT
    )

    print(f"\nAnalyzer enabled: {vt.is_enabled}")

    # Test with a known malware hash (EICAR test file)
    # This is a standard test file, not actual malware
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    print(f"\nTesting with EICAR test file hash...")
    print(f"Hash: {eicar_hash[:32]}...")

    result = vt.analyze_hash(eicar_hash)

    if result:
        print("\n[OK] VirusTotal API is working!")
        print(f"\nResults:")
        print(f"  Found: {result.get('found', False)}")

        if result.get('found'):
            print(f"  Threat Level: {result.get('threat_level', 'unknown').upper()}")
            print(f"  Detection Ratio: {result.get('detection_ratio', 'N/A')}")
            print(f"  Is Malware: {result.get('is_malware', False)}")
            print(f"  Threat Name: {result.get('popular_threat_names', 'N/A')}")
            print(f"  File Type: {result.get('file_type', 'N/A')}")
            print(f"\n  VT Link: {result.get('vt_link', 'N/A')}")
    else:
        print("\n[FAIL] VirusTotal API test failed")
        print("Check your API key and network connection")


if __name__ == '__main__':
    main()
