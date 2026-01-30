#!/usr/bin/env python3
"""
VirusTotal Batch Scanner

Scans downloaded files in the database using VirusTotal API.
Useful for processing existing downloads that haven't been scanned yet.
"""
import sys
import os
import argparse
import logging
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import config
from backend.database.db_manager import DatabaseManager
from backend.analyzers import VirusTotalAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DownloadScanner:
    """Batch scan downloads with VirusTotal"""

    def __init__(self):
        self.db_manager = DatabaseManager()

        if not config.VIRUSTOTAL_API_KEY:
            raise ValueError("VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env")

        self.vt_analyzer = VirusTotalAnalyzer(
            api_key=config.VIRUSTOTAL_API_KEY,
            rate_limit=config.VIRUSTOTAL_RATE_LIMIT
        )

    def scan_unscanned(self, limit: int = 100) -> dict:
        """Scan downloads that haven't been analyzed yet"""
        downloads = self.db_manager.get_unscanned_downloads(limit=limit)

        if not downloads:
            logger.info("No unscanned downloads found")
            return {'scanned': 0, 'malware': 0, 'clean': 0, 'not_found': 0}

        logger.info(f"Found {len(downloads)} unscanned downloads")

        stats = {'scanned': 0, 'malware': 0, 'clean': 0, 'not_found': 0}

        for download in downloads:
            if not download.file_hash:
                continue

            logger.info(f"Scanning: {download.file_hash[:16]}...")

            result = self.vt_analyzer.analyze_hash(download.file_hash)

            if result:
                stats['scanned'] += 1

                if result.get('found'):
                    is_malware = result.get('is_malware', False)
                    detection_ratio = result.get('detection_ratio', '0/0')

                    self.db_manager.update_download_virustotal(
                        download.id,
                        is_malware,
                        detection_ratio
                    )

                    if is_malware:
                        stats['malware'] += 1
                        threat_name = result.get('popular_threat_names', 'Unknown')
                        logger.warning(f"  MALWARE: {threat_name} ({detection_ratio})")
                    else:
                        stats['clean'] += 1
                        logger.info(f"  Clean ({detection_ratio})")
                else:
                    stats['not_found'] += 1
                    logger.info(f"  Not found in VirusTotal database")

        return stats

    def scan_hash(self, file_hash: str) -> dict:
        """Scan a specific file hash"""
        logger.info(f"Scanning hash: {file_hash}")

        result = self.vt_analyzer.analyze_hash(file_hash)

        if result:
            # Update database if we have this hash
            download = self.db_manager.get_download_by_hash(file_hash)
            if download and result.get('found'):
                self.db_manager.update_download_virustotal(
                    download.id,
                    result.get('is_malware', False),
                    result.get('detection_ratio', '')
                )
                logger.info("Database updated")

            return result
        return {}

    def rescan_all(self, limit: int = 100) -> dict:
        """Rescan all downloads (including previously scanned)"""
        downloads = self.db_manager.get_recent_downloads(limit=limit)

        if not downloads:
            logger.info("No downloads found")
            return {'scanned': 0, 'malware': 0, 'clean': 0, 'not_found': 0}

        logger.info(f"Rescanning {len(downloads)} downloads")

        stats = {'scanned': 0, 'malware': 0, 'clean': 0, 'not_found': 0}

        for download in downloads:
            if not download.file_hash:
                continue

            logger.info(f"Scanning: {download.file_hash[:16]}...")

            result = self.vt_analyzer.analyze_hash(download.file_hash)

            if result:
                stats['scanned'] += 1

                if result.get('found'):
                    is_malware = result.get('is_malware', False)
                    detection_ratio = result.get('detection_ratio', '0/0')

                    self.db_manager.update_download_virustotal(
                        download.id,
                        is_malware,
                        detection_ratio
                    )

                    if is_malware:
                        stats['malware'] += 1
                        logger.warning(f"  MALWARE: {result.get('popular_threat_names', 'Unknown')}")
                    else:
                        stats['clean'] += 1
                        logger.info(f"  Clean ({detection_ratio})")
                else:
                    stats['not_found'] += 1
                    logger.info(f"  Not found in VirusTotal")

        return stats

    def get_stats(self) -> dict:
        """Get current download/malware statistics"""
        return self.db_manager.get_download_stats()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Scan downloads with VirusTotal')

    parser.add_argument(
        '--scan-unscanned',
        action='store_true',
        help='Scan downloads not yet analyzed'
    )

    parser.add_argument(
        '--rescan-all',
        action='store_true',
        help='Rescan all downloads (including previously scanned)'
    )

    parser.add_argument(
        '--hash',
        type=str,
        help='Scan a specific file hash'
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show download/malware statistics'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum number of files to scan (default: 100)'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("VirusTotal Download Scanner")
    print("=" * 60)

    try:
        scanner = DownloadScanner()
    except ValueError as e:
        print(f"\nError: {e}")
        print("\nTo configure VirusTotal:")
        print("1. Get a free API key at https://www.virustotal.com/gui/join-us")
        print("2. Add VIRUSTOTAL_API_KEY=your_key to .env file")
        sys.exit(1)

    if args.stats:
        stats = scanner.get_stats()
        print("\nDownload Statistics:")
        print(f"  Total downloads: {stats['total_downloads']}")
        print(f"  Scanned: {stats['scanned_count']}")
        print(f"  Unscanned: {stats['unscanned_count']}")
        print(f"  Malware detected: {stats['malware_detected']}")
        print(f"  Unique files: {stats['unique_files']}")
        print(f"  Malware rate: {stats['malware_rate']}%")

    elif args.hash:
        result = scanner.scan_hash(args.hash)
        if result:
            print(f"\nVirusTotal Result for {args.hash}:")
            if result.get('found'):
                print(f"  Threat Level: {result.get('threat_level', 'unknown').upper()}")
                print(f"  Detection: {result.get('detection_ratio', 'N/A')}")
                print(f"  Threat Name: {result.get('popular_threat_names', 'N/A')}")
                print(f"  File Type: {result.get('file_type', 'N/A')}")
                print(f"  VT Link: {result.get('vt_link', 'N/A')}")
            else:
                print("  File not found in VirusTotal database")
        else:
            print("\nScan failed")

    elif args.rescan_all:
        print(f"\nRescanning up to {args.limit} downloads...")
        stats = scanner.rescan_all(limit=args.limit)
        print(f"\nResults:")
        print(f"  Scanned: {stats['scanned']}")
        print(f"  Malware: {stats['malware']}")
        print(f"  Clean: {stats['clean']}")
        print(f"  Not in VT: {stats['not_found']}")

    else:
        # Default: scan unscanned
        print(f"\nScanning up to {args.limit} unscanned downloads...")
        stats = scanner.scan_unscanned(limit=args.limit)
        print(f"\nResults:")
        print(f"  Scanned: {stats['scanned']}")
        print(f"  Malware: {stats['malware']}")
        print(f"  Clean: {stats['clean']}")
        print(f"  Not in VT: {stats['not_found']}")


if __name__ == '__main__':
    main()
