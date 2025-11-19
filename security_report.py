#!/usr/bin/env python3
"""
Security Report Generator for Wazuh Multi-Tenant Environment

Generates monthly security reports including:
1. Vulnerability Tracking (1st vs 30th comparison)
2. Security Incident Reporting (Level 12+ alerts)
3. Access Auditing (USA vs International, VPN activity)

USAGE:
  Capture baseline:    python3 security_report.py --snapshot
  Generate report:     python3 security_report.py
"""

import sys
import logging
import os
import argparse
from datetime import datetime
from typing import Dict, Any

import yaml
from dotenv import load_dotenv

from wazuh_connector import WazuhScanner
from email_reporter import EmailReporter
from snapshot_manager import SnapshotManager
from analysis import SecurityAnalyzer
from excel_generator import SecurityExcelGenerator

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self):
        self.config = self._load_config()
        self.wazuh = WazuhScanner(self.config['dashboard'])
        self.email_reporter = EmailReporter(
            smtp_server=self.config['email_server'],
            smtp_port=self.config['email_port'],
            sender=self.config['email_sender'],
            password=self.config['email_password']
        )
        self.snapshot_manager = SnapshotManager(self.wazuh)
        self.analyzer = SecurityAnalyzer()
        self.excel_generator = SecurityExcelGenerator()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        return {
            'email_server': os.getenv('EMAIL_SERVER'),
            'email_port': int(os.getenv('EMAIL_PORT', 25)),
            'email_sender': os.getenv('EMAIL_SENDER'),
            'email_password': os.getenv('EMAIL_PASSWORD', ''),
            'dashboard': {
                'host': os.getenv('WAZUH_HOST'),
                'port': int(os.getenv('WAZUH_PORT', 9200)),
                'username': os.getenv('WAZUH_USERNAME'),
                'password': os.getenv('WAZUH_PASSWORD'),
                'verify_ssl': os.getenv('WAZUH_VERIFY_SSL', 'false').lower() == 'true'
            },
            'clients': yaml.safe_load(os.getenv('CLIENTS_CONFIG', 'clients: {}') or {}).get('clients', {})
        }
    
    def fetch_alerts_paginated(self, client_name: str, start_date: str, end_date: str,
                              min_level: int = 12, batch_size: int = 10000,
                              max_alerts: int = None, timeout_minutes: int = 30):
        """
        Fetch alerts with pagination, excluding noise
        
        Args:
            client_name: Client identifier
            start_date: Start date for alert query
            end_date: End date for alert query
            min_level: Minimum alert level (default 12)
            batch_size: Number of alerts per request (default 10,000)
            max_alerts: Maximum total alerts to fetch (None = unlimited)
            timeout_minutes: Maximum time to spend fetching (default 30 min)
        
        Returns:
            List of alert dictionaries
        """
        excluded_rules = [
            "Office 365: Phishing and malware events from Exchange Online Protection and Microsoft Defender for Office 365.",
            "Agent event queue is flooded. Check the agent configuration."
        ]
        
        all_alerts = []
        search_after = None
        start_time = datetime.now()
        iterations = 0
        
        must_not_clauses = [{"term": {"data.vulnerability.classification": "CVSS"}}]
        for desc in excluded_rules:
            must_not_clauses.append({"match_phrase": {"rule.description": desc}})
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_date, "lte": end_date}}},
                        {"range": {"rule.level": {"gte": min_level}}}
                    ],
                    "must_not": must_not_clauses
                }
            },
            "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
            "size": batch_size
        }
        
        logger.info(f"Fetching alerts for {client_name} from {start_date} to {end_date} (Level {min_level}+)")
        if max_alerts:
            logger.info(f"  Max alerts limit: {max_alerts:,}")
        
        while True:
            # Check timeout
            elapsed_minutes = (datetime.now() - start_time).total_seconds() / 60
            if elapsed_minutes > timeout_minutes:
                logger.warning(f"  Timeout reached ({timeout_minutes} min). Fetched {len(all_alerts):,} alerts so far.")
                logger.warning(f"   Consider reducing date range or increasing timeout.")
                break
            
            # Check max alerts limit
            if max_alerts and len(all_alerts) >= max_alerts:
                logger.warning(f"  Max alerts limit reached ({max_alerts:,}). Stopping fetch.")
                break
            
            if search_after:
                query["search_after"] = search_after
            
            try:
                response = self.wazuh.search_client_alerts(client_name, query)
            except Exception as e:
                logger.error(f" Error fetching alerts: {e}")
                break
            
            if not response or 'hits' not in response or 'hits' not in response['hits']:
                break
            
            hits = response['hits']['hits']
            if not hits:
                break
            
            # Add alerts to list
            all_alerts.extend([hit.get('_source', {}) for hit in hits])
            search_after = hits[-1].get('sort')
            iterations += 1
            
            # Progress indicator every 10 iterations (100k alerts)
            if iterations % 10 == 0:
                elapsed_sec = (datetime.now() - start_time).total_seconds()
                rate = len(all_alerts) / elapsed_sec if elapsed_sec > 0 else 0
                logger.info(f"  Progress: {len(all_alerts):,} alerts | {rate:.0f} alerts/sec | {elapsed_sec:.1f}s elapsed")
            
            # If we got less than batch_size, we're done
            if len(hits) < batch_size:
                break
        
        logger.info(f" Total alerts fetched: {len(all_alerts):,} in {iterations} requests")
        return all_alerts
    
    def capture_baseline_snapshot(self, client_name: str, client_config: Dict[str, Any]):
        """Capture and save baseline vulnerability snapshot"""
        display_name = client_config.get('display_name', client_name.upper())
        today = datetime.now().strftime("%Y-%m-%d")
        
        logger.info("")
        logger.info("=" * 60)
        logger.info(f"Capturing Baseline Snapshot: {display_name}")
        logger.info(f"Date: {today}")
        logger.info("=" * 60)
        logger.info("")
        
        logger.info("Fetching vulnerability data...")
        snapshot = self.snapshot_manager.fetch(client_name, today)
        self.snapshot_manager.save(client_name, snapshot)
        
        logger.info(f"\n Baseline captured: {snapshot['total']} vulnerabilities")
        logger.info(f"   Critical: {snapshot['by_severity'].get('Critical', 0)}")
        logger.info(f"   High: {snapshot['by_severity'].get('High', 0)}")
        logger.info(f"   Medium: {snapshot['by_severity'].get('Medium', 0)}")
        logger.info(f"   Low: {snapshot['by_severity'].get('Low', 0)}")
        logger.info("")
    
    def run_monthly_report(self, client_name: str, client_config: Dict[str, Any]):
        """Generate monthly security report for a specific client"""
        display_name = client_config.get('display_name', client_name.upper())
        now = datetime.now()
        report_month = now.strftime("%B %Y")
        year, month = now.year, now.month
        
        logger.info("")
        logger.info("=" * 60)
        logger.info(f"Generating Security Report: {display_name}")
        logger.info(f"Period: {report_month}")
        logger.info("=" * 60)
        logger.info("")
        
        # Create output folder
        client_folder = f"reports/{client_name}"
        os.makedirs(client_folder, exist_ok=True)
        logger.info(f"Output folder: {client_folder}")
        
        # Load or create baseline snapshot
        baseline_date = f"{year}-{month:02d}-01"
        vuln_start = self.snapshot_manager.load(client_name, baseline_date)
        
        if vuln_start is None:
            logger.warning(f"  No baseline snapshot found for {baseline_date}")
            logger.warning(f"   Run 'python3 security_report.py --snapshot' on the 1st to capture baseline")
            logger.info(f"   Using current data as baseline for this report...")
            vuln_start = self.snapshot_manager.fetch(client_name, baseline_date)
            self.snapshot_manager.save(client_name, vuln_start)
        
        # Fetch current vulnerability state
        logger.info("Fetching current vulnerability data...")
        vuln_current = self.snapshot_manager.fetch(client_name, now.strftime("%Y-%m-%d"))
        
        # Fetch alerts
        start_date = f"{year}-{month:02d}-01T00:00:00"
        end_date = now.strftime("%Y-%m-%dT%H:%M:%S")
        
        logger.info(f"Fetching high-level alerts (Level 12+)...")
        alerts = self.fetch_alerts_paginated(
            client_name, start_date, end_date, 
            min_level=12,
            max_alerts=100000,  # Limit to 100k high-level alerts
            timeout_minutes=15
        )
        
        logger.info(f"Fetching login events (Level 3+)...")
        login_alerts = self.fetch_alerts_paginated(
            client_name, start_date, end_date, 
            min_level=3,
            max_alerts=1000000,  # Limit to 1M login events
            timeout_minutes=30
        )
        
        if not alerts and not login_alerts and vuln_start['total'] == 0 and vuln_current['total'] == 0:
            logger.warning(f"No data found for {client_name}")
            return
        
        # Analyze data
        logger.info("Analyzing security incidents...")
        alert_analysis = self.analyzer.analyze_alerts(alerts) if alerts else self._empty_alert_analysis()
        
        logger.info("Analyzing access patterns...")
        access_analysis = self.analyzer.analyze_access_patterns(login_alerts) if login_alerts else self._empty_access_analysis()
        
        # Generate Excel report
        logger.info("Generating Excel report...")
        report_file = self.excel_generator.generate_report(
            client_name=client_name,
            display_name=display_name,
            alert_analysis=alert_analysis,
            access_analysis=access_analysis,
            vuln_start=vuln_start,
            vuln_current=vuln_current,
            report_month=report_month,
            output_folder=client_folder
        )
        
        # Send email
        email_recipients = client_config.get('email_recipients', [])
        if email_recipients:
            logger.info("Sending report via email...")
            for recipient in email_recipients:
                try:
                    self.email_reporter.send_report(
                        recipient=recipient,
                        client_name=display_name,
                        excel_file=report_file
                    )
                    logger.info(f" Report sent to {recipient}")
                except Exception as e:
                    logger.error(f"Failed to send to {recipient}: {e}")
        
        logger.info(f"\n Security report generation complete for {client_name}\n")
    
    def _empty_alert_analysis(self):
        """Return empty alert analysis structure"""
        return {
            'total_count': 0,
            'by_level': {},
            'top_rules': [],
            'unique_agents': []
        }
    
    def _empty_access_analysis(self):
        """Return empty access analysis structure"""
        return {
            'usa_logins': 0,
            'international_logins': 0,
            'vpn_access': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'by_region': {},
            'by_user': {},
            'vpn_events': [],
            'foreign_logins': [],
            'internal_logins': []
        }


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Security Report Generator for Wazuh Multi-Tenant',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  1. Capture baseline: python3 security_report.py --snapshot
  2. Generate report:  python3 security_report.py
  3. Specific client:  python3 security_report.py --client homelab
        """
    )
    
    parser.add_argument('--snapshot', action='store_true',
                       help='Capture baseline vulnerability snapshot only')
    parser.add_argument('--client', type=str,
                       help='Process specific client only')
    
    args = parser.parse_args()
    generator = SecurityReportGenerator()
    
    # Determine which clients to process
    if args.client:
        if args.client not in generator.config['clients']:
            logger.error(f"Client '{args.client}' not found in configuration")
            sys.exit(1)
        clients_to_process = {args.client: generator.config['clients'][args.client]}
    else:
        clients_to_process = generator.config['clients']
    
    # Process clients
    for client_name, client_config in clients_to_process.items():
        if not client_config.get('enabled', False):
            logger.info(f"Client {client_name} is disabled, skipping")
            continue
        
        try:
            if args.snapshot:
                generator.capture_baseline_snapshot(client_name, client_config)
            else:
                generator.run_monthly_report(client_name, client_config)
        except Exception as e:
            logger.error(f"Error processing {client_name}: {e}")
            import traceback
            traceback.print_exc()
            continue


if __name__ == '__main__':
    main()