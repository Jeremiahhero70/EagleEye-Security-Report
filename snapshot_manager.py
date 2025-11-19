#!/usr/bin/env python3
"""
Snapshot Manager - Vulnerability Snapshot Storage
Handles saving, loading, and fetching vulnerability snapshots
"""

import os
import json
import logging
from typing import Dict, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class SnapshotManager:
    """Manage vulnerability snapshots for month-over-month comparison"""
    
    def __init__(self, wazuh_scanner):
        """Initialize with Wazuh scanner instance
        
        Args:
            wazuh_scanner: WazuhScanner instance for fetching vulnerability data
        """
        self.wazuh = wazuh_scanner
    
    def fetch(self, client_name: str, date: str) -> Dict[str, Any]:
        """Fetch vulnerability snapshot for a specific date
        
        Args:
            client_name: Client identifier
            date: Date in YYYY-MM-DD format
            
        Returns:
            Dictionary with vulnerability counts by severity and agent
        """
        severities = ["Critical", "High", "Medium", "Low"]
        snapshot = {
            'date': date,
            'total': 0,
            'by_severity': {},
            'by_agent': defaultdict(lambda: {
                'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'total': 0
            }),
            'vulnerabilities': []
        }
        
        for severity in severities:
            result = self.wazuh.search_vulnerabilities(client_name, severity, page_size=10000)
            
            if result.get('error'):
                logger.error(f"Error fetching {severity} vulnerabilities for {date}: {result['error']}")
                continue
            
            count = result.get('total', 0)
            snapshot['by_severity'][severity] = count
            snapshot['total'] += count
            
            # Track by agent
            for vuln in result.get('results', []):
                agent_name = vuln.get('agent', {}).get('name', 'Unknown')
                snapshot['by_agent'][agent_name][severity] += 1
                snapshot['by_agent'][agent_name]['total'] += 1
                
                # Store vulnerability details
                snapshot['vulnerabilities'].append({
                    'agent': agent_name,
                    'severity': severity,
                    'cve': vuln.get('vulnerability', {}).get('cve', 'N/A'),
                    'title': vuln.get('vulnerability', {}).get('title', 'Unknown'),
                    'package': vuln.get('package', {}).get('name', 'Unknown')
                })
        
        return snapshot
    
    def save(self, client_name: str, snapshot: Dict[str, Any]) -> str:
        """Save vulnerability snapshot to JSON file
        
        Only saves counts, not full vulnerability details, to keep files small.
        
        Args:
            client_name: Client identifier
            snapshot: Snapshot dictionary to save
            
        Returns:
            Path to saved snapshot file
        """
        snapshot_dir = f"reports/{client_name}/snapshots"
        os.makedirs(snapshot_dir, exist_ok=True)
        
        snapshot_file = f"{snapshot_dir}/snapshot_{snapshot['date']}.json"
        
        # Convert defaultdict to regular dict and ONLY save counts
        snapshot_to_save = {
            'date': snapshot['date'],
            'total': snapshot['total'],
            'by_severity': snapshot['by_severity'],
            'by_agent': {agent: dict(counts) for agent, counts in snapshot['by_agent'].items()}
        }
        
        with open(snapshot_file, 'w') as f:
            json.dump(snapshot_to_save, f, indent=2)
        
        logger.info(f" Snapshot saved: {snapshot_file} ({snapshot['total']} vulnerabilities)")
        return snapshot_file
    
    def load(self, client_name: str, date: str) -> Dict[str, Any]:
        """Load previously saved vulnerability snapshot
        
        Args:
            client_name: Client identifier
            date: Date in YYYY-MM-DD format
            
        Returns:
            Snapshot dictionary or None if not found
        """
        snapshot_file = f"reports/{client_name}/snapshots/snapshot_{date}.json"
        
        if not os.path.exists(snapshot_file):
            logger.warning(f"No snapshot found for {date}: {snapshot_file}")
            return None
        
        with open(snapshot_file, 'r') as f:
            snapshot = json.load(f)
        
        logger.info(f" Loaded snapshot from {date}: {snapshot['total']} vulnerabilities")
        return snapshot