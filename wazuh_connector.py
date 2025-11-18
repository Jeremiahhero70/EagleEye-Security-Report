#!/usr/bin/env python3
"""
Wazuh Connector for Vulnerability Scanning
Handles multi-tenant Wazuh dashboard connections and agent IP enrichment
"""

import requests
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class WazuhScanner:
    """Simple Wazuh vulnerability scanner with shared dashboard and agent IP enrichment"""
    
    def __init__(self, dashboard_config: Dict[str, Any]):
        """Initialize scanner with shared dashboard configuration
        
        Args:
            dashboard_config: Shared dashboard configuration dict containing:
                - host: Wazuh dashboard host
                - port: Wazuh dashboard port (default 9200)
                - username: Authentication username
                - password: Authentication password
                - verify_ssl: SSL verification (default False)
        """
        host = dashboard_config.get('host', 'localhost')
        port = dashboard_config.get('port', 9200)
        user = dashboard_config.get('username', 'admin')
        password = dashboard_config.get('password', '')
        
        # Remove https:// prefix if already included in host
        host = host.replace('https://', '').replace('http://', '').rstrip('/')
        
        self.base_url = f"https://{host}:{port}"
        self.auth = (user, password)
        self.verify_ssl = dashboard_config.get('verify_ssl', False)
        self.timeout = 30
    
    def get_agents(self) -> Dict[str, Dict[str, str]]:
        """Fetch all agents with their IP addresses from Wazuh monitoring indices
        
        Queries the multi-tenant monitoring indices to get the latest agent information
        including IP addresses for all configured clients.
        
        Returns:
            Dictionary mapping agent ID to {'name': ..., 'ip': ..., 'status': ..., 'last_keep_alive': ...}
            Returns empty dict if query fails (graceful fallback to agent IDs)
        """
        try:
            # Query monitoring indices for latest agent information
            # Pattern: *:wazuh-monitoring-* to get all clients
            search_url = f"{self.base_url}/*:wazuh-monitoring-*/_search"
            
            # Aggregation to get latest record per agent
            query = {
                "size": 0,
                "aggs": {
                    "agents": {
                        "terms": {"field": "id", "size": 5000},
                        "aggs": {
                            "latest_record": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": ["id", "name", "ip", "status", "lastKeepAlive"]
                                }
                            }
                        }
                    }
                }
            }
            
            response = requests.post(
                search_url,
                auth=self.auth,
                json=query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.info(f"  Monitoring index query failed (HTTP {response.status_code}). Will use agent IDs as fallback.")
                return {}
            
            data = response.json()
            agents_dict = {}
            
            aggs = data.get('aggregations', {}).get('agents', {}).get('buckets', [])
            for agent_bucket in aggs:
                hits = agent_bucket.get('latest_record', {}).get('hits', {}).get('hits', [])
                if hits:
                    source = hits[0].get('_source', {})
                    agent_id = source.get('id')
                    agent_name = source.get('name')
                    agent_ip = source.get('ip', 'N/A')
                    
                    if agent_id:
                        agents_dict[agent_id] = {
                            'name': agent_name,
                            'ip': agent_ip,
                            'status': source.get('status'),
                            'last_keep_alive': source.get('lastKeepAlive')
                        }
            
            logger.info(f" Fetched {len(agents_dict)} agents with IP information from monitoring indices")
            return agents_dict
            
        except Exception as e:
            logger.info(f" Error fetching agents from monitoring indices: {e}. Will use agent IDs as fallback.")
            return {}
    
    def search_vulnerabilities(self, client_name: str, severity: str, page_size: int = 1000) -> Dict[str, Any]:
        """Search vulnerabilities for a specific client and severity level
        
        Args:
            client_name: Client identifier (e.g., "lab", "homelab")
            severity: Vulnerability severity level (e.g., "Critical", "High")
            page_size: Number of results to retrieve per page (default 1000)
        
        Returns:
            Dictionary with:
                - severity: Severity level queried
                - total: Total number of vulnerabilities found
                - results: List of vulnerability documents
                - error: Error message if query failed (optional)
        """
        
        # Build client-specific index pattern
        index_pattern = f"{client_name}:wazuh-states-vulnerabilities-*"
        search_url = f"{self.base_url}/{index_pattern}/_search"
        
        # Query for vulnerabilities with specific severity
        query = {
            "query": {
                "term": {
                    "vulnerability.severity": severity
                }
            },
            "size": page_size
        }
        
        try:
            response = requests.post(
                search_url,
                auth=self.auth,
                json=query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            total_hits = data.get("hits", {}).get("total", {}).get("value", 0)
            hits = data.get("hits", {}).get("hits", [])
            
            logger.info(f"    {severity}: {len(hits)} vulnerabilities found (total: {total_hits})")
            
            return {
                'severity': severity,
                'total': total_hits,
                'results': [hit.get('_source', {}) for hit in hits]
            }
            
        except Exception as e:
            logger.error(f"    Error scanning {severity}: {e}")
            return {
                'severity': severity,
                'total': 0,
                'results': [],
                'error': str(e)
            }
    
    def search_client_alerts(self, client_name: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """Search alerts for a specific client
        
        Args:
            client_name: Client identifier (e.g., "lab", "homelab")
            query: Elasticsearch query DSL
        
        Returns:
            Elasticsearch response with hits
        """
        # Build client-specific index pattern for alerts
        index_pattern = f"{client_name}:wazuh-alerts-*"
        search_url = f"{self.base_url}/{index_pattern}/_search"
        
        try:
            response = requests.post(
                search_url,
                auth=self.auth,
                json=query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Error searching alerts for {client_name}: {e}")
            return {}
