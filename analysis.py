#!/usr/bin/env python3
"""
Security Analysis Module
Analyzes security alerts and access patterns
"""

import logging
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Analyze security alerts and access patterns"""
    
    @staticmethod
    def analyze_alerts(alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze alerts for security incident reporting
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            Analysis dictionary with alert statistics
        """
        analysis = {
            'total_count': len(alerts),
            'by_level': defaultdict(int),
            'by_rule': defaultdict(int),
            'by_agent': defaultdict(int),
            'by_date': defaultdict(int),
            'top_rules': [],
            'unique_agents': set()
        }
        
        for alert in alerts:
            level = alert.get('rule', {}).get('level', 0)
            rule_id = alert.get('rule', {}).get('id', 'unknown')
            rule_desc = alert.get('rule', {}).get('description', 'Unknown')
            agent_name = alert.get('agent', {}).get('name', 'Unknown')
            timestamp = alert.get('timestamp', '')[:10]  # Get date only
            
            analysis['by_level'][f"Level {level}"] += 1
            analysis['by_rule'][f"{rule_id} - {rule_desc}"] += 1
            analysis['by_agent'][agent_name] += 1
            analysis['by_date'][timestamp] += 1
            analysis['unique_agents'].add(agent_name)
        
        # Get top 10 rules
        analysis['top_rules'] = sorted(
            analysis['by_rule'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        analysis['unique_agents'] = list(analysis['unique_agents'])
        
        return analysis
    
    @staticmethod
    def analyze_access_patterns(alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze login and VPN access patterns with detailed events
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            Access analysis dictionary with event details
        """
        access_analysis = {
            'usa_logins': 0,
            'international_logins': 0,
            'vpn_access': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'by_region': defaultdict(int),
            'by_user': defaultdict(int),
            'vpn_events': [],
            'foreign_logins': [],
            'internal_logins': []
        }
        
        login_keywords = ['login', 'logon', 'authentication', 'logged in', 'logon type']
        
        for alert in alerts:
            rule_desc = alert.get('rule', {}).get('description', '').lower()
            data = alert.get('data', {})
            timestamp = alert.get('timestamp', '')
            
            # Check if it's a login event
            if not any(keyword in rule_desc for keyword in login_keywords):
                continue
            
            # Check for internal Windows login
            win_eventdata = data.get('win', {}).get('eventdata', {})
            target_user = win_eventdata.get('targetUserName', '')
            workstation = win_eventdata.get('workstationName', '')
            
            if target_user and workstation:
                access_analysis['internal_logins'].append({
                    'timestamp': timestamp,
                    'user': target_user,
                    'workstation': workstation,
                    'source_ip': win_eventdata.get('ipAddress', ''),
                    'logon_type': win_eventdata.get('logonType', '')
                })
                continue
            
            # Process Office365 logins
            scamalytics = data.get('Scamalytics', {})
            ipinfo = scamalytics.get('ipinfo', {})
            maxmind = scamalytics.get('maxmind', {})
            scamalytics_proxy = scamalytics.get('scamalytics_proxy', {})
            
            # Get country from ipinfo first, fallback to maxmind
            country = ipinfo.get('country', '') or maxmind.get('country', '')
            country_code = ipinfo.get('country_code', '') or maxmind.get('country_code', '')
            city = maxmind.get('city', '')
            state = maxmind.get('state', '')
            
            office365 = data.get('office365', {})
            user = office365.get('UserId', 'Unknown')
            source_ip = scamalytics.get('ip', '')
            os_info = data.get('device_properties', {}).get('OS', '')
            is_vpn = scamalytics_proxy.get('is_vpn', False)
            
            access_analysis['by_user'][user] += 1
            
            # VPN access event
            if is_vpn:
                access_analysis['vpn_access'] += 1
                access_analysis['vpn_events'].append({
                    'timestamp': timestamp,
                    'user': user,
                    'source_ip': source_ip,
                    'os': os_info
                })
            
            # USA vs International (only for non-VPN logins)
            # Use country_code for exact matching (more reliable)
            if country and not is_vpn:
                is_usa = (country_code == 'US' or country == 'United States')
                
                if is_usa:
                    access_analysis['usa_logins'] += 1
                else:
                    access_analysis['international_logins'] += 1
                    access_analysis['foreign_logins'].append({
                        'timestamp': timestamp,
                        'user': user,
                        'source_ip': source_ip,
                        'country': country,
                        'city': city,
                        'state': state,
                        'os': os_info
                    })
                
                access_analysis['by_region'][country] += 1
            
            # Success vs Failure
            if 'fail' in rule_desc or 'denied' in rule_desc:
                access_analysis['failed_logins'] += 1
            else:
                access_analysis['successful_logins'] += 1
        
        # Sort events by timestamp (most recent first)
        for key in ['vpn_events', 'foreign_logins', 'internal_logins']:
            access_analysis[key] = sorted(
                access_analysis[key],
                key=lambda x: x['timestamp'],
                reverse=True
            )
        
        return access_analysis