#!/usr/bin/env python3
"""
Email Reporter Module - Vulnerability Scanner
Sends vulnerability scan reports via SMTP with attachments
"""

import smtplib
import os
import logging
from typing import List, Dict
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

logger = logging.getLogger(__name__)


class EmailReporter:
    """Send vulnerability reports via email with attachments"""
    
    def __init__(self, smtp_server: str, smtp_port: int, sender: str, password: str, use_tls: bool = True):
        """Initialize email reporter with SMTP credentials
        
        Args:
            smtp_server: SMTP server hostname
            smtp_port: SMTP port (typically 587 for TLS)
            sender: Sender email address
            password: SMTP password or app-specific password
            use_tls: Whether to use TLS (default True)
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender = sender
        self.password = password
        self.use_tls = use_tls
    
    def send_report(self, recipient: str, client_name: str, excel_file: str, findings: List[Dict] = None) -> bool:
        """Send vulnerability scan report with Excel attachment
        
        Args:
            recipient: Email recipient address
            client_name: Client/environment name (for subject/body)
            excel_file: Path to Excel file to attach
            findings: List of finding dictionaries for count (optional)
        
        Returns:
            True if email sent successfully, False otherwise
        """
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender
            msg['To'] = recipient
            
            # Calculate total findings count
            total_findings = len(findings) if findings else 0
            
            # Subject line
            msg['Subject'] = f"Vulnerability Scan Report - {client_name}: {total_findings} findings detected"
            
            # Email body
            body_text = f"""Vulnerability Scan Report

Client: {client_name}
Total Findings: {total_findings}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC

Please see the attached Excel report for detailed vulnerability information.
The report contains:
- Summary Sheet: Executive overview with vulnerability counts and recommendations
- Details Sheet: Complete list of all vulnerabilities

---
EagleEye Vulnerability Scanner
"""
            
            msg.attach(MIMEText(body_text, 'plain'))
            
            # Attach Excel report
            if excel_file and os.path.exists(excel_file):
                with open(excel_file, 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', 'attachment',
                                  filename=f'{client_name}_Vulnerability_Report.xlsx')
                    msg.attach(part)
            
            # Send email via SMTP
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                
                # Only login if password is provided (skip for SMTP relay)
                if self.password:
                    server.login(self.sender, self.password)
                
                server.send_message(msg)

            logger.info(f" Email sent to {recipient} with {total_findings} findings")
            return True
            
        except Exception as e:
            logger.error(f" Failed to send email: {e}")
            return False
