#!/usr/bin/env python3
"""
Automated Incident Response System for AI Zero-Day Detection.

Provides intelligent, automated responses to detected security threats
including network isolation, process termination, and alert escalation.
"""

import logging
import os
import json
import time
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """Types of automated response actions."""
    ISOLATE_NETWORK = "isolate_network"
    BLOCK_IP = "block_ip"
    TERMINATE_PROCESS = "terminate_process"
    QUARANTINE_FILE = "quarantine_file"
    ALERT_SECURITY_TEAM = "alert_security_team"
    LOG_EVENT = "log_event"
    ESCALATE_HIGH_SEVERITY = "escalate_high_severity"


class IncidentSeverity(Enum):
    """Incident severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AutomatedIncidentResponse:
    """
    Intelligent incident response system that automatically responds
    to detected security threats based on severity and threat type.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        alert_callback: Optional[Callable] = None,
        escalation_callback: Optional[Callable] = None
    ):
        """
        Initialize automated incident response system.

        Args:
            config: Configuration dictionary
            alert_callback: Callback for alert notifications
            escalation_callback: Callback for escalation notifications
        """
        self.config = config or self._load_config()
        self.alert_callback = alert_callback
        self.escalation_callback = escalation_callback

        # Response tracking
        self.active_responses = {}
        self.response_history = []

        # System capabilities detection
        self._detect_capabilities()

        logger.info("✓ Automated Incident Response System initialized")

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        return {
            'auto_response_enabled': os.getenv('AUTO_RESPONSE_ENABLED', 'false').lower() == 'true',
            'high_severity_auto_isolate': os.getenv('HIGH_SEVERITY_AUTO_ISOLATE', 'false').lower() == 'true',
            'critical_severity_auto_shutdown': os.getenv('CRITICAL_SEVERITY_AUTO_SHUTDOWN', 'false').lower() == 'true',
            'webhook_url': os.getenv('ALERT_WEBHOOK_URL', ''),
            'slack_webhook': os.getenv('SLACK_WEBHOOK_URL', ''),
            'email_recipients': os.getenv('ALERT_EMAIL_RECIPIENTS', '').split(',') if os.getenv('ALERT_EMAIL_RECIPIENTS') else [],
            'isolation_duration_minutes': int(os.getenv('ISOLATION_DURATION_MINUTES', '30')),
            'max_concurrent_responses': int(os.getenv('MAX_CONCURRENT_RESPONSES', '10'))
        }

    def _detect_capabilities(self):
        """Detect system capabilities for automated responses."""
        self.capabilities = {
            'network_isolation': self._can_isolate_network(),
            'process_termination': self._can_terminate_processes(),
            'firewall_control': self._can_control_firewall(),
            'webhook_alerts': bool(self.config.get('webhook_url')),
            'slack_alerts': bool(self.config.get('slack_webhook')),
            'email_alerts': bool(self.config.get('email_recipients'))
        }

        logger.info(f"Detected capabilities: {self.capabilities}")

    def _can_isolate_network(self) -> bool:
        """Check if network isolation is possible."""
        try:
            # Check for Windows firewall or iptables capabilities
            if os.name == 'nt':  # Windows
                # Check if we can access Windows Firewall
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'currentprofile'],
                    capture_output=True, text=True, timeout=5
                )
                return result.returncode == 0
            else:  # Linux/Unix
                # Check for iptables
                result = subprocess.run(
                    ['which', 'iptables'],
                    capture_output=True, text=True, timeout=5
                )
                return result.returncode == 0
        except:
            return False

    def _can_terminate_processes(self) -> bool:
        """Check if process termination is possible."""
        try:
            # Test with a simple process listing command
            if os.name == 'nt':
                result = subprocess.run(
                    ['tasklist', '/FI', 'IMAGENAME eq System'],
                    capture_output=True, text=True, timeout=5
                )
                return result.returncode == 0
            else:
                result = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True, text=True, timeout=5
                )
                return result.returncode == 0
        except:
            return False

    def _can_control_firewall(self) -> bool:
        """Check if firewall control is possible."""
        return self._can_isolate_network()  # Same capability check

    def respond_to_incident(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Respond to a detected security incident.

        Args:
            alert_data: Alert information from anomaly detector

        Returns:
            Response actions taken and their results
        """
        try:
            threat_score = alert_data.get('threat_score', 0.0)
            severity = self._calculate_severity(threat_score)
            threat_type = alert_data.get('type', 'unknown')

            # Determine response actions based on severity and type
            response_actions = self._determine_response_actions(severity, threat_type, alert_data)

            # Execute response actions
            executed_actions = []
            for action in response_actions:
                result = self._execute_response_action(action, alert_data)
                executed_actions.append(result)

            # Track response
            response_record = {
                'timestamp': datetime.now().isoformat(),
                'alert_id': alert_data.get('id', 'unknown'),
                'severity': severity.value,
                'threat_score': threat_score,
                'actions_taken': executed_actions,
                'alert_data': alert_data
            }

            self.response_history.append(response_record)

            # Limit history size
            if len(self.response_history) > 1000:
                self.response_history = self.response_history[-1000:]

            logger.info(f"🚨 Incident Response: {severity.value.upper()} severity - {len(executed_actions)} actions taken")

            return {
                'severity': severity.value,
                'actions_taken': executed_actions,
                'response_id': f"resp_{int(time.time())}_{len(self.response_history)}"
            }

        except Exception as e:
            logger.error(f"Error in incident response: {e}")
            return {
                'error': str(e),
                'severity': 'unknown',
                'actions_taken': []
            }

    def _calculate_severity(self, threat_score: float) -> IncidentSeverity:
        """Calculate incident severity from threat score."""
        if threat_score >= 0.9:
            return IncidentSeverity.CRITICAL
        elif threat_score >= 0.75:
            return IncidentSeverity.HIGH
        elif threat_score >= 0.5:
            return IncidentSeverity.MEDIUM
        else:
            return IncidentSeverity.LOW

    def _determine_response_actions(
        self,
        severity: IncidentSeverity,
        threat_type: str,
        alert_data: Dict[str, Any]
    ) -> List[ResponseAction]:
        """
        Determine appropriate response actions based on severity and threat type.

        Args:
            severity: Calculated incident severity
            threat_type: Type of threat detected
            alert_data: Original alert data

        Returns:
            List of response actions to take
        """
        actions = []

        # Always log the event
        actions.append(ResponseAction.LOG_EVENT)

        # Severity-based responses
        if severity == IncidentSeverity.CRITICAL:
            if self.config.get('critical_severity_auto_shutdown', False):
                actions.append(ResponseAction.ESCALATE_HIGH_SEVERITY)
            actions.append(ResponseAction.ALERT_SECURITY_TEAM)

        elif severity == IncidentSeverity.HIGH:
            if self.config.get('high_severity_auto_isolate', False):
                if 'network' in threat_type.lower():
                    actions.append(ResponseAction.ISOLATE_NETWORK)
                elif 'sysmon' in threat_type.lower():
                    actions.append(ResponseAction.TERMINATE_PROCESS)
            actions.append(ResponseAction.ALERT_SECURITY_TEAM)

        elif severity == IncidentSeverity.MEDIUM:
            actions.append(ResponseAction.ALERT_SECURITY_TEAM)

        # Threat-type specific responses
        if 'network' in threat_type.lower():
            entity_id = alert_data.get('entity_id', '')
            if entity_id and self._is_ip_address(entity_id):
                actions.append(ResponseAction.BLOCK_IP)

        elif 'sysmon' in threat_type.lower():
            # Could add process-specific responses here
            pass

        # Remove duplicates while preserving order
        seen = set()
        unique_actions = []
        for action in actions:
            if action not in seen:
                seen.add(action)
                unique_actions.append(action)

        return unique_actions

    def _execute_response_action(self, action: ResponseAction, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a specific response action.

        Args:
            action: Response action to execute
            alert_data: Alert context data

        Returns:
            Action execution result
        """
        action_result = {
            'action': action.value,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'details': {}
        }

        try:
            if action == ResponseAction.ISOLATE_NETWORK:
                action_result.update(self._isolate_network(alert_data))

            elif action == ResponseAction.BLOCK_IP:
                action_result.update(self._block_ip(alert_data))

            elif action == ResponseAction.TERMINATE_PROCESS:
                action_result.update(self._terminate_process(alert_data))

            elif action == ResponseAction.QUARANTINE_FILE:
                action_result.update(self._quarantine_file(alert_data))

            elif action == ResponseAction.ALERT_SECURITY_TEAM:
                action_result.update(self._alert_security_team(alert_data))

            elif action == ResponseAction.LOG_EVENT:
                action_result.update(self._log_event(alert_data))

            elif action == ResponseAction.ESCALATE_HIGH_SEVERITY:
                action_result.update(self._escalate_high_severity(alert_data))

            action_result['success'] = True

        except Exception as e:
            logger.error(f"Failed to execute response action {action.value}: {e}")
            action_result['error'] = str(e)

        return action_result

    def _isolate_network(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate network access for affected entity."""
        if not self.capabilities.get('network_isolation'):
            return {'success': False, 'reason': 'Network isolation not available'}

        entity_id = alert_data.get('entity_id', '')
        duration = self.config.get('isolation_duration_minutes', 30)

        try:
            if os.name == 'nt':  # Windows
                # Block all outbound connections for the entity
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=Incident_Response_Block_{entity_id}',
                    'dir=out', 'action=block',
                    f'remoteip={entity_id}' if self._is_ip_address(entity_id) else 'remoteip=any',
                    f'description=Automated incident response - blocked for {duration} minutes'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    # Schedule unblock
                    self._schedule_unblock(entity_id, duration)
                    return {
                        'success': True,
                        'method': 'windows_firewall',
                        'entity_blocked': entity_id,
                        'duration_minutes': duration
                    }

            else:  # Linux
                # Use iptables to block
                cmd = ['iptables', '-A', 'OUTPUT', '-d', entity_id, '-j', 'DROP']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    self._schedule_unblock(entity_id, duration)
                    return {
                        'success': True,
                        'method': 'iptables',
                        'entity_blocked': entity_id,
                        'duration_minutes': duration
                    }

        except Exception as e:
            logger.error(f"Network isolation failed: {e}")

        return {'success': False, 'error': str(e)}

    def _block_ip(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Block specific IP address."""
        entity_id = alert_data.get('entity_id', '')

        if not self._is_ip_address(entity_id):
            return {'success': False, 'reason': 'Invalid IP address'}

        return self._isolate_network(alert_data)  # Reuse isolation logic

    def _terminate_process(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Terminate suspicious process."""
        if not self.capabilities.get('process_termination'):
            return {'success': False, 'reason': 'Process termination not available'}

        # Extract process information from alert data
        process_info = alert_data.get('details', {}).get('process_info', {})

        if not process_info:
            return {'success': False, 'reason': 'No process information available'}

        process_id = process_info.get('process_id')
        process_name = process_info.get('process_name')

        try:
            if os.name == 'nt':  # Windows
                if process_id:
                    cmd = ['taskkill', '/PID', str(process_id), '/F']
                elif process_name:
                    cmd = ['taskkill', '/IM', process_name, '/F']
                else:
                    return {'success': False, 'reason': 'No process identifier available'}

            else:  # Linux/Unix
                if process_id:
                    cmd = ['kill', '-9', str(process_id)]
                else:
                    return {'success': False, 'reason': 'No process identifier available'}

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                return {
                    'success': True,
                    'process_terminated': process_id or process_name,
                    'method': 'system_kill'
                }
            else:
                return {'success': False, 'error': result.stderr}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _quarantine_file(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine suspicious file."""
        file_path = alert_data.get('details', {}).get('file_path')

        if not file_path or not os.path.exists(file_path):
            return {'success': False, 'reason': 'File not found'}

        try:
            # Create quarantine directory
            quarantine_dir = os.path.join(os.getcwd(), 'quarantine')
            os.makedirs(quarantine_dir, exist_ok=True)

            # Move file to quarantine
            import shutil
            quarantined_path = os.path.join(quarantine_dir, f"quarantined_{int(time.time())}_{os.path.basename(file_path)}")
            shutil.move(file_path, quarantined_path)

            return {
                'success': True,
                'original_path': file_path,
                'quarantined_path': quarantined_path
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _alert_security_team(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send alerts to security team via configured channels."""
        alert_methods = []

        # Webhook alert
        if self.capabilities.get('webhook_alerts'):
            try:
                self._send_webhook_alert(alert_data)
                alert_methods.append('webhook')
            except Exception as e:
                logger.warning(f"Webhook alert failed: {e}")

        # Slack alert
        if self.capabilities.get('slack_alerts'):
            try:
                self._send_slack_alert(alert_data)
                alert_methods.append('slack')
            except Exception as e:
                logger.warning(f"Slack alert failed: {e}")

        # Email alert
        if self.capabilities.get('email_alerts'):
            try:
                self._send_email_alert(alert_data)
                alert_methods.append('email')
            except Exception as e:
                logger.warning(f"Email alert failed: {e}")

        # Custom alert callback
        if self.alert_callback:
            try:
                self.alert_callback(alert_data)
                alert_methods.append('callback')
            except Exception as e:
                logger.warning(f"Alert callback failed: {e}")

        return {
            'success': len(alert_methods) > 0,
            'methods_used': alert_methods,
            'alert_sent': len(alert_methods) > 0
        }

    def _log_event(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log incident response event."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'incident_response_log',
            'alert_data': alert_data,
            'severity': self._calculate_severity(alert_data.get('threat_score', 0.0)).value
        }

        # Log to file
        try:
            log_file = os.path.join(os.getcwd(), 'logs', 'incident_response.log')
            os.makedirs(os.path.dirname(log_file), exist_ok=True)

            with open(log_file, 'a') as f:
                json.dump(log_entry, f)
                f.write('\n')

            return {'success': True, 'log_file': log_file}

        except Exception as e:
            logger.error(f"Failed to log incident response: {e}")
            return {'success': False, 'error': str(e)}

    def _escalate_high_severity(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate critical severity incidents."""
        escalation_data = {
            'type': 'critical_incident_escalation',
            'original_alert': alert_data,
            'escalation_time': datetime.now().isoformat(),
            'severity': 'CRITICAL',
            'requires_immediate_attention': True
        }

        # Send to escalation callback if available
        if self.escalation_callback:
            try:
                self.escalation_callback(escalation_data)
                return {'success': True, 'method': 'callback'}
            except Exception as e:
                logger.error(f"Escalation callback failed: {e}")

        # Fallback to security team alert
        return self._alert_security_team(escalation_data)

    def _send_webhook_alert(self, alert_data: Dict[str, Any]):
        """Send alert via webhook."""
        import requests

        webhook_url = self.config.get('webhook_url')
        if not webhook_url:
            return

        payload = {
            'text': f"🚨 Security Alert: {alert_data.get('type', 'Unknown')} detected",
            'severity': self._calculate_severity(alert_data.get('threat_score', 0.0)).value,
            'threat_score': alert_data.get('threat_score', 0.0),
            'timestamp': datetime.now().isoformat(),
            'details': alert_data
        }

        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()

    def _send_slack_alert(self, alert_data: Dict[str, Any]):
        """Send alert via Slack webhook."""
        import requests

        slack_url = self.config.get('slack_webhook')
        if not slack_url:
            return

        severity = self._calculate_severity(alert_data.get('threat_score', 0.0)).value
        emoji_map = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': 'ℹ️'
        }

        payload = {
            'text': f"{emoji_map.get(severity, '❓')} *Security Alert*\n"
                   f"Type: {alert_data.get('type', 'Unknown')}\n"
                   f"Severity: {severity}\n"
                   f"Threat Score: {alert_data.get('threat_score', 0.0):.4f}\n"
                   f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        }

        response = requests.post(slack_url, json=payload, timeout=10)
        response.raise_for_status()

    def _send_email_alert(self, alert_data: Dict[str, Any]):
        """Send alert via email (placeholder - requires email server config)."""
        # This would require SMTP server configuration
        # For now, just log that email would be sent
        recipients = self.config.get('email_recipients', [])
        if recipients:
            logger.info(f"Email alert would be sent to: {', '.join(recipients)}")
            return True
        return False

    def _schedule_unblock(self, entity_id: str, duration_minutes: int):
        """Schedule automatic unblocking of isolated entity."""
        def unblock_entity():
            time.sleep(duration_minutes * 60)  # Convert to seconds

            try:
                if os.name == 'nt':  # Windows
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        f'name=Incident_Response_Block_{entity_id}'
                    ]
                    subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                else:  # Linux
                    cmd = ['iptables', '-D', 'OUTPUT', '-d', entity_id, '-j', 'DROP']
                    subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                logger.info(f"✓ Automatically unblocked {entity_id} after {duration_minutes} minutes")

            except Exception as e:
                logger.error(f"Failed to unblock {entity_id}: {e}")

        # Start unblock thread
        unblock_thread = threading.Thread(target=unblock_entity, daemon=True)
        unblock_thread.start()

    def _is_ip_address(self, string: str) -> bool:
        """Check if string is a valid IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(string)
            return True
        except ValueError:
            return False

    def get_response_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent response history."""
        return self.response_history[-limit:] if self.response_history else []

    def get_active_responses(self) -> Dict[str, Any]:
        """Get currently active response actions."""
        return self.active_responses.copy()

    def get_capabilities(self) -> Dict[str, bool]:
        """Get system response capabilities."""
        return self.capabilities.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Get response system statistics."""
        total_responses = len(self.response_history)
        severity_counts = {}

        for response in self.response_history:
            severity = response.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'total_responses': total_responses,
            'severity_breakdown': severity_counts,
            'active_responses': len(self.active_responses),
            'capabilities': self.capabilities
        }
