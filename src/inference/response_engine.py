"""
Enhanced Automated Response Engine for Zero-Day Attack Detection.

Integrated response system that:
- Processes threat scores with severity classification
- Implements multi-tier alerting (LOW/MEDIUM/HIGH/CRITICAL)
- Includes explainability (feature attributions, attention weights)
- Supports automated network isolation via API hooks
- Logs detailed detection context for retraining
- Tracks alert history and false positive rates
- Generates actionable incident reports
- Configurable response policies per severity level
"""

import logging
import json
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from collections import deque
import requests  # For webhook/API integration

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ResponsePolicy:
    """
    Defines response actions for different threat severity levels.
    """
    
    def __init__(
        self,
        severity: str,
        alert_enabled: bool = True,
        log_enabled: bool = True,
        isolate_enabled: bool = False,
        notify_soc: bool = False,
        custom_actions: Optional[List[Callable]] = None
    ):
        """
        Initialize response policy.
        
        Args:
            severity: Threat severity (LOW/MEDIUM/HIGH/CRITICAL)
            alert_enabled: Send alerts via webhook/email
            log_enabled: Log to incident database
            isolate_enabled: Trigger network isolation
            notify_soc: Notify Security Operations Center
            custom_actions: List of custom action functions
        """
        self.severity = severity
        self.alert_enabled = alert_enabled
        self.log_enabled = log_enabled
        self.isolate_enabled = isolate_enabled
        self.notify_soc = notify_soc
        self.custom_actions = custom_actions or []


class EnhancedResponseEngine:
    """
    Enhanced response engine for zero-day attack detection.
    
    Key Features:
    - Multi-tier severity-based responses
    - Explainable alerts with feature attributions
    - Automated network isolation via firewall APIs
    - Detailed incident logging for retraining
    - False positive tracking and learning
    - Configurable response policies
    - Integration with SIEM systems
    - Incident report generation
    """

    def __init__(
        self,
        alert_webhook_url: Optional[str] = None,
        siem_api_url: Optional[str] = None,
        firewall_api_url: Optional[str] = None,
        isolation_api_key: Optional[str] = None,
        incident_log_path: str = "data/incidents/incident_log.jsonl",
        alert_history_size: int = 1000
    ):
        """
        Initialize Enhanced Response Engine.

        Args:
            alert_webhook_url: Webhook URL for alerts (e.g., Slack, Teams)
            siem_api_url: SIEM system API endpoint
            firewall_api_url: Firewall/isolation API endpoint
            isolation_api_key: API key for network isolation
            incident_log_path: Path to incident log file
            alert_history_size: Max alerts to keep in memory
        """
        self.alert_webhook_url = alert_webhook_url
        self.siem_api_url = siem_api_url
        self.firewall_api_url = firewall_api_url
        self.isolation_api_key = isolation_api_key
        self.incident_log_path = Path(incident_log_path)
        
        # Create log directory if needed
        self.incident_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Alert history for tracking and analysis
        self.alert_history = deque(maxlen=alert_history_size)
        
        # Response policies per severity level
        self.policies = {
            'LOW': ResponsePolicy(
                severity='LOW',
                alert_enabled=False,
                log_enabled=True,
                isolate_enabled=False,
                notify_soc=False
            ),
            'MEDIUM': ResponsePolicy(
                severity='MEDIUM',
                alert_enabled=True,
                log_enabled=True,
                isolate_enabled=False,
                notify_soc=False
            ),
            'HIGH': ResponsePolicy(
                severity='HIGH',
                alert_enabled=True,
                log_enabled=True,
                isolate_enabled=False,
                notify_soc=True
            ),
            'CRITICAL': ResponsePolicy(
                severity='CRITICAL',
                alert_enabled=True,
                log_enabled=True,
                isolate_enabled=True,
                notify_soc=True
            )
        }
        
        # Statistics
        self.stats = {
            'total_alerts': 0,
            'by_severity': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
            'isolated_entities': 0,
            'false_positives': 0
        }
        
        logger.info("Enhanced Response Engine initialized")
        logger.info(f"  Incident log: {self.incident_log_path}")
        logger.info(f"  Alert webhook: {'Configured' if alert_webhook_url else 'Not configured'}")
        logger.info(f"  Network isolation: {'Enabled' if firewall_api_url else 'Disabled'}")

    def process_detection(
        self,
        detection_result: Dict[str, Any],
        entity_id: str = 'system',
        entity_type: str = 'system',
        source_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Process a detection result and execute appropriate responses.
        
        Args:
            detection_result: Output from EnhancedAnomalyDetector.detect_comprehensive()
            entity_id: Identifier (IP address, process GUID, etc.)
            entity_type: Type of entity ('ip', 'process', 'device')
            source_data: Original data that triggered detection
            
        Returns:
            Response summary with actions taken
        """
        severity = detection_result.get('severity', 'LOW')
        threat_score = detection_result.get('final_threat_score', 0.0)
        confidence = detection_result.get('confidence', 0.0)
        
        logger.info(f"Processing detection: Entity={entity_id}, Severity={severity}, Score={threat_score:.4f}")
        
        # Get policy for this severity
        policy = self.policies.get(severity)
        if not policy:
            logger.warning(f"No policy defined for severity {severity}, using default")
            policy = self.policies['LOW']
        
        actions_taken = []
        
        # 1. Log incident
        if policy.log_enabled:
            self._log_incident(detection_result, entity_id, entity_type, source_data)
            actions_taken.append('incident_logged')
        
        # 2. Send alert
        if policy.alert_enabled:
            self._send_alert(detection_result, entity_id, entity_type)
            actions_taken.append('alert_sent')
        
        # 3. Isolate entity (CRITICAL threats only by default)
        if policy.isolate_enabled:
            isolation_result = self._isolate_entity(entity_id, entity_type, detection_result)
            if isolation_result['success']:
                actions_taken.append('entity_isolated')
            else:
                actions_taken.append('isolation_failed')
        
        # 4. Notify SOC
        if policy.notify_soc:
            self._notify_soc(detection_result, entity_id, entity_type)
            actions_taken.append('soc_notified')
        
        # 5. Execute custom actions
        for action_func in policy.custom_actions:
            try:
                action_func(detection_result, entity_id, entity_type)
                actions_taken.append(f'custom_{action_func.__name__}')
            except Exception as e:
                logger.error(f"Custom action failed: {e}")
        
        # Update statistics
        self.stats['total_alerts'] += 1
        self.stats['by_severity'][severity] += 1
        if 'entity_isolated' in actions_taken:
            self.stats['isolated_entities'] += 1
        
        # Store in alert history
        alert_record = {
            'timestamp': datetime.now().isoformat(),
            'entity_id': entity_id,
            'entity_type': entity_type,
            'severity': severity,
            'threat_score': threat_score,
            'confidence': confidence,
            'actions_taken': actions_taken
        }
        self.alert_history.append(alert_record)
        
        logger.info(f"Response complete: {len(actions_taken)} actions taken")
        
        return {
            'entity_id': entity_id,
            'severity': severity,
            'actions_taken': actions_taken,
            'timestamp': alert_record['timestamp']
        }

    def _log_incident(
        self,
        detection_result: Dict[str, Any],
        entity_id: str,
        entity_type: str,
        source_data: Optional[Dict]
    ):
        """Log detailed incident data for future analysis and retraining."""
        incident = {
            'timestamp': datetime.now().isoformat(),
            'entity_id': entity_id,
            'entity_type': entity_type,
            'severity': detection_result.get('severity'),
            'threat_score': detection_result.get('final_threat_score'),
            'confidence': detection_result.get('confidence'),
            'lstm_score': detection_result.get('lstm_analysis', {}).get('anomaly_score'),
            'gnn_score': detection_result.get('gnn_analysis', {}).get('graph_anomaly_score'),
            'model_agreement': detection_result.get('ensemble_details', {}).get('model_agreement'),
            'temporal_trend': detection_result.get('ensemble_details', {}).get('trend'),
            'explainability': {
                'top_features': detection_result.get('explainability', {}).get('top_temporal_features', []),
                'anomalous_nodes': detection_result.get('explainability', {}).get('anomalous_nodes', [])
            },
            'source_data': source_data
        }
        
        # Append to JSONL log file
        with open(self.incident_log_path, 'a') as f:
            f.write(json.dumps(incident) + '\n')
        
        logger.debug(f"Incident logged to {self.incident_log_path}")

    def _send_alert(
        self,
        detection_result: Dict[str, Any],
        entity_id: str,
        entity_type: str
    ):
        """Send alert via webhook (Slack, Teams, email, etc.)."""
        if not self.alert_webhook_url:
            logger.debug("Alert webhook not configured, skipping")
            return
        
        severity = detection_result.get('severity', 'UNKNOWN')
        threat_score = detection_result.get('final_threat_score', 0.0)
        confidence = detection_result.get('confidence', 0.0)
        
        # Extract explainability
        explainability = detection_result.get('explainability', {})
        top_features = explainability.get('top_temporal_features', [])[:3]
        anomalous_nodes = explainability.get('anomalous_nodes', [])[:3]
        
        # Build alert message
        emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': 'ℹ️'
        }.get(severity, '❓')
        
        message = {
            'text': f"{emoji} Zero-Day Threat Detected - {severity}",
            'blocks': [
                {
                    'type': 'header',
                    'text': {
                        'type': 'plain_text',
                        'text': f"{emoji} Zero-Day Threat Detected"
                    }
                },
                {
                    'type': 'section',
                    'fields': [
                        {'type': 'mrkdwn', 'text': f'*Severity:*\n{severity}'},
                        {'type': 'mrkdwn', 'text': f'*Threat Score:*\n{threat_score:.4f}'},
                        {'type': 'mrkdwn', 'text': f'*Confidence:*\n{confidence:.2%}'},
                        {'type': 'mrkdwn', 'text': f'*Entity:*\n{entity_id}'}
                    ]
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f'*Top Anomalous Features:*\n' + '\n'.join([
                            f"• {feat['feature']}: {feat['error']:.4f}"
                            for feat in top_features
                        ])
                    }
                }
            ]
        }
        
        if anomalous_nodes:
            message['blocks'].append({
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*Anomalous Network Nodes:*\n' + '\n'.join([
                        f"• {node['node']}: {node['score']:.4f}"
                        for node in anomalous_nodes
                    ])
                }
            })
        
        try:
            response = requests.post(
                self.alert_webhook_url,
                json=message,
                timeout=5
            )
            response.raise_for_status()
            logger.info(f"Alert sent successfully to webhook")
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")

    def _isolate_entity(
        self,
        entity_id: str,
        entity_type: str,
        detection_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Trigger network isolation via firewall API.
        
        This would integrate with:
        - Palo Alto Networks API
        - Cisco FTD API
        - pfSense API
        - Cloud security groups (AWS, Azure)
        """
        if not self.firewall_api_url:
            logger.warning("Network isolation not configured")
            return {'success': False, 'reason': 'not_configured'}
        
        logger.warning(f"⚠️ ISOLATING ENTITY: {entity_id} (type: {entity_type})")
        
        # Prepare isolation request
        isolation_request = {
            'action': 'block',
            'entity_id': entity_id,
            'entity_type': entity_type,
            'reason': f"Zero-day threat detected (score: {detection_result.get('final_threat_score'):.4f})",
            'severity': detection_result.get('severity'),
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Send isolation command to firewall API
            headers = {}
            if self.isolation_api_key:
                headers['Authorization'] = f'Bearer {self.isolation_api_key}'
            
            response = requests.post(
                self.firewall_api_url,
                json=isolation_request,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            logger.info(f"✓ Entity {entity_id} isolated successfully")
            return {
                'success': True,
                'entity_id': entity_id,
                'response': response.json()
            }
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to isolate entity: {e}")
            return {
                'success': False,
                'entity_id': entity_id,
                'error': str(e)
            }

    def _notify_soc(
        self,
        detection_result: Dict[str, Any],
        entity_id: str,
        entity_type: str
    ):
        """Send detailed notification to Security Operations Center."""
        if not self.siem_api_url:
            logger.debug("SIEM API not configured, skipping SOC notification")
            return
        
        # Prepare SIEM event
        siem_event = {
            'event_type': 'zero_day_detection',
            'severity': detection_result.get('severity'),
            'threat_score': detection_result.get('final_threat_score'),
            'confidence': detection_result.get('confidence'),
            'entity_id': entity_id,
            'entity_type': entity_type,
            'timestamp': datetime.now().isoformat(),
            'models': {
                'lstm_score': detection_result.get('lstm_analysis', {}).get('anomaly_score'),
                'gnn_score': detection_result.get('gnn_analysis', {}).get('graph_anomaly_score'),
                'model_agreement': detection_result.get('ensemble_details', {}).get('model_agreement')
            },
            'explainability': detection_result.get('explainability', {})
        }
        
        try:
            response = requests.post(
                self.siem_api_url,
                json=siem_event,
                timeout=5
            )
            response.raise_for_status()
            logger.info("SOC notified via SIEM API")
        except Exception as e:
            logger.error(f"Failed to notify SOC: {e}")

    def mark_false_positive(
        self,
        entity_id: str,
        timestamp: str,
        reason: Optional[str] = None
    ):
        """
        Mark an alert as false positive for learning.
        
        This data can be used to:
        - Retrain ensemble weights
        - Adjust detection thresholds
        - Improve model calibration
        """
        self.stats['false_positives'] += 1
        
        false_positive_record = {
            'entity_id': entity_id,
            'timestamp': timestamp,
            'marked_fp_at': datetime.now().isoformat(),
            'reason': reason
        }
        
        # Log false positive
        fp_log_path = self.incident_log_path.parent / 'false_positives.jsonl'
        with open(fp_log_path, 'a') as f:
            f.write(json.dumps(false_positive_record) + '\n')
        
        logger.info(f"Marked alert as false positive: {entity_id}")

    def generate_incident_report(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        min_severity: str = 'MEDIUM'
    ) -> Dict[str, Any]:
        """
        Generate comprehensive incident report for a time period.
        
        Args:
            start_time: Report start time (default: last 24 hours)
            end_time: Report end time (default: now)
            min_severity: Minimum severity to include
            
        Returns:
            Report summary with statistics and incident list
        """
        if end_time is None:
            end_time = datetime.now()
        if start_time is None:
            start_time = end_time - pd.Timedelta(days=1)
        
        # Filter alerts in time window
        severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        min_severity_level = severity_order.get(min_severity, 0)
        
        filtered_alerts = [
            alert for alert in self.alert_history
            if (
                start_time <= datetime.fromisoformat(alert['timestamp']) <= end_time
                and severity_order.get(alert['severity'], 0) >= min_severity_level
            )
        ]
        
        # Calculate statistics
        report = {
            'report_period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'summary': {
                'total_incidents': len(filtered_alerts),
                'by_severity': {
                    severity: len([a for a in filtered_alerts if a['severity'] == severity])
                    for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                },
                'unique_entities': len(set(a['entity_id'] for a in filtered_alerts)),
                'average_threat_score': np.mean([a['threat_score'] for a in filtered_alerts]) if filtered_alerts else 0.0,
                'average_confidence': np.mean([a['confidence'] for a in filtered_alerts]) if filtered_alerts else 0.0
            },
            'incidents': filtered_alerts,
            'statistics': self.stats.copy()
        }
        
        logger.info(f"Generated incident report: {len(filtered_alerts)} incidents")
        
        return report

    def update_policy(
        self,
        severity: str,
        **kwargs
    ):
        """
        Update response policy for a severity level.
        
        Example:
            engine.update_policy('HIGH', isolate_enabled=True)
        """
        if severity not in self.policies:
            logger.error(f"Unknown severity level: {severity}")
            return
        
        policy = self.policies[severity]
        for key, value in kwargs.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
                logger.info(f"Updated policy for {severity}: {key}={value}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get current response engine statistics."""
        return {
            **self.stats,
            'alert_history_size': len(self.alert_history),
            'false_positive_rate': (
                self.stats['false_positives'] / self.stats['total_alerts']
                if self.stats['total_alerts'] > 0 else 0.0
            )
        }


def main_demo():
    """Demonstration of Enhanced Response Engine."""
    logger.info("=== Enhanced Response Engine Demo ===\n")
    
    # Initialize engine
    engine = EnhancedResponseEngine(
        alert_webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        incident_log_path="data/incidents/demo_incidents.jsonl"
    )
    
    # Simulate detection results
    detection_results = [
        # Low severity - minimal response
        {
            'final_threat_score': 0.45,
            'severity': 'LOW',
            'confidence': 0.6,
            'lstm_analysis': {'anomaly_score': 0.4},
            'gnn_analysis': {'graph_anomaly_score': 0.5},
            'explainability': {'top_temporal_features': []}
        },
        # High severity - alert + log + notify SOC
        {
            'final_threat_score': 0.85,
            'severity': 'HIGH',
            'confidence': 0.9,
            'lstm_analysis': {'anomaly_score': 0.8},
            'gnn_analysis': {'graph_anomaly_score': 0.9},
            'explainability': {
                'top_temporal_features': [
                    {'feature': 'burstiness', 'error': 0.95},
                    {'feature': 'entropy', 'error': 0.88}
                ],
                'anomalous_nodes': [
                    {'node': '192.168.1.100', 'score': 0.92}
                ]
            }
        },
        # Critical severity - full response including isolation
        {
            'final_threat_score': 0.96,
            'severity': 'CRITICAL',
            'confidence': 0.95,
            'lstm_analysis': {'anomaly_score': 0.95},
            'gnn_analysis': {'graph_anomaly_score': 0.97},
            'explainability': {
                'top_temporal_features': [
                    {'feature': 'rare_protocol_ratio', 'error': 0.98},
                    {'feature': 'protocol_switching_rate', 'error': 0.96}
                ],
                'anomalous_nodes': [
                    {'node': '10.0.0.50', 'score': 0.99}
                ]
            }
        }
    ]
    
    entities = [
        ('192.168.1.50', 'ip'),
        ('192.168.1.100', 'ip'),
        ('10.0.0.50', 'ip')
    ]
    
    # Process each detection
    for detection, (entity_id, entity_type) in zip(detection_results, entities):
        logger.info(f"\n--- Processing {detection['severity']} threat ---")
        result = engine.process_detection(
            detection_result=detection,
            entity_id=entity_id,
            entity_type=entity_type
        )
        logger.info(f"Actions taken: {result['actions_taken']}")
    
    # Generate report
    logger.info("\n--- Generating Incident Report ---")
    report = engine.generate_incident_report(min_severity='MEDIUM')
    logger.info(f"Total incidents (MEDIUM+): {report['summary']['total_incidents']}")
    logger.info(f"By severity: {report['summary']['by_severity']}")
    
    # Show statistics
    logger.info("\n--- Engine Statistics ---")
    stats = engine.get_statistics()
    for key, value in stats.items():
        logger.info(f"  {key}: {value}")
    
    logger.info("\n✅ Demo complete!")


if __name__ == '__main__':
    import numpy as np  # For demo statistics
    main_demo()
