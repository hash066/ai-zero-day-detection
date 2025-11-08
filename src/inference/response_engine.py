"""
Automated response engine for handling detected threats.

This module defines the ResponseEngine, which is responsible for taking
action when a threat score exceeds a defined threshold. Actions can include
sending alerts, logging events for review, or triggering external systems.
"""

import logging
import pandas as pd
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ResponseEngine:
    """
    Handles automated responses to security threats.
    """

    def __init__(self, alert_threshold: float, alert_webhook_url: str = ""):
        """
        Initialize the ResponseEngine.

        Args:
            alert_threshold (float): The threat score threshold [0, 1] above which
                                     an alert should be triggered.
            alert_webhook_url (str, optional): A URL to which alerts should be sent (e.g., Slack).
                                               If None, alerts are only logged.
        """
        if not (0.0 < alert_threshold <= 1.0):
            raise ValueError("alert_threshold must be between 0 and 1.")
            
        self.alert_threshold = alert_threshold
        self.alert_webhook_url = alert_webhook_url
        logging.info(f"ResponseEngine initialized with an alert threshold of {self.alert_threshold}.")

    def process_threat_score(self, entity_id: str, threat_score: float, metadata: Dict[str, Any] = None):
        """
        Processes a threat score and triggers actions if the threshold is met.

        Args:
            entity_id (str): The identifier of the entity being scored (e.g., device IP, process GUID).
            threat_score (float): The final threat score for the entity.
            metadata (Dict[str, Any], optional): Additional data about the event.
        """
        logging.debug(f"Processing score for entity '{entity_id}': {threat_score:.4f}")
        
        if threat_score >= self.alert_threshold:
            self.trigger_alert(entity_id, threat_score, metadata)
            self.log_event_for_review(entity_id, threat_score, metadata)
        else:
            # Optionally, you could log "normal" events to a different system for analytics
            pass

    def trigger_alert(self, entity_id: str, threat_score: float, metadata: Dict[str, Any]):
        """
        Sends an alert to the configured destination.
        """
        alert_message = (
            f"High-Threat Event Detected!\n"
            f"  - Entity ID: {entity_id}\n"
            f"  - Threat Score: {threat_score:.4f} (Threshold: {self.alert_threshold})\n"
            f"  - Metadata: {metadata}"
        )
        
        logging.warning(alert_message)
        
        if self.alert_webhook_url:
            # In a real-world scenario, you would use a library like `requests`
            # to send this data to a webhook.
            #
            # import requests
            # try:
            #     payload = {
            #         'text': alert_message,
            #         'username': 'ZeroDayDetectorBot',
            #         'icon_emoji': ':warning:'
            #     }
            #     requests.post(self.alert_webhook_url, json=payload)
            #     logging.info(f"Successfully sent alert to webhook for entity '{entity_id}'.")
            # except Exception as e:
            #     logging.error(f"Failed to send alert to webhook: {e}")
            logging.info(f"Simulating sending alert to: {self.alert_webhook_url}")

    def log_event_for_review(self, entity_id: str, threat_score: float, metadata: Dict[str, Any]):
        """
        Logs the high-threat event to a dedicated log file or database for
        later analysis and potential model retraining.
        """
        # This could write to a CSV, a database, or a dedicated logging system like ELK.
        log_entry = {
            "timestamp": pd.Timestamp.utcnow().isoformat(),
            "entity_id": entity_id,
            "threat_score": threat_score,
            "metadata": metadata
        }
        
        # For this example, we'll just log it to the console.
        logging.info(f"Logged for review: {log_entry}")


def main_demo():
    """Demonstrates the functionality of the ResponseEngine."""
    import pandas as pd
    
    logging.info("--- Response Engine Demo ---")
    
    # Initialize the engine with a threshold of 0.75
    engine = ResponseEngine(alert_threshold=0.75, alert_webhook_url="https://hooks.slack.com/services/...")

    # --- Case 1: Score below threshold ---
    entity1 = "192.168.1.101"
    score1 = 0.45
    metadata1 = {"reason": "Normal network traffic"}
    print(f"\nProcessing score {score1} for entity {entity1}...")
    engine.process_threat_score(entity1, score1, metadata1)

    # --- Case 2: Score above threshold ---
    entity2 = "{5e285c88-e400-6904-bc1f-000000007500}" # A process GUID
    score2 = 0.88
    metadata2 = {
        "process_name": "powershell.exe",
        "command_line": "powershell -enc ...",
        "lstm_error": 1.2,
        "gnn_prob": 0.9,
    }
    print(f"\nProcessing score {score2} for entity {entity2}...")
    engine.process_threat_score(entity2, score2, metadata2)

    # --- Case 3: Score exactly at threshold ---
    entity3 = "10.0.0.5"
    score3 = 0.75
    metadata3 = {"reason": "Suspicious DNS query"}
    print(f"\nProcessing score {score3} for entity {entity3}...")
    engine.process_threat_score(entity3, score3, metadata3)
    
if __name__ == '__main__':
    main_demo()
