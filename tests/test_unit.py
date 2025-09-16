import unittest
from agent.anomaly import detect_anomaly
from agent.quarantine import quarantine_ip
from backend.db import init_db, log_attack, get_recent_attacks
from backend.blockchain import anchor_data
from ai_engine.model import predict_anomaly
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import requests
from web3 import Web3

class TestAnomalyDetection(unittest.TestCase):
    def test_detect_anomaly_normal(self):
        # Normal system metrics
        log_data = {
            'cpu_percent': 50,
            'memory_percent': 60,
            'disk_usage': 40,
            'network_connections': 50,
            'process_count': 100
        }
        self.assertFalse(detect_anomaly(log_data))
    
    def test_detect_anomaly_high_cpu(self):
        # High CPU usage
        log_data = {
            'cpu_percent': 95,
            'memory_percent': 60,
            'disk_usage': 40,
            'network_connections': 50,
            'process_count': 100
        }
        self.assertTrue(detect_anomaly(log_data))
    
    def test_detect_anomaly_high_memory(self):
        # High memory usage
        log_data = {
            'cpu_percent': 50,
            'memory_percent': 90,
            'disk_usage': 40,
            'network_connections': 50,
            'process_count': 100
        }
        self.assertTrue(detect_anomaly(log_data))

class TestQuarantine(unittest.TestCase):
    def test_quarantine_ip(self):
        # Mock quarantine function
        self.assertTrue(quarantine_ip("192.168.1.100"))

class TestDatabase(unittest.TestCase):
    def setUp(self):
        init_db()
    
    def test_log_attack(self):
        attack_data = {
            'attack_type': 'brute_force',
            'source_ip': '192.168.1.100',
            'target_resource': '/login',
            'severity': 'high'
        }
        attack_id = log_attack(attack_data)
        self.assertIsInstance(attack_id, int)
    
    def test_get_recent_attacks(self):
        attacks = get_recent_attacks(5)
        self.assertIsInstance(attacks, list)

class TestBlockchain(unittest.TestCase):
    def test_anchor_data(self):
        # Mock blockchain function
        data = {'test': 'data'}
        tx_hash = anchor_data(data)
        self.assertIsNone(tx_hash)  # No blockchain configured in test

class TestAIModel(unittest.TestCase):
    def test_predict_anomaly(self):
        data = {
            'cpu_percent': 50,
            'memory_percent': 60,
            'disk_usage': 40,
            'network_connections': 50,
            'process_count': 100
        }
        score = predict_anomaly(data)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 1)

if __name__ == '__main__':
    unittest.main()
