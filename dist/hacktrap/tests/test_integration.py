import unittest
import requests
import time
from scripts.demo_attack import simulate_brute_force, simulate_ddos

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.base_url = 'http://localhost:8000'
        # Wait for services to be ready
        time.sleep(5)
    
    def test_health_check(self):
        response = requests.get(f'{self.base_url}/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'healthy')
    
    def test_brute_force_simulation(self):
        # This test simulates brute force attacks
        simulate_brute_force(self.base_url)
        # No assertion, just checking it runs without errors
    
    def test_ddos_simulation(self):
        # This test simulates DDoS attacks
        simulate_ddos(self.base_url)
        # No assertion, just checking it runs without errors

if __name__ == '__main__':
    unittest.main()
