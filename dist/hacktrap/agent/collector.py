import json
import time
import logging
import psutil
from anomaly import detect_anomaly
from quarantine import quarantine_ip

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def collect_system_logs():
    """Collect system logs and metrics"""
    logs = {
        "timestamp": time.time(),
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "network_connections": len(psutil.net_connections()),
        "process_count": len(psutil.pids())
    }
    return logs

def monitor_logs():
    """Continuously monitor and analyze logs"""
    while True:
        try:
            logs = collect_system_logs()
            
            # Check for anomalies
            if detect_anomaly(logs):
                logger.warning(f"Anomaly detected: {logs}")
                # In a real scenario, you might quarantine suspicious IPs
                # quarantine_ip("suspicious_ip_here")
            
            # Simulate sending to backend (in real implementation)
            # requests.post("http://backend:8000/api/logs", json=logs)
            
            print(json.dumps(logs))
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Error in log collection: {e}")
            time.sleep(10)

if __name__ == "__main__":
    monitor_logs()