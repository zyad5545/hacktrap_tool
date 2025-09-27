def detect_anomaly(log_data):
    """
    Detect anomalies in system logs based on thresholds
    """
    thresholds = {
        "cpu_percent": 90,
        "memory_percent": 85,
        "disk_usage": 90,
        "network_connections": 100,
        "process_count": 300
    }
    
    # Check each metric against thresholds
    for metric, threshold in thresholds.items():
        if log_data.get(metric, 0) > threshold:
            return True
    
    return False