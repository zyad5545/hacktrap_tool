import numpy as np

def predict_anomaly(data):
    """
    Simplified anomaly detection model
    In a real implementation, this would be a trained ML model
    """
    # Extract features (simplified)
    features = np.array([
        data.get('cpu_percent', 0) / 100,
        data.get('memory_percent', 0) / 100,
        data.get('disk_usage', 0) / 100,
        min(data.get('network_connections', 0) / 200, 1.0),
        min(data.get('process_count', 0) / 500, 1.0)
    ])
    
    # Simple weighted average (replace with actual model)
    weights = np.array([0.3, 0.3, 0.2, 0.1, 0.1])
    anomaly_score = np.dot(features, weights)
    
    return anomaly_score
