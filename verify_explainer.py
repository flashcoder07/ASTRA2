from explainer import get_explainer
import pandas as pd
import logging

# Mute logging for cleaner output
logging.basicConfig(level=logging.ERROR)

def test_explainer():
    print("Initializing explainer...")
    exp = get_explainer()
    
    if not exp.is_ready:
        print("Explainer failed to initialize.")
        return

    print("Explainer ready.")
    
    # Create a dummy feature vector (all zeros)
    # The explainer expects specific columns, so we need to know them or let it handle dict
    # We will pass a dict with some values
    
    # Get feature columns from explainer
    cols = exp.feature_columns
    print(f"Model expects {len(cols)} features.")
    
    # Mock data: High Rate to simulate DDoS
    mock_data = {col: 0.0 for col in cols}
    if 'Rate' in mock_data:
        mock_data['Rate'] = 1000.0
    if 'Srate' in mock_data:
        mock_data['Srate'] = 5000.0
    if 'Protocol Type' in mock_data:
        mock_data['Protocol Type'] = 6 # TCP
        
    print("\nTesting explanation on mock DDoS data...")
    explanation = exp.explain_prediction(mock_data)
    
    import json
    print(json.dumps(explanation, indent=2))

if __name__ == "__main__":
    test_explainer()
