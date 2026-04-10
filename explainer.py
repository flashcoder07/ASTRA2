import shap
import joblib
import os
import pandas as pd
import numpy as np
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('astra_explainer')

class ThreatExplainer:
    def __init__(self, model_dir='models'):
        self.model_dir = model_dir
        self.classifier = None
        self.feature_columns = None
        self.explainer = None
        self.is_ready = False
        
        self.load_resources()

    def load_resources(self):
        try:
            clf_path = os.path.join(self.model_dir, 'threat_classifier.joblib')
            feat_path = os.path.join(self.model_dir, 'feature_columns.joblib')
            
            if not os.path.exists(clf_path) or not os.path.exists(feat_path):
                logger.warning("Model files not found. Explainer disabled.")
                return

            self.classifier = joblib.load(clf_path)
            self.feature_columns = joblib.load(feat_path)
            
            # Initialize SHAP TreeExplainer
            # TreeExplainer is efficient for Random Forests
            self.explainer = shap.TreeExplainer(self.classifier)
            self.is_ready = True
            logger.info("SHAP Explainer initialized successfully.")
            
        except Exception as e:
            logger.exception(f"Failed to initialize explainer: {e}")
            self.is_ready = False

    def explain_prediction(self, feature_vector):
        """
        Explain a single prediction.
        
        Args:
            feature_vector (dict or list or np.array): The feature values for one instance.
            
        Returns:
            dict: Top contributing features and summary.
        """
        if not self.is_ready:
            return {"error": "Explainer not ready"}

        try:
            # Ensure input is 2D array/DataFrame with correct columns if possible
            if isinstance(feature_vector, dict):
                # Align with feature columns
                try:
                    data = [feature_vector[col] for col in self.feature_columns]
                    X = pd.DataFrame([data], columns=self.feature_columns)
                except KeyError as e:
                    logger.error(f"Missing feature column in input: {e}")
                    return {"error": f"Missing feature: {e}"}
            elif isinstance(feature_vector, (list, np.ndarray)):
                X = pd.DataFrame([feature_vector], columns=self.feature_columns)
            else:
                return {"error": "Invalid input format"}

            # Calculate SHAP values
            # shap_values for random forest is a list of arrays (one for each class)
            # or an array of shape (n_samples, n_features, n_classes) depending on version.
            shap_values = self.explainer.shap_values(X)
            
            # Identify the class index for the predicted label
            # random_forest.predict returns the class label (string)
            # Pass numpy array to avoid warning "X has feature names, but RandomForestClassifier was fitted without feature names"
            prediction_label = self.classifier.predict(X.values)[0]
            
            # Find index of this label in classes_
            try:
                class_idx = list(self.classifier.classes_).index(prediction_label)
            except ValueError:
                # Should not happen
                return {"error": f"Predicted class {prediction_label} not found in model classes"}
            
            # Extract shap values for this specific class
            if isinstance(shap_values, list):
                # Old shap style: list of [n_samples, n_features]
                class_shap_values = shap_values[class_idx]
            else:
                # New shap style or binary: [n_samples, n_features, n_classes]
                # If binary, sometimes just [n_samples, n_features] for positive class?
                if len(shap_values.shape) == 3:
                     class_shap_values = shap_values[:, :, class_idx]
                elif len(shap_values.shape) == 2:
                    # Binary case often returns just one matrix. 
                    # If it's for the positive class (idx 1), use it. 
                    # If predicted is 0 (idx 0), we might need to negate it or it implicitly represents log-odds.
                    # For safety in this specific snippet, let's assume standard multi-class shape or list.
                    class_shap_values = shap_values
                else: 
                     return {"error": f"Unexpected SHAP values shape: {shap_values.shape}"}

            # Get values for the single instance (row 0)
            instance_values = class_shap_values[0]
            
            # Map features to values
            contributions = []
            for i, col_name in enumerate(self.feature_columns):
                val = instance_values[i]
                contributions.append({
                    "feature": col_name,
                    "impact": val,
                    "abs_impact": abs(val)
                })
                
            # Sort by absolute impact
            contributions.sort(key=lambda x: x['abs_impact'], reverse=True)
            
            # Top 3
            top_features = contributions[:3]
            
            # Format output
            result_features = []
            for item in top_features:
                direction = "increases risk" if item['impact'] > 0 else "decreases risk"
                result_features.append({
                    "feature": item['feature'], 
                    "impact": round(float(item['impact']), 4),
                    "direction": direction
                })
                
            reason_str = ", ".join([f"{f['feature']}" for f in result_features])
            
            return {
                "top_features": result_features,
                "summary": f"Flagged mainly due to {reason_str}"
            }

        except Exception as e:
            logger.exception("Error in explain_prediction")
            return {"error": str(e)}

_explainer = None

def get_explainer():
    """Singleton accessor"""
    global _explainer
    if _explainer is None:
        _explainer = ThreatExplainer()
    return _explainer
