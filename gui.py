import joblib
import pandas as pd
from explainability import explain_model_prediction  # Asigură-te că ai fișierul explicativ îmbunătățit

def run_explainability(model_path, sample_dict):
    """
    Încarcă modelul și generează o explicație SHAP pentru un eșantion dat.

    Args:
        model_path (str): calea către modelul .pkl
        sample_dict (dict): observație unică de analizat (feature_name: value)

    Returns:
        dict: cu cheia 'summary_base64' și 'text_explanation', sau 'error'
    """
    try:
        if not sample_dict or not isinstance(sample_dict, dict):
            raise ValueError("Eșantionul transmis trebuie să fie un dicționar valid.")

        print("[INFO] Încărcare model:", model_path)
        model = joblib.load(model_path)

        sample_df = pd.DataFrame([sample_dict])
        print("[INFO] Dimensiune eșantion pentru explicație:", sample_df.shape)

        summary_base64, text_explanation = explain_model_prediction(
            model,
            sample_df,
            feature_names=list(sample_dict.keys())
        )

        if not summary_base64 or not text_explanation:
            raise RuntimeError("Nu s-au putut genera explicațiile SHAP.")

        print("[SUCCESS] Explicație generată.")
        return {
            "summary_base64": summary_base64,
            "text_explanation": text_explanation
        }

    except Exception as e:
        print(f"[ERROR] Eroare la generarea explicației: {str(e)}")
        return {
            "error": str(e)
        }
