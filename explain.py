import os
import shap
import numpy as np
import pandas as pd
import logging
from io import BytesIO
import base64
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Optional, Sequence, Tuple, Union

# Configurare logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Configurări de securitate și performanță
MAX_ROWS = int(os.getenv("SHAP_MAX_ROWS", 100))
MAX_DISPLAY = int(os.getenv("SHAP_MAX_DISPLAY", 10))
SHAP_CACHE_ENABLED = os.getenv("SHAP_CACHE_ENABLED", "true").lower() == "true"

# Cache pentru explainers (model_id -> shap.Explainer)
_explainer_cache: dict[int, shap.Explainer] = {}

# Funcție pentru obținerea explain-er-ului, cu caching
def _get_explainer(model: object, data_sample: pd.DataFrame) -> shap.Explainer:
    key = id(model)
    if SHAP_CACHE_ENABLED and key in _explainer_cache:
        logger.debug("Folosesc explainer din cache pentru model %s", key)
        return _explainer_cache[key]
    logger.info("Creare shap.Explainer pentru model %s", key)
    explainer = shap.Explainer(model, data_sample)
    if SHAP_CACHE_ENABLED:
        _explainer_cache[key] = explainer
    return explainer


def explain_model_prediction(
    model: object,
    data_sample: Union[pd.DataFrame, np.ndarray],
    feature_names: Optional[Sequence[str]] = None,
    max_display: Optional[int] = None
) -> Tuple[str, str]:
    """
    Generează explicații SHAP sub formă de imagine (base64) și text.

    Args:
        model: Modelul antrenat (ex: XGBoost, LightGBM etc.)
        data_sample: pd.DataFrame sau np.ndarray cu cel mult MAX_ROWS rânduri.
        feature_names: Lista de nume de coloane (opțional).
        max_display: Câte feature-uri să afișeze în explicație (opțional).

    Returns:
        summary_base64: PNG summary plot codificat base64.
        text_explanation: Explicație textuală a principalelor feature-uri SHAP.
    """
    try:
        # Convertire și validare data_sample
        if isinstance(data_sample, np.ndarray):
            df = pd.DataFrame(data_sample, columns=feature_names) if feature_names else pd.DataFrame(data_sample)
        elif isinstance(data_sample, pd.DataFrame):
            df = data_sample.copy()
            if feature_names:
                df.columns = feature_names
        else:
            raise ValueError("data_sample trebuie să fie DataFrame sau ndarray.")

        n_rows = df.shape[0]
        if n_rows == 0 or n_rows > MAX_ROWS:
            raise ValueError(f"Număr invalid de rânduri: {n_rows}. Rămâi între 1 și {MAX_ROWS}.")

        # Setare max_display
        max_disp = max_display if max_display is not None else MAX_DISPLAY
        max_disp = min(max_disp, df.shape[1])

        # Obține explainer și valori SHAP
        explainer = _get_explainer(model, df)
        shap_values = explainer(df)

        # Summary plot
        plt.figure()
        shap.summary_plot(
            shap_values,
            df,
            feature_names=feature_names,
            show=False,
            max_display=max_disp
        )
        plt.tight_layout()
        buffer = BytesIO()
        plt.savefig(buffer, format="png")
        plt.close()
        buffer.seek(0)
        summary_base64 = base64.b64encode(buffer.read()).decode("utf-8")
        buffer.close()

        # Textual explanation: top contributions pentru primul rând
        contrib = list(zip(df.columns.tolist(), shap_values.values[0].tolist()))
        contrib_sorted = sorted(contrib, key=lambda x: abs(x[1]), reverse=True)[:max_disp]
        lines = [f"{name}: {val:.4f}" for name, val in contrib_sorted]
        text_explanation = "\n".join(lines)

        return summary_base64, text_explanation

    except Exception as e:
        logger.error("Eroare la explain_model_prediction: %s", e)
        raise
