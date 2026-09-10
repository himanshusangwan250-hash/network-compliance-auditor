# ML Compliance Layer

## Overview
This directory contains an **isolated** machine‑learning component that augments the deterministic compliance engine. It learns the *semantic intent* of the existing six CIS policies and can recognise equivalent configuration statements across Cisco IOS, Juniper Junos, and Palo Alto PAN‑OS.

### Why a separate component?
- The existing `backend/compliance/rules_engine.py` remains the **source of truth** and is used as a fallback.
- The ML layer is **optional** – it is never invoked by the production API until we explicitly call it.
- Keeping it under `ml_compliance/` guarantees no accidental import‑side‑effects on the main application.

## Architecture
```
ml_compliance/
├─ data/                # Generated dataset (CSV files)
│   ├─ train.csv
│   ├─ val.csv
│   ├─ test.csv
│   └─ cross_vendor_test.csv
├─ model/               # Training / inference scripts
│   ├─ train.py         # CLI: generate-data, train-model
│   ├─ evaluate.py      # Evaluate trained model
│   └─ infer.py         # Inference API
├─ integration/         # Placeholder for future integration
│   └─ ml_rules.py      # Wrapper that loads the model (not used yet)
└─ configs/
    └─ model_config.yaml   # Hyper‑parameters & thresholds
```

## Dataset Generation (`train.py generate-data`)
1. **Policy knowledge base** – extracted from `rules_engine.py` (rule ID, description, severity).
2. For each rule we create:
   - `policy` – natural‑language description.
   - `security_intent` – short phrase of the intent (e.g., `"use SSH version 2"`).
   - `compliant_examples` – realistic configuration snippets for each vendor that **satisfy** the intent.
   - `violating_examples` – snippets that **violate** the intent (including adversarial look‑alikes).
3. Vendor support matrix is respected; if a vendor cannot express the rule (e.g., Cisco has no zones), the vendor is marked **unsupported** and no examples are generated for it.
4. Variations are created by:
   - Changing ordering of tokens, adding comments, using different quoting styles, optional whitespace, and alternative but equivalent CLI commands (where the parser accepts them).
   - Using different but valid values (e.g., different NTP server IPs).
5. The script writes four CSV files:
   - `train.csv` – 70 % of the examples.
   - `val.csv` – 15 % for early‑stopping.
   - `test.csv` – 15 % held‑out (same vendors as training).
   - `cross_vendor_test.csv` – each rule is **excluded** for one vendor during training; the held‑out set contains only that vendor’s examples to evaluate cross‑vendor generalisation.

## Training (`train.py train-model`)
- **Model**: `all-MiniLM-L6-v2` from *sentence‑transformers*.
- **Fine‑tuning method**: **SetFit** – a lightweight adapter that trains a logistic‑regression classifier on top of frozen embeddings. It works well with a few thousand examples and needs minimal GPU memory.
- The script:
  1. Detects CUDA (`torch.cuda.is_available()`). If unavailable it falls back to CPU and prints a warning.
  2. Prints GPU name, PyTorch version, and CUDA version.
  3. Loads the training/validation CSVs.
  4. Trains for **3‑5 epochs** (configurable) with a small batch size (16).
  5. Uses early stopping on validation F1.
  6. Saves the best checkpoint to `model/setfit/`.

## Evaluation (`evaluate.py`)
- Loads the best checkpoint.
- Computes **accuracy, precision, recall, F1**, and a **confusion matrix**.
- Reports per‑vendor, per‑rule, and cross‑vendor metrics.
- Prints the number of examples in each split.

## Inference (`infer.py`)
```bash
python infer.py \
  --policy "SSH must use secure protocol version 2" \
  --config "ip ssh version 2" \
  --vendor cisco
```
Outputs JSON:
```json
{
  "rule_id": "CIS-1.2",
  "prediction": "compliant",
  "confidence": 0.94,
  "vendor": "cisco",
  "explanation": "Detected SSH version 2 configuration."
}
```
If `confidence` < *threshold* (default 0.6, configurable in `model_config.yaml`) the `prediction` field is set to `"uncertain"`.

## How This Differs From the Deterministic Engine
| Aspect | Deterministic Engine | ML Layer |
|--------|----------------------|----------|
| **Logic** | Hand‑written rule checks on normalized data. | Learns semantic intent from examples. |
| **Coverage** | Limited to fields parsed by the vendor parsers. | Can infer intent even when the parser misses a field (e.g., alternative CLI syntax). |
| **Explainability** | Exact rule ID and evidence string. | Model provides confidence and a short natural‑language explanation. |
| **Fallback** | Always used; results are authoritative. | Optional – called only after the deterministic check returns *UNKNOWN* or when explicitly requested. |
| **Maintenance** | Requires code changes for new policies. | New policies added by extending the dataset and retraining. |

---

**Next steps** after dataset generation and model training:
1. Review the generated CSVs.
2. Run `python model/train.py train-model`.
3. Run `python model/evaluate.py` and inspect the metrics.
4. If satisfactory, integrate `ml_rules.py` into the main engine (outside the scope of this initial implementation).

---

*All scripts are self‑contained and can be executed from the repository root.*