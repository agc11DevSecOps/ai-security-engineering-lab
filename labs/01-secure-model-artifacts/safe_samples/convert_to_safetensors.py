"""Convert a reviewed synthetic weight pickle to the data-only safetensors format.

Static scanning can identify known unsafe serialization patterns. A data-only
format removes pickle's code-execution mechanism, but neither control proves a
model's provenance, behavior, or safety.
"""
import pickle
import torch
from safetensors.torch import save_file

INPUT_PATH = "safe_samples/safe_model.pkl"
OUTPUT_PATH = "safe_samples/safe_model.safetensors"

# This is intentionally the only pickle load in the lab: the file is a locally
# generated control fixture that has been reviewed and scanned. Never load an
# untrusted or unscanned artifact; scan first, then load only approved inputs.
with open(INPUT_PATH, "rb") as f:
    fake_weights = pickle.load(f)

# safetensors requires tensors rather than plain lists.
tensors = {k: torch.tensor(v, dtype=torch.float32) for k, v in fake_weights.items()}

save_file(tensors, OUTPUT_PATH)
print(f"Converted to safetensors: {OUTPUT_PATH}")

# Reload the data-only artifact to confirm the conversion completed.
from safetensors.torch import load_file
reloaded = load_file(OUTPUT_PATH)
print("\nTensors reloaded from safetensors:")
for k, v in reloaded.items():
    print(f"  {k}: {v.tolist()}")
