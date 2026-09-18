"""Create a synthetic benign pickle fixture for static-analysis control testing.

The fixture represents a simple weight dictionary. A scanner should report no
issues; it is not a real model or a provenance claim.
"""
import pickle

# Simulate a PyTorch-like state dictionary: layer names map to float lists.
fake_weights = {
    "layer1.weight": [0.12, -0.45, 0.89, 0.03],
    "layer1.bias": [0.01, -0.02],
    "layer2.weight": [0.55, 0.10, -0.33],
}

output_path = "safe_samples/safe_model.pkl"
with open(output_path, "wb") as f:
    pickle.dump(fake_weights, f)

print(f"Benign control pickle created at: {output_path}")
