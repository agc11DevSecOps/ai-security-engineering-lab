"""Create an unsafe pickle fixture for static-analysis testing only.

The payload would create a local marker file only if an unsafe deserialization
occurred. It is non-destructive and makes no network request. Never load this
fixture; scan it statically instead.
"""
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # Pickle serializes this as: "when reconstructing this object, call this."
        cmd = "touch /tmp/pwned_by_pickle_demo.txt"
        return (os.system, (cmd,))

output_path = "malicious_samples/malicious_model.pkl"
with open(output_path, "wb") as f:
    pickle.dump(MaliciousPayload(), f)

print(f"Unsafe test pickle created at: {output_path}")
print("Never load it with pickle.load(); inspect it with static analysis only.")
