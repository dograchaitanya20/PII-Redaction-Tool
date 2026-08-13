import sys
import os
from flask import Flask, jsonify

# Insert the src folder into path so existing modules are importable
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))

try:
    from redactor import PiiRedactor
    # Instantiate PiiRedactor to verify imports and models load correctly
    _ = PiiRedactor()
    print("PII Redactor imported and verified successfully.")
except Exception as e:
    print(f"Warning: could not initialize redactor on startup: {e}")

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return "PII Redaction Tool is deployed and running."

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    # Local dev server configuration
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
