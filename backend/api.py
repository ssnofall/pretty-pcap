from flask import Flask, request, jsonify
from flask_cors import CORS
from parser.pcap_parser import parse_pcap
import traceback

app = Flask(__name__)
CORS(app)

@app.route("/parse", methods=["POST"])
def parse_endpoint():
    data = request.get_json()

    if not data or "file_path" not in data:
        return jsonify({"error": "file_path is required"}), 400

    try:
        result = parse_pcap(data["file_path"])
        return jsonify(result)
    except FileNotFoundError:
        return jsonify({"error": f"File not found: {data['file_path']}"}), 404
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"Error parsing PCAP: {error_details}")
        return jsonify({"error": str(e), "details": error_details}), 500

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)