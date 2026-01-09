from flask import Flask, request, jsonify
from flask_cors import CORS
from parser.pcap_parser import parse_pcap

app = Flask(__name__)
CORS(app)

@app.route("/parse", methods=["POST"])
def parse_endpoint():
    data = request.get_json()

    if not data or "file_path" not in data:
        return jsonify({"error": "file_path is required"}), 400

    try:
        packets = parse_pcap(data["file_path"])
        return jsonify(packets)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)