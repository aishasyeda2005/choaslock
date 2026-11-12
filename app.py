"""ChaosLock Flask web application.

Exposes REST endpoints for:
- Image encryption (/encrypt)
- Image decryption (/decrypt)
- Cryptographic security analysis (/analyze)
- Interactive web frontend (/)
"""
import io
import base64
import os
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from PIL import Image

from engine.crypto import encrypt, decrypt
from engine.analysis import run_full_analysis

app = Flask(__name__)

# Security & Validation constraints
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # Max 5 MB upload limit
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}


def _is_allowed_file(filename: str) -> bool:
    """Check if uploaded file has an allowed image extension."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    """Handle uploads exceeding the 5 MB limit."""
    return jsonify({"error": "File size exceeds the 5 MB limit. Please upload a smaller image."}), 413


@app.route("/")
def index():
    """Render the single-page application."""
    return render_template("index.html")


@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    """Encrypt an uploaded PNG/JPG image with a user password.

    Returns:
        Encrypted PNG file (lossless).
    """
    # Step 1: Validate file presence
    if "file" not in request.files:
        return jsonify({"error": "No image file provided in request."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not _is_allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Allowed formats: PNG, JPG, JPEG."}), 400

    # Step 2: Validate password (never logged or saved)
    password = request.form.get("password", "").strip()
    if not password:
        return jsonify({"error": "Password cannot be empty."}), 400

    try:
        # Step 3: Load image and execute chaotic encryption
        img = Image.open(file.stream)
        encrypted_img = encrypt(img, password)

        # Step 4: Stream encrypted image as PNG
        out_buf = io.BytesIO()
        encrypted_img.save(out_buf, format="PNG")
        out_buf.seek(0)

        # Return as downloadable PNG
        return send_file(
            out_buf,
            mimetype="image/png",
            as_attachment=True,
            download_name="encrypted.png",
        )
    except Exception as e:
        # Return friendly error message without leaking sensitive internal details
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    """Decrypt an uploaded encrypted PNG image with a password.

    Returns:
        Decrypted PNG file.
    """
    if "file" not in request.files:
        return jsonify({"error": "No encrypted image file provided in request."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not _is_allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Encrypted image must be PNG."}), 400

    password = request.form.get("password", "").strip()
    if not password:
        return jsonify({"error": "Password cannot be empty."}), 400

    try:
        img = Image.open(file.stream)
        decrypted_img = decrypt(img, password)

        out_buf = io.BytesIO()
        decrypted_img.save(out_buf, format="PNG")
        out_buf.seek(0)

        return send_file(
            out_buf,
            mimetype="image/png",
            as_attachment=True,
            download_name="decrypted.png",
        )
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500


@app.route("/analyze", methods=["POST"])
def analyze_route():
    """Perform security analysis comparing original and encrypted images.

    Returns:
        JSON containing entropy, correlation metrics, PASS/FAIL verdict,
        and base64-encoded comparison histogram plot.
    """
    if "original" not in request.files or "encrypted" not in request.files:
        return jsonify({"error": "Both original and encrypted images are required for analysis."}), 400

    orig_file = request.files["original"]
    enc_file = request.files["encrypted"]

    if orig_file.filename == "" or enc_file.filename == "":
        return jsonify({"error": "Both original and encrypted image files must be selected."}), 400

    if not _is_allowed_file(orig_file.filename) or not _is_allowed_file(enc_file.filename):
        return jsonify({"error": "Invalid file type. Allowed formats: PNG, JPG, JPEG."}), 400

    try:
        orig_img = Image.open(orig_file.stream)
        enc_img = Image.open(enc_file.stream)

        # Run analysis module
        analysis_data = run_full_analysis(orig_img, enc_img)

        # Encode histogram image to base64 data URI for direct frontend display
        histogram_b64 = base64.b64encode(analysis_data["histogram_bytes"]).decode("utf-8")
        histogram_data_uri = f"data:image/png;base64,{histogram_b64}"

        return jsonify({
            "original": analysis_data["original"],
            "encrypted": analysis_data["encrypted"],
            "verdict": analysis_data["verdict"],
            "histogram_image": histogram_data_uri,
        })
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


if __name__ == "__main__":
    # Host on port 5000 for local access
    app.run(host="127.0.0.1", port=5000, debug=True)

