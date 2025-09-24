# app.py
from flask import Flask, request, jsonify
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import traceback

app = Flask(__name__)
BASE_URL = "https://pkmkb.free.nf/api.php"

# Hex values copied from the upstream JS
A_HEX = "f655ba9d09a112d4968c63579db590b4"
B_HEX = "98344c2eee86c3994890592585b49f80"
C_HEX = "a0ec2500a5bd2cdf8fdd40b6792072d3"

# Convert hex to bytes
A = bytes.fromhex(A_HEX)
B = bytes.fromhex(B_HEX)
C = bytes.fromhex(C_HEX)

# AES modes to try
MODE_TRIALS = [
    ("CBC", AES.MODE_CBC),
    ("ECB", AES.MODE_ECB),
    ("CFB", AES.MODE_CFB),
    ("OFB", AES.MODE_OFB),
]

def try_decrypt_variants(key_bytes, iv_bytes, cipher_bytes):
    tried = set()
    key_iv_pairs = [
        ("A_key_B_iv", (key_bytes, iv_bytes)),
        ("B_key_A_iv", (iv_bytes, key_bytes)),
    ]

    for pair_label, (key, iv) in key_iv_pairs:
        for mode_name, mode_const in MODE_TRIALS:
            try:
                cipher = AES.new(key, mode_const, iv=iv if mode_const != AES.MODE_ECB else None)
                plain = cipher.decrypt(cipher_bytes)

                # raw hex
                cand_raw = binascii.hexlify(plain).decode().lower()
                if cand_raw not in tried:
                    tried.add(cand_raw)
                    yield cand_raw

                # try PKCS7 unpad
                try:
                    p = unpad(plain, AES.block_size)
                    cand_unp = binascii.hexlify(p).decode().lower()
                    if cand_unp not in tried:
                        tried.add(cand_unp)
                        yield cand_unp
                except Exception:
                    pass
            except Exception:
                continue

@app.route("/proxy", methods=["GET"])
def proxy():
    number = request.args.get("number")
    if not number:
        return jsonify({"error": "Missing number"}), 400

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/115.0 Safari/537.36"
    }

    last_response_text = None
    last_status = None
    last_headers = None

    try:
        for cand_hex in try_decrypt_variants(A, B, C):
            headers_loc = dict(headers)
            headers_loc["Cookie"] = f"__test={cand_hex}"

            try:
                r = requests.get(BASE_URL, params={"number": number, "i": "2"}, headers=headers_loc, timeout=15)
            except Exception as e:
                last_response_text = f"request failed: {str(e)}"
                continue

            last_status = r.status_code
            last_headers = dict(r.headers)
            last_response_text = r.text or ""

            # Try parse JSON
            try:
                data = r.json()
                if isinstance(data, dict) and "credit" in data:
                    data["credit"] = "API OWNER : @frappeash"
                return jsonify({
                    "status": "success",
                    "data": data
                })
            except Exception:
                pass

        # Nothing produced JSON
        debug = {
            "error": "No candidate produced JSON response",
            "last_status": last_status,
            "last_headers": last_headers,
            "last_body_preview": (last_response_text[:2000] if last_response_text else None),
        }
        return jsonify(debug), 502

    except Exception:
        return jsonify({"error": "Internal error", "trace": traceback.format_exc()}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
