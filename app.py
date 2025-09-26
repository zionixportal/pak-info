import re, requests
from flask import Flask, jsonify, request
from Crypto.Cipher import AES

app = Flask(__name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/117 Safari/537.36",
    "Referer": "https://pkmkb.free.nf/"
}

def hexpairs_to_bytes(s):
    if len(s) % 2 != 0:
        s = "0" + s
    return bytes.fromhex(s)

def pkcs7_unpad(b):
    pad = b[-1]
    if 1 <= pad <= AES.block_size and b[-pad:] == bytes([pad])*pad:
        return b[:-pad]
    return b

def compute_cookie(url):
    r = requests.get(url, headers=HEADERS, timeout=15)
    html = r.text

    # Extract a,b,c
    hex_matches = re.findall(r'toNumbers\("([0-9a-fA-F]+)"\)', html)
    if len(hex_matches) < 3:
        return None, None
    a_hex, b_hex, c_hex = hex_matches[0], hex_matches[1], hex_matches[2]

    # Extract redirect target
    m_href = re.search(r'location\.href\s*=\s*"([^"]+)"', html)
    target_url = m_href.group(1) if m_href else url

    # Decrypt c
    key = hexpairs_to_bytes(a_hex)
    iv  = hexpairs_to_bytes(b_hex)
    ct  = hexpairs_to_bytes(c_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = pkcs7_unpad(cipher.decrypt(ct))
    cookie_val = pt.hex()
    return target_url, cookie_val

@app.route("/proxy")
def proxy():
    number = request.args.get("number")
    if not number:
        return jsonify({"error": "Missing number"}), 400

    start_url = f"https://pkmkb.free.nf/api.php?number={number}&i=2"
    target_url, cookie_val = compute_cookie(start_url)
    if not cookie_val:
        return jsonify({"error": "Failed to compute cookie"}), 500

    cookies = {"__test": cookie_val}
    resp = requests.get(target_url, headers=HEADERS, cookies=cookies, timeout=15)
    try:
        data = resp.json()
        data["credit"] = "API OWNER : @frappeash & @zioniiix"
        return jsonify(data)
    except Exception:
        return jsonify({"error": "Not JSON", "preview": resp.text[:500]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
