from flask import Flask, jsonify, request

from jwt_service import generate_access_token
from cert_utils import (
    extract_thumbprint_from_xfcc,
    extract_cn_from_xfcc
)

app = Flask(__name__)
    
@app.route("/auth/login", methods=["POST"])
def login():

    xfcc = request.headers.get(
        "x-forwarded-client-cert"
    )

    if not xfcc:
        return jsonify({
            "error": "Missing XFCC header"
        }), 400

    try:
        thumbprint = extract_thumbprint_from_xfcc(
            xfcc
        )

        client_id = extract_cn_from_xfcc(
            xfcc
        )

    except ValueError as e:
        return jsonify({
            "error": str(e)
        }), 400

    token = generate_access_token(
        client_id,
        thumbprint
    )

    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=True
    )