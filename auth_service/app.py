from flask import Flask, jsonify, request
import jwt
from jwt_service import (
    generate_access_token,
    verify_access_token
)
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

@app.route("/verify", methods=["POST"])
def verify():

    auth_header = request.headers.get(
        "Authorization"
    )

    if not auth_header:
        return jsonify({
            "error": "Missing Authorization header"
        }), 401

    if not auth_header.startswith(
        "Bearer "
    ):
        return jsonify({
            "error": "Invalid Authorization header"
        }), 401

    token = auth_header.split(
        " ", 1
    )[1]

    xfcc = request.headers.get(
        "x-forwarded-client-cert"
    )

    if not xfcc:
        return jsonify({
            "error": "Missing XFCC header"
        }), 400

    try:

        payload = verify_access_token(
            token
        )

        jwt_thumbprint = (
            payload
            .get("cnf", {})
            .get("x5t#S256")
        )

        if not jwt_thumbprint:
            return jsonify({
                "error": "Missing cnf thumbprint"
            }), 403

        current_thumbprint = (
            extract_thumbprint_from_xfcc(
                xfcc
            )
        )

        if jwt_thumbprint != current_thumbprint:
            return jsonify({
                "error": "certificate binding failed"
            }), 403

        return jsonify({
            "status": "ok",
            "subject": payload.get("sub")
        }), 200

    except jwt.InvalidTokenError as e:
        return jsonify({
            "error": str(e)
        }), 403

    except ValueError as e:
        return jsonify({
            "error": str(e)
        }), 400

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=True
    )