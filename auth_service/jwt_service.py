import jwt
import time
import uuid

def get_private_key():
    with open("keys/private.pem") as f:
        return f.read()


def generate_access_token(client_id, thumbprint):

    now = int(time.time())

    payload = {
        "iss": "https://auth.zero-trust.local",

        "sub": client_id,

        "aud": "https://api.resource.local",

        "exp": now + 3600,

        "nbf": now,

        "iat": now,

        "jti": str(uuid.uuid4()),

        "scope": "read:resources write:resources",

        "cnf": {
            "x5t#S256": thumbprint
        }
    }

    headers = {
        "alg": "RS256",
        "typ": "at+jwt",
        "kid": "auth-service-key-2026"
    }

    token = jwt.encode(
        payload,
        get_private_key(),
        algorithm="RS256",
        headers=headers
    )

    return token