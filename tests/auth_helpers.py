"""Exercise the real encrypted browser protocol in integration tests."""

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def encrypted_password(client, purpose, password, *, nonce=None):
    response = client.get("/password-challenge", query_string={"purpose": purpose})
    if response.status_code != 200:
        raise AssertionError(f"Challenge creation returned {response.status_code}")
    challenge = response.get_json()
    return encrypt_challenge(challenge, password, nonce=nonce)


def encrypt_challenge(challenge, password, *, nonce=None):
    public_key = serialization.load_pem_public_key(challenge["public_key"].encode("ascii"))
    payload = json.dumps({
        "password_b64": base64.b64encode(password.encode("utf-8")).decode("ascii"),
        "nonce": challenge["nonce"] if nonce is None else nonce,
    }, separators=(",", ":")).encode("utf-8")
    ciphertext = public_key.encrypt(payload, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None,
    ))
    return {"password_challenge": challenge["id"],
            "password_envelope": base64.b64encode(ciphertext).decode("ascii")}
