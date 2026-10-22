"""Synthetic mailbox capture; exercises CAPTCHA and the real verification route."""
from unittest.mock import patch


def verified_email(client, email="alice@stu.pku.edu.cn", purpose="register", username="alice"):
    with patch("app.services.captcha._random_answer", return_value="ABC234"):
        captcha = client.get("/captcha").get_json()
    captured = []
    with patch("app.services.email_verification.send_verification_code",
               side_effect=lambda address, code: captured.append((address, code))):
        response = client.post("/email-code", data={
            "purpose": purpose, "email": email, "username": username,
            "captcha_id": captcha["id"], "captcha_answer": "ABC234",
        })
    if response.status_code != 200:
        raise AssertionError(f"Email verification request returned {response.status_code}: {response.get_json()}")
    return {"email": email, "email_code": captured[0][1], "email_challenge": response.get_json()["id"]}
