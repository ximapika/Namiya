"""SMTP delivery. Recipient addresses live only for the duration of a request."""
import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app


class MailUnavailable(RuntimeError):
    pass


def send_verification_code(recipient: str, code: str) -> None:
    config = current_app.config
    if not config.get("MAIL_HOST") or not config.get("MAIL_FROM"):
        raise MailUnavailable("邮件服务暂不可用，请稍后再试。")
    if not (config.get("MAIL_USE_TLS") or config.get("MAIL_USE_SSL")):
        raise MailUnavailable("邮件服务暂不可用，请稍后再试。")

    message = EmailMessage()
    message["Subject"] = "解忧杂货铺 · 邮箱验证码"
    message["From"] = config["MAIL_FROM"]
    message["To"] = recipient
    minutes = max(1, config["EMAIL_CODE_TTL_SECONDS"] // 60)
    message.set_content(
        f"你的验证码是：{code}\n\n有效期 {minutes} 分钟，仅可使用一次。"
        "\n请勿向他人透露验证码；如果不是你发起的请求，请忽略本邮件。"
        "\n\n邮件中不包含你的账号名或信件内容。"
    )
    smtp_class = smtplib.SMTP_SSL if config["MAIL_USE_SSL"] else smtplib.SMTP
    kwargs = {"timeout": config["MAIL_TIMEOUT_SECONDS"]}
    if config["MAIL_USE_SSL"]:
        kwargs["context"] = ssl.create_default_context()
    try:
        with smtp_class(config["MAIL_HOST"], config["MAIL_PORT"], **kwargs) as server:
            if config["MAIL_USE_TLS"] and not config["MAIL_USE_SSL"]:
                server.starttls(context=ssl.create_default_context())
            if config.get("MAIL_USERNAME"):
                server.login(config["MAIL_USERNAME"], config.get("MAIL_PASSWORD", ""))
            server.send_message(message)
    except (OSError, smtplib.SMTPException):
        # SMTP exception strings can contain recipient addresses or credentials.
        current_app.logger.warning("Verification email delivery failed.")
        raise MailUnavailable("邮件暂时无法发送，请稍后再试。") from None
