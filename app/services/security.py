import re


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-\u4e00-\u9fff]{2,20}$")
PHONE_PATTERN = re.compile(r"^[0-9+\-()\s]{6,20}$")


def normalize_username(value: str) -> str:
    return value.strip()


def normalize_phone(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def sanitize_text(value: str, *, max_length: int, multiline: bool = True) -> str:
    normalized = value.replace("\r\n", "\n")
    if multiline:
        normalized = "\n".join(line.rstrip() for line in normalized.split("\n")).strip()
    else:
        normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized[:max_length]


def validate_registration(*, username: str, password: str, confirm: str, min_length: int) -> list[str]:
    errors: list[str] = []
    if not username:
        errors.append("用户名不能为空")
    elif not USERNAME_PATTERN.fullmatch(username):
        errors.append("用户名只能包含中文、字母、数字、下划线或短横线，长度 2 到 20 位")

    if not password:
        errors.append("密码不能为空")
    elif len(password) < min_length:
        errors.append(f"密码长度至少需要 {min_length} 个字符")
    elif password != confirm:
        errors.append("两次输入的密码不一致")
    return errors


def validate_letter_submission(form) -> tuple[list[str], dict]:
    msg_type = form.get("type", "letter").strip()
    title = sanitize_text(form.get("title", ""), max_length=100, multiline=False)
    content = sanitize_text(form.get("content", ""), max_length=5000)
    phone_title = sanitize_text(form.get("phone_title", ""), max_length=100, multiline=False)
    phone_content = sanitize_text(form.get("phone_content", ""), max_length=5000)
    phone_number = normalize_phone(form.get("phone_number", ""))
    preferred_call_time = sanitize_text(
        form.get("preferred_call_time", ""),
        max_length=80,
        multiline=False,
    )

    if msg_type not in {"letter", "phone"}:
        msg_type = "letter"

    if msg_type == "phone":
        title = phone_title or title
        content = phone_content or content

    errors: list[str] = []
    if not title:
        errors.append("请填写主题")
    if msg_type == "letter" and not content:
        errors.append("请填写信件内容")
    if msg_type == "phone":
        if not phone_number:
            errors.append("请填写您的联系电话")
        elif not PHONE_PATTERN.fullmatch(phone_number):
            errors.append("联系电话格式不正确")
        if not preferred_call_time:
            errors.append("请填写您希望的来电时间")

    return errors, {
        "type": msg_type,
        "title": title,
        "content": content,
        "phone_number": phone_number,
        "preferred_call_time": preferred_call_time,
    }


def validate_reply_content(content: str) -> tuple[list[str], str]:
    value = sanitize_text(content, max_length=4000)
    if not value:
        return ["回复内容不能为空"], ""
    return [], value
