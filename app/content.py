from flask import session, url_for


THEME_OPTIONS = [
    {
        "key": "starlight",
        "label": "星夜月白",
        "description": "深靛夜空、月光留白和一点金色，沿用海报的安静陪伴感。",
        "preview": ["#10152E", "#5561C4", "#F2C172"],
    },
    {
        "key": "paper",
        "label": "纸页琥珀",
        "description": "偏暖的信纸质感，适合更传统、更温柔的杂货铺氛围。",
        "preview": ["#FAF5E9", "#C8922A", "#6B3A22"],
    },
    {
        "key": "mist",
        "label": "晨雾青岚",
        "description": "低饱和青蓝与米白，观感更克制，也更偏现代。",
        "preview": ["#EAF3F2", "#76A7AA", "#29495F"],
    },
]
THEME_OPTION_MAP = {theme["key"]: theme for theme in THEME_OPTIONS}
DEFAULT_THEME = "starlight"

PROMO_SLIDES = [
    {
        "label": "深夜倾听",
        "eyebrow": "Hello I'm listening to you",
        "title": "写下心事，或留下一个电话，等一声温柔回应",
        "description": "如果你想被听见，也可以登记电话倾诉。来信与来电，都会被认真接住。",
        "image": "img/promos/c7ba9d7ccb8c822979aa3980c5b53bab.jpg",
        "tone": "月色夜航",
        "link": "user.write",
        "link_text": "开始倾诉",
    },
    {
        "label": "温柔回应",
        "eyebrow": "We are here for you",
        "title": "把难以启齿的心事，放进会发光的门里",
        "description": "无论是学业压力、关系困惑，还是一句说不出口的话，都可以在这里慢慢写下来。",
        "image": "img/promos/c7ba9d7ccb8c822979aa3980c5b53bab-1.jpg",
        "tone": "微光回信",
        "link": "auth.register",
        "link_text": "进入信箱",
    },
]


def active_theme_name() -> str:
    theme_name = session.get("theme_name", DEFAULT_THEME)
    if theme_name not in THEME_OPTION_MAP:
        return DEFAULT_THEME
    return theme_name


def build_promo_slides() -> list[dict]:
    slides = []
    for slide in PROMO_SLIDES:
        slide_data = dict(slide)
        slide_data["image_url"] = url_for("static", filename=slide["image"])
        slide_data["link_url"] = url_for(slide["link"]) if slide.get("link") else None
        slides.append(slide_data)
    return slides
