from dataclasses import dataclass

from flask import abort, current_app, request, url_for
from sqlalchemy import func

from ..extensions import db


@dataclass
class Page:
    items: list
    page: int
    per_page: int
    total: int
    parameter: str

    @property
    def pages(self) -> int:
        return max(1, (self.total + self.per_page - 1) // self.per_page)

    def url(self, page: int) -> str:
        args = request.args.to_dict()
        args.update(request.view_args or {})
        args[self.parameter] = page
        return url_for(request.endpoint, **args)


def paginate(query, *, parameter="page") -> Page:
    try:
        page = int(request.args.get(parameter, "1"))
        per_page = int(request.args.get("per_page", current_app.config.get("PAGE_SIZE", 20)))
    except (ValueError, TypeError):
        abort(400, "分页参数无效")
    if page < 1 or per_page < 1:
        abort(400, "分页参数无效")
    per_page = min(per_page, 50)
    # Query.count() wraps the original ORM projection, including deferred body,
    # password and email columns. Count only rows while retaining FROM/filters.
    count_statement = query.order_by(None).statement.with_only_columns(
        func.count(), maintain_column_froms=True
    )
    total = db.session.execute(count_statement).scalar_one()
    pages = max(1, (total + per_page - 1) // per_page)
    if page > pages:
        abort(404)
    items = query.limit(per_page).offset((page - 1) * per_page).all()
    return Page(items, page, per_page, total, parameter)
