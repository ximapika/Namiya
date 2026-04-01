import logging
import sys

from app import create_app
from app.bootstrap import bootstrap_database


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)

app = create_app()


if __name__ == "__main__":
    with app.app_context():
        bootstrap_database()
    app.run(host="0.0.0.0", port=50000, debug=False)
