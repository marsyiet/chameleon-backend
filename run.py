from app import create_app
from dotenv import load_dotenv
from os import getenv

load_dotenv("app/.env")

app = create_app()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(getenv("PORT", 5000)),
        debug=True
    )