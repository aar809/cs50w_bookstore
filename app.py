import os
from flask import Flask, session, flash, jsonify, redirect, render_template, request
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
import re
import requests
from datetime import date
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash



app = Flask(__name__)

if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods = ["GET","POST"])
# @login_required
def index():
	if request.method == "POST":
		book = request.form.get("book")
		rows = db.execute("SELECT * FROM books WHERE UPPER(title) LIKE UPPER(:book) OR UPPER(author) LIKE UPPER(:book) OR isbn LIKE UPPER(:book)", {"book": "%" + book + "%"}).fetchall()
		return render_template("results.html", results = rows)
	else:
		return render_template("index.html")


if __name__ == "__main__":
	app.run()
