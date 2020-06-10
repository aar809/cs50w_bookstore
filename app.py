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
@login_required
def index():
	if request.method == "POST":
		book = request.form.get("book")
		rows = db.execute("SELECT * FROM books WHERE UPPER(title) LIKE UPPER(:book) OR UPPER(author) LIKE UPPER(:book) OR isbn LIKE UPPER(:book)", {"book": "%" + book + "%"}).fetchall()
		return render_template("results.html", results = rows)
	else:
		return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    # Forget any user_id
	session.clear()
    # User reached route via POST (as by submitting a form via POST)
	if request.method == "POST":
		# Ensure username was submitted
		if not request.form.get("username"):
			message = "Need a username."
			return message

        # Ensure password was submitted
		elif not request.form.get("password"):
			message = "Need a password."
			return message
		username = request.form.get("username")
		# Query database for username
		rows = db.execute("SELECT * FROM users WHERE username = :username", {"username": request.form.get("username")}).fetchall()

		if len(rows) != 0:
		    message = "Username taken."
		    return message
		elif re.search('[!@#$%^&*()\s]', request.form.get("username")) != None:
		     return "Username can't have space or special characters."
		elif len(request.form.get("password")) < 8 or len(request.form.get("password")) > 25:
			return "Password length needs to be between 8 to 25."
		elif re.search('[a-z]', request.form.get("password")) == None:
		    return "Password needs a lowercase letter."
		elif re.search('[A-Z]', request.form.get("password")) == None:
		    return "Password needs an uppercase letter."
		elif re.search('[0-9]', request.form.get("password")) == None:
			return "Password needs a number."
		elif request.form.get("password") != request.form.get("password2"):
			return "Password fields do not match."
		else:
			username = request.form.get("username")
			first_name = request.form.get("first_name")
			last_name = request.form.get("last_name")
			password = generate_password_hash(request.form.get("password"))
			current_date = date.today()

			db.execute("INSERT INTO users (username, first_name, last_name, password, date_joined) VALUES (:username, :first_name, :last_name, :password, :date_joined)",{"username":username, "first_name":first_name, "last_name":last_name, "password":password, "date_joined":current_date})
			db.commit()
			flash("Account created")
			return redirect("/")
	else:
		return render_template("register.html")	

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return "Must provide username"

        # Ensure password was submitted
        elif not request.form.get("password"):
            return "Must provide password"

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          {"username":request.form.get("username")}).fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
             return "Invalid username and/or password."
 
        # or not check_password_hash(rows[0]["hash"], request.form.get("password")):

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]
        session["username"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/book/<isbn>", methods=["GET", "POST"])
@login_required
def book(isbn):
	if request.method == 'POST':	
		if request.form["btn"]=="submit":
			review = request.form.get("review")
			user_id = session["user_id"]
			rating = request.form.get("rating")
			review_date = date.today().strftime("%b-%d-%Y")
			# isbn = isbn
					
			# Query database for existing reviews by user for this book
			rows = db.execute("SELECT * FROM reviews WHERE isbn = :isbn AND user_id = :user_id", {"isbn": isbn, "user_id":user_id}).fetchall()
	        # Ensure username DOES NOT already exist.
			if len(rows) != 0:
			    message = "Already reviewed. Cannot review the same book twice!"
			    return message
			else:
				# isbn = isbn
				db.execute("INSERT INTO reviews (user_id, review_text, isbn, rating, date) VALUES (:user_id, :review_text, :isbn, :rating, :date)",{"user_id":user_id, "review_text":review, "isbn":isbn, "rating": rating, "date": review_date})
				db.commit()
				flash("Review submitted!")
				return redirect("/book/"+isbn)
			# db.execute("INSERT INTO reviews (user_id, review_text, isbn) VALUES (:user_id, :review_text, :isbn)",{"user_id":user_id, "review_text":review, "isbn":isbn})
		elif request.form["btn"]=="delete":
			user_id = session["user_id"]
			db.execute("DELETE FROM reviews WHERE user_id = :user_id", {"user_id" :user_id})
			db.commit()
			flash("Review deleted!")
			return redirect("/book/"+isbn)	
		elif request.form["btn"]=="like":
			user_id = session["user_id"]
			review_id = request.form.get("review_id")
			likes = db.execute("SELECT likes FROM reviews WHERE review_id = :review_id", {"review_id": review_id}).fetchall()
			likes = likes[0][0]
			# return "Total likes are:" + str(likes[0][0])		
			new_likes = likes+1
			db.execute("UPDATE reviews SET likes = :new_likes WHERE review_id = :review_id",{"new_likes": new_likes, "review_id": review_id})
			db.commit()
			return redirect("/book/"+isbn)
			# db.execute("DELETE FROM reviews WHERE user_id = :user_id", {"user_id" :user_id})
			# db.commit()
			# flash("Review liked!")
			# return redirect("/book/"+isbn)	

	else:
		rows = db.execute("SELECT * FROM books WHERE isbn = :isbn", {"isbn": isbn}).fetchall()
		reviews = db.execute("SELECT * FROM reviews JOIN users ON reviews.user_id = users.user_id WHERE isbn = :isbn", {"isbn": isbn}).fetchall()
		review_count = db.execute("SELECT COUNT(review_text) as count FROM reviews WHERE isbn = :isbn", {"isbn": isbn}).fetchall()
		goodreads = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": "T0p4jpsKI1Twqw4QwmAtw", "isbns": isbn}).json()
		current_user = session["user_id"]
		return render_template("book.html", rows=rows, reviews=reviews, goodreads=goodreads, review_count=review_count, current_user=current_user )

@app.route("/api/<isbn>", methods=["GET"])
@login_required
def api(isbn):
	rows = db.execute("SELECT * FROM books WHERE isbn = :isbn", {"isbn": isbn}).fetchall()
	reviews = db.execute("SELECT * FROM reviews JOIN users ON reviews.user_id = users.user_id WHERE isbn = :isbn", {"isbn": isbn}).fetchall()
	review_count = db.execute("SELECT COUNT(review_text) as count, AVG(rating) as average FROM reviews WHERE isbn = :isbn", {"isbn": isbn}).fetchall()	
	return render_template("api.html", rows=rows, review_count=review_count)

@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":

        rows = db.execute("SELECT * FROM users WHERE id = :user_id",
                          user_id = session["user_id"])
        # Ensure username exists and password is correct
        if not check_password_hash(rows[0]["password"], request.form.get("old_password")):
            return "Incorrect old password"

        # Ensure password was submitted
        if not request.form.get("new_password1"):
            return "Must provide new password."
        elif len(request.form.get("new_password1")) < 8 or len(request.form.get("new_password1")) > 25:
            return "Password length needs to be between 8 to 25."
        elif re.search('[a-z]', request.form.get("new_password1")) == None:
            return "Password needs a lowercase letter."
        elif re.search('[A-Z]', request.form.get("new_password1")) == None:
            return "Password needs an uppercase letter."
        elif re.search('[0-9]', request.form.get("new_password1")) == None:
            return "Password needs a number."
        elif request.form.get("new_password1") != request.form.get("new_password2"):
            return "Password fields do not match."
        elif request.form.get("new_password1") == request.form.get("old_password"):
            return "New password can't be same as old."
        # elif re.search('[!@#$%^&*()]', request.form.get("password")) == None:
        #     return apology("Password needs a special character.")
        else:
            rows = db.execute("UPDATE users SET password = :new_password WHERE id = :user_id",
            user_id=session["user_id"], new_password = generate_password_hash(request.form.get("new_password1")))
        return render_template("index.html")
    else:
        return render_template("account.html")


if __name__ == "__main__":
	app.run()
