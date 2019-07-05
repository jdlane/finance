import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT symbol, shares FROM stocks WHERE user_id=:user_id", user_id=session["user_id"])
    if not stocks:
        return apology("portfolio empty")
    rows = []
    total_value = 0
    for stock in stocks:
        data = lookup(stock["symbol"])
        if not data:
            return apology("could not access API")
        rows.append({"name": data["name"], "symbol": data["symbol"], "shares": stock["shares"], "price": usd(data["price"]), "total_price": usd(stock["shares"]*data["price"])})
        total_value += (stock["shares"]*data["price"])
    cash = db.execute("SELECT cash FROM users WHERE id=:user_id",user_id=session["user_id"])[0]['cash']
    
    if not cash:
        return apology("could not access account info")
    return render_template("index.html", rows=rows, total_value=usd(total_value), total_money=usd(total_value+cash), balance=usd(cash))
        
@app.route("/price", methods=["GET"])
@login_required
def price():
    """Return prcie of stocks specified in GET"""
    #use symbol and amount to provide price
    shares = request.args.get("shares")
    symbol = request.args.get("symbol")
    if shares and symbol:
        data = lookup(request.args.get("symbol"))
        #make sure get data is valid
        try:
            shares = int(shares)
        except:
            return jsonify("no")
        if not data or shares < 1:
            return jsonify("no")
        return jsonify(usd(data["price"]*shares))
    
    
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    #if form submitted buy stock
    if request.method == "POST":
        shares =  request.form.get("shares")
        symbol = request.form.get("symbol")
        #validate input
        try:
            shares = int(shares)
        except:
            return apology("submit an integer", 400)
        if not shares:
            return apology("shares is equal to none", 400)
        if shares < 1:
            return apology("submit a positive integer",400)
        if not symbol:
            return apology("submit a stock symbol",400)
        #look up stock info
        info = lookup(symbol)
        symbol = info["symbol"]
        if not info:
            return apology("symbol not recognized",400)
        #find cost of shares
        total = shares * info['price']
        #get user cash
        balance = db.execute("SELECT cash FROM users WHERE id=:user_id",user_id=session["user_id"])[0]['cash']
        #apologize if user can't afford shares
        if total > balance:
            return apology("not enough money",403)
        #update user cash
        if not db.execute("UPDATE users SET cash=:cash WHERE id=:user_id",cash=balance-total,user_id=session["user_id"]):
            return apology("unable to update user balance")
        #add stock to stocks table
        #check if shares of that stock already owned
        stock = db.execute("SELECT shares FROM stocks WHERE user_id=:user_id AND symbol=:symbol",user_id=session["user_id"],symbol=symbol)
        if stock:
            db.execute("UPDATE stocks SET shares=:shares WHERE user_id=:user_id AND symbol=:symbol",shares=stock[0]["shares"]+1,user_id=session["user_id"],symbol=symbol)
        elif not db.execute("INSERT INTO stocks (user_id, symbol, shares) VALUES (:user_id, :symbol, :shares)", user_id=session["user_id"], symbol=symbol, shares=shares):
            #if can't add stock to table, refund user
            db.execute("UPDATE users SET cash=:cash WHERE id=:user_id",cash=balance,user_id=session["user_id"])
            return apology("unable to add stock")
        return redirect("/")
    #form not submitted, but get should contain stock symbol
    else:
        #use symbol to render buy template with stock
        if request.args.get("symbol"):   
            return render_template("buy.html", symbol=request.args.get("symbol").upper())
        else:
            return render_template("buy.html",symbol="")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
        
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        info = lookup(request.form.get("symbol"))
        if not info:
            return apology("Symbol not found", 400)
        return render_template("quote.html",name=info["name"], price=info["price"],symbol=info["symbol"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    
    session.clear()
    
    if request.method == "POST":
        #check if username, password, repeat fields are filled
        if not request.form.get("username"):
            return apology("must provide username",400)
        if not request.form.get("password"):
            return apology("must provide password",400)
        if not request.form.get("password2"):
            return apology("must repeat password",400)
        #check password match
        if request.form.get("password") != request.form.get("password2"):
            return apology("passwords did not match",403)
        #check user exists
        if db.execute("SELECT id FROM users WHERE username=:username",username=request.form.get("username")):
            return apology("username taken",403)
        if db.execute("INSERT INTO users (username, hash)  VALUES (:username, :pword)",username=request.form.get("username"),pword=generate_password_hash(request.form.get("password"))):
            # Remember which user has logged in
            user_id = db.execute("SELECT id FROM users WHERE username=:username",username=request.form.get("username"))
            session["user_id"] = user_id[0]["id"]

            #redirect to home page
            return redirect("/")
        else: 
            return apology("error creating user")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        #verify input
        if not symbol:
            return apology("must provide symbol", 400)
        if not shares:
            return apology("must provide share number",400)
        try:
            shares = int(shares)
        except:
            return apology("submit an integer", 400)
        info = lookup(symbol)
        symbol = info["symbol"]
        shares_owned = db.execute("SELECT shares FROM stocks WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=symbol)[0]["shares"]
        if not shares_owned:
            return apology("share not owned",400)
        if shares_owned < shares:
            return apology("you do not own that many shares", 403)
        #subtract shares from stocks table
        if not db.execute("UPDATE stocks SET shares=:new_shares WHERE user_id=:user_id AND symbol=:symbol", new_shares=shares_owned-shares, symbol=symbol, user_id=session["user_id"]):
            return apology("failed to update shares")
        balance = db.execute("SELECT cash FROM users WHERE id=:user_id",user_id=session["user_id"])[0]["cash"]
        #if can't give money, refund shares
        if not db.execute("UPDATE users SET cash=:new_cash WHERE id=:user_id", user_id=session["user_id"], new_cash=balance+(info['price']*shares)):
            db.execute("UPDATE stocks SET shares=:new_shares WHERE user_id=:user_id AND symbol=:symbol", new_shares=shares_owned, symbol=symbol, user_id=session["user_id"])
            return apology("sale failed")
        #delete row if no shares
        db.execute("DELETE FROM stocks WHERE user_id=:user_id AND symbol=:symbol AND shares<1",user_id=session["user_id"],symbol=symbol)
        return redirect("/")
    else:
        symbols = db.execute("SELECT symbol FROM stocks WHERE user_id=:user_id",user_id=session["user_id"])
        if request.args.get("symbol"):
            return render_template("sell.html", options=symbols, symbol=request.args.get("symbol"))
        else:
            return render_template("sell.html", options=symbols)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
