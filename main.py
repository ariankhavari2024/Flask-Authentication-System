from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)  #our flask is defined
app.config["SECRET_KEY"] = "random-secret-key-here"

class Base(DeclarativeBase): 
    pass

app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///users_encrypted.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id): 
    return db.get_or_404(User, user_id) # we are using UserMixin, so we should be fine with pulling the id

class User(UserMixin, db.Model): 
    id: Mapped[int] = mapped_column(Integer, primary_key=True) #we set the primary key to true over here in this case
    title: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

with app.app_context(): 
    db.create_all()

@app.route("/")
def home(): 
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route("/login", methods = ["POST", "GET"])
def login(): 
    if request.method == "POST": 
        email = request.form.get("email")
        password = request.form.get("password")
        user = db.session.execute(db.select(User).where(User.title == email)).scalar()
        if check_password_hash(user.password, password): 
            login_user(user) #the user is logged in and now has privilages, once the server runs
            return redirect(url_for("secrets"))
    return render_template("login.html", logged_in=current_user.is_authenticated)

@app.route("/register", methods = ["POST", "GET"])
def register(): 
    if request.method == "POST": 
        # in this case we are creating the new user in the database
        new_user = User(
            name = request.form.get("name"), 
            title = request.form.get("email"), 
            password = generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8) #this adds a salt and encrypts with sha256
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user) # this means this user has login access now
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)

@app.route("/secrets")
@login_required
def secrets(): 
    return render_template("secrets.html", logged_in=current_user.is_authenticated)


@app.route("/download")
@login_required
def download(): 
    return send_from_directory('static', path="files/cheat_sheet.pdf") # this sends the user to the donwloaded pdf, not downloading, but raking them there

@app.route("/logout")
@login_required
def logout(): 
    logout_user()
    return redirect(url_for("home"))

if __name__ == "__main__": 
    app.run(debug=True)