from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash
from passlib.context import CryptContext
import os
from functools import wraps
from pytube import YouTube
import datetime
# from flask_turnstile import Turnstile

persistent_path = os.getenv("PERSISTENT_STORAGE_DIR", os.path.dirname(os.path.realpath(__file__)))

app = Flask(__name__)
app.secret_key = 'totally_secret_key'

app.permanent_session_lifetime = datetime.timedelta(hours=1)
app.config['session_permanent'] = True
db_path = os.path.join(persistent_path, "sqlite.db")
# Replace with your site_key, secret_key. 
# Ensure that whenever you host your application, go to https://dash.cloudflare.com/ turnstile to register your site and get your site_key and secret_key and specify your IP address
# If you are running locally, please specify 127.0.0.1 as your IP address
# turnstile = Turnstile(app=app, site_key='0x4AAAAAAAKx8g5dcqepg6zf', secret_key='0x4AAAAAAAKx8th8Hf53CIfuTRAtOoJC0W8',
#                       is_enabled=True)
# turnstile.init_app(app)

app.config["SQLALCHEMY_DATABASE_URI"] = f'sqlite:///{db_path}'
app.config["SQLALCHEMY_ECHO"] = False
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy()

db.init_app(app)
myctx = CryptContext(schemes=["sha256_crypt", "md5_crypt", "des_crypt"])


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash


with app.app_context():
    db.create_all()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/", methods=["GET"])
@login_required
def main():
    if session.get('user_id'):
        user = User.query.filter_by(user_id=session['user_id']).first()
        return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # Validate inputs
        if not username:
            flash("No username")
            return render_template("register.html")
        elif not password:
            flash("No password")
            return render_template("register.html")
        elif not confirmation:
            flash("No confirmation")
            return render_template("register.html")
        elif password != confirmation:
            flash("Passwords don't match")
            return render_template("register.html")
        elif len(password) < 8 or len(password) > 20 or not any(char.isdigit() for char in password) or not any(
                char.isupper() for char in password) or not any(char.islower() for char in password):
            flash(
                "New password must be between 8 to 20 characters, contain at least one uppercase letter, one lowercase letter and one digit.",
                "error")
            return render_template("register.html")
        # Check if the username is already taken
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash("Username already taken")
            return render_template("register.html")
        # Hash the password

        password_hash = myctx.hash(password)

        # Create a new user and add it to the database
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        # Start a session
        user = User.query.filter_by(username=username).first()
        session["user_id"] = user.user_id

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        #Comment this out if you will be using recaptcha
        # if turnstile.verify():
        #     pass
        # else:

        #     flash("Too many login attempts. Please try again later.", "error")
        #     return render_template("login.html")
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate inputs
        if not username:
            flash("Must provide username", "error")
            return render_template("login.html")

        elif not password:
            flash("Must provide password", "error")
            return render_template("login.html")

        user = User.query.filter_by(username=username).first()
        if user is None:
            flash("Invalid username and/or password", "error")
            return render_template("login.html")

        # Check if the user exists and the password is correct

        print(myctx.verify(password, user.password_hash))
        print(user.password_hash)
        if user is None or not myctx.verify(password, user.password_hash):
            flash("Invalid username and/or password", "error")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = user.user_id

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    # Implement your own authentication logic here

    if session.get('user_id') is None:
        return redirect(url_for('login'))

    user = User.query.filter_by(user_id=session["user_id"]).first()
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not myctx.verify(old_password, user.password_hash):
            flash("Incorrect old password. Please try again.", "error")
            return render_template("change_password.html")
        elif new_password != confirm_password:
            flash("New passwords do not match. Please try again.", "error")
            return render_template("change_password.html")
        ## implement password strength check here ##
        elif len(new_password) < 8 or len(new_password) > 20 or not any(
                char.isdigit() for char in new_password) or not any(char.isupper() for char in new_password) or not any(
            char.islower() for char in new_password):
            flash(
                "New password must be between 8 to 20 characters, contain at least one uppercase letter, one lowercase letter and one digit.",
                "error")
            return render_template("change_password.html")
        else:
            # Update the user's password with the new password
            new_password = myctx.hash(new_password)
            user.password_hash = new_password
            # add here
            db.session.commit()
            flash("Password successfully changed.", "success")
            return redirect("/")

    return render_template("change_password.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


def validate_youtube_link(link):
    if link.startswith("https://www.youtube.com/") or link.startswith('https://youtu.be/'):
        return True
    else:
        return False


@app.route('/downloader', methods=['GET', 'POST'])
@login_required
def downloader():
    if request.method == 'POST':
        ytlink = request.form['ytlink']
        if validate_youtube_link(ytlink):
            try:
                # downloads to the download directory
                full_path = os.path.join(os.path.expanduser("~"), "Downloads")
                if ytlink.startswith("https://youtu.be/"):
                    segments = ytlink.split("/")
                    # Get the last segment of the URL
                    video_id = segments[-1]
                    ytlink = "https://www.youtube.com/watch?v=" + video_id

                print(ytlink)
                yt = YouTube(ytlink)
                ytTitle = yt.title[:10]
                print(ytTitle)
                title = ytTitle + '.mp3'
                stream = yt.streams.get_audio_only()
                print(full_path)
                stream.download(output_path=full_path, filename=title)

                flash(f'Download Complete', category='success')
                return redirect(url_for("downloader"))

            except Exception as e:
                flash("Unexpected Error", category='error')
                print(f'Error: {e}')
        else:
            flash("Not a valid youtube link", category='error')
    # to render home.html user render_template
    # pass user variable which is the current user
    return render_template("downloader.html")


if __name__ == "__main__":
    app.run(debug=True, port=9000)
