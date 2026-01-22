import io
import base64
import pyotp
import qrcode
import time


from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-later"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///totp.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

#----------------------
# AUTH / 2FA HELPERS remove 2FA authentication

from functools import wraps
from flask import flash

def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def require_2fa_consistency(view):
    """
    If user.is_2fa_enabled is True but totp_secret is missing,
    2FA is in a broken state -> force re-enrollment.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = User.query.filter_by(username=session.get("username")).first()
        if not user:
            session.clear()
            return redirect(url_for("login"))

        # Broken 2FA state: enabled flag but no secret
        if user.is_2fa_enabled and not user.totp_secret:
            # Fix the DB state so it doesn't stay inconsistent
            user.is_2fa_enabled = False
            db.session.commit()

            # Send user to enroll again
            flash("2FA was removed. Please re-enroll to continue.", "warning")
            return redirect(url_for("enable_2fa"))

        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    username = session.get("username")
    return render_template("home.html", username=username)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose another one.", "warning")
            return render_template("register.html")

        password_hash = generate_password_hash(password)
        user = User(username=username, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()

        flash("Account created! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if not user:
            # User not found → show message on login page
            flash("User not found.", "error")
            return render_template("login.html")

        if not check_password_hash(user.password_hash, password):
            # Wrong password → show message on login page
            flash("Wrong password.", "error")
            return render_template("login.html")

        # If user has 2FA enabled → require OTP
        if user.is_2fa_enabled:
            session["pre_2fa_user"] = user.username
            return redirect(url_for("login_otp"))

        # Otherwise login normally
        session["username"] = user.username
        return redirect(url_for("dashboard"))

    return render_template("login.html")
#-------------------DDOS/brute force prevention-------------------/
OTP_MAX_ATTEMPTS = 5          # tries allowed
OTP_LOCK_SECONDS = 60         # lock duration

def _otp_key(username: str) -> str:
    return f"otp_fail_{username}"

def _otp_lock_key(username: str) -> str:
    return f"otp_lock_{username}"

def otp_is_locked(username: str) -> int:
    """Returns remaining lock seconds (0 if not locked)."""
    until = session.get(_otp_lock_key(username))
    if not until:
        return 0
    remaining = int(until - time.time())
    if remaining <= 0:
        session.pop(_otp_lock_key(username), None)
        session.pop(_otp_key(username), None)
        return 0
    return remaining

def otp_register_fail(username: str) -> int:
    """Increment fail count; return remaining attempts before lock."""
    k = _otp_key(username)
    fails = int(session.get(k, 0)) + 1
    session[k] = fails

    remaining = OTP_MAX_ATTEMPTS - fails
    if remaining <= 0:
        session[_otp_lock_key(username)] = time.time() + OTP_LOCK_SECONDS
    return max(0, remaining)

def otp_reset(username: str) -> None:
    session.pop(_otp_key(username), None)
    session.pop(_otp_lock_key(username), None)
#------------------------------------------------------#

@app.route("/login-otp", methods=["GET", "POST"])
def login_otp():
    if "pre_2fa_user" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["pre_2fa_user"]).first()
    if not user:
        return redirect(url_for("login"))

    #  brute-force lock check
    remaining_lock = otp_is_locked(user.username)
    if remaining_lock > 0:
        flash(f"Too many OTP attempts. Try again in {remaining_lock} seconds.", "error")
        return render_template("login_otp.html")

    if request.method == "POST":
        code = request.form["code"].strip()
        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code, valid_window=1):
            # OTP correct → complete login
            otp_reset(user.username)  # ✅ reset counter on success
            session.pop("pre_2fa_user", None)
            session["username"] = user.username
            return redirect(url_for("dashboard"))
        else:
            remaining = otp_register_fail(user.username)
            if remaining == 0:
                flash(f"Too many OTP attempts. Locked for {OTP_LOCK_SECONDS} seconds.", "error")
            else:
                flash(f"Invalid OTP. {remaining} attempt(s) left.", "error")
            return render_template("login_otp.html")

    return render_template("login_otp.html")

@app.route("/dashboard")
@require_login
@require_2fa_consistency
def dashboard():
    user = User.query.filter_by(username=session["username"]).first()
    return render_template("dashboard.html", user=user)


@app.route("/enable-2fa")
def enable_2fa():
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()

    # Create secret if not created yet
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    # Create otpauth URI (QR content)
    issuer = "TOTP_WebApp"
    otp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.username,
        issuer_name=issuer
    )

    # Make QR image
    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    return render_template(
        "enable_2fa.html",
        qr_b64=qr_b64,
        secret=user.totp_secret,
        otp_uri=otp_uri
    )

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()
    if not user or not user.totp_secret:
        return redirect(url_for("enable_2fa"))

    if request.method == "POST":
        code = request.form["code"].strip()
        totp = pyotp.TOTP(user.totp_secret)

        # valid_window=1 allows 30s clock drift
        if totp.verify(code, valid_window=1):
            user.is_2fa_enabled = True
            db.session.commit()
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid OTP. Try again.", "error")
            return render_template("verify_2fa.html")

    return render_template("verify_2fa.html")

@app.route("/disable-2fa", methods=["GET", "POST"])
@require_login
def disable_2fa():
    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    # If it's already disabled, just go back
    if not user.is_2fa_enabled:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        code = request.form["code"].strip()

        # Must have secret to verify; if missing, treat as already removed
        if not user.totp_secret:
            user.is_2fa_enabled = False
            db.session.commit()
            return redirect(url_for("dashboard"))

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code, valid_window=1):
            user.is_2fa_enabled = False
            user.totp_secret = None
            db.session.commit()
            flash("2FA disabled.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid OTP. Try again.", "error")
            return render_template("disable_2fa.html", user=user)

    return render_template("disable_2fa.html", user=user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
