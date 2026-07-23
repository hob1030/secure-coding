import hmac
import os
import re
import secrets
import sqlite3
import sys
import time
import uuid
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_socketio import SocketIO, send
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

DATABASE = "market.db"
REPORT_BLOCK_THRESHOLD = 3
socketio = SocketIO(app)
last_chat_time = {}


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def add_column_if_missing(cursor, table, column, definition):
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row["name"] for row in cursor.fetchall()]
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                balance INTEGER NOT NULL DEFAULT 100000,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        add_column_if_missing(cursor, "user", "balance", "INTEGER NOT NULL DEFAULT 100000")
        add_column_if_missing(cursor, "user", "is_admin", "INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(cursor, "user", "is_active", "INTEGER NOT NULL DEFAULT 1")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                image_url TEXT,
                is_blocked INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        add_column_if_missing(cursor, "product", "image_url", "TEXT")
        add_column_if_missing(cursor, "product", "is_blocked", "INTEGER NOT NULL DEFAULT 0")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT 'user',
                created_at TEXT
            )
            """
        )
        add_column_if_missing(cursor, "report", "target_type", "TEXT NOT NULL DEFAULT 'user'")
        add_column_if_missing(cursor, "report", "created_at", "TEXT")
        cursor.execute(
            "UPDATE report SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL CHECK(amount > 0),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS private_message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.commit()


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return token


@app.before_request
def csrf_protect():
    if request.method != "POST":
        return
    token = session.get("_csrf_token")
    submitted = request.form.get("_csrf_token", "")
    if not token or not submitted or not hmac.compare_digest(token, submitted):
        abort(400)


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    if user is None or not user["is_active"]:
        session.clear()
        return None
    return user


@app.context_processor
def inject_common_values():
    return {
        "current_user": get_current_user(),
        "csrf_token": generate_csrf_token(),
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return redirect(url_for("login"))
        if not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def valid_username(username):
    return re.fullmatch(r"[A-Za-z0-9_]{3,30}", username) is not None


def valid_password(password):
    return (
        8 <= len(password) <= 128
        and any(ch.isalpha() for ch in password)
        and any(ch.isdigit() for ch in password)
    )


def valid_image_url(image_url):
    if not image_url:
        return True
    parsed = urlparse(image_url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


@app.route("/")
def index():
    if get_current_user() is not None:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not valid_username(username):
            flash("아이디는 영문, 숫자, 밑줄로 3~30자 입력해주세요.")
            return redirect(url_for("register"))
        if not valid_password(password):
            flash("비밀번호는 8자 이상이며 영문과 숫자를 포함해야 합니다.")
            return redirect(url_for("register"))

        db = get_db()
        if db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone():
            flash("이미 존재하는 사용자명입니다.")
            return redirect(url_for("register"))

        try:
            db.execute(
                "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                (str(uuid.uuid4()), username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            flash("이미 존재하는 사용자명입니다.")
            return redirect(url_for("register"))

        flash("회원가입이 완료되었습니다.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user and user["is_active"] and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("로그인 성공!")
            return redirect(url_for("dashboard"))

        flash("차단된 계정입니다." if user and not user["is_active"] else "아이디 또는 비밀번호가 올바르지 않습니다.")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    query = request.args.get("q", "").strip()[:100]
    db = get_db()
    sql = """
        SELECT product.*, user.username AS seller_name
        FROM product
        JOIN user ON product.seller_id = user.id
        WHERE product.is_blocked = 0 AND user.is_active = 1
    """
    params = []
    if query:
        sql += " AND (product.title LIKE ? OR product.description LIKE ?)"
        search_value = f"%{query}%"
        params.extend([search_value, search_value])
    sql += " ORDER BY product.rowid DESC"
    products = db.execute(sql, params).fetchall()
    return render_template("dashboard.html", products=products, user=user, query=query)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action", "bio")
        if action == "bio":
            bio = request.form.get("bio", "").strip()
            if len(bio) > 300:
                flash("소개글은 300자 이하로 입력해주세요.")
                return redirect(url_for("profile"))
            db.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, user["id"]))
            db.commit()
            flash("프로필이 수정되었습니다.")
        elif action == "password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            if not check_password_hash(user["password"], current_password):
                flash("현재 비밀번호가 올바르지 않습니다.")
                return redirect(url_for("profile"))
            if not valid_password(new_password):
                flash("새 비밀번호는 8자 이상이며 영문과 숫자를 포함해야 합니다.")
                return redirect(url_for("profile"))
            db.execute(
                "UPDATE user SET password = ? WHERE id = ?",
                (generate_password_hash(new_password), user["id"]),
            )
            db.commit()
            flash("비밀번호가 변경되었습니다.")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


@app.route("/product/new", methods=["GET", "POST"])
@login_required
def new_product():
    user = get_current_user()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        price_text = request.form.get("price", "").strip()
        image_url = request.form.get("image_url", "").strip()
        if not 1 <= len(title) <= 100:
            flash("상품명은 1~100자로 입력해주세요.")
            return redirect(url_for("new_product"))
        if not 1 <= len(description) <= 1000:
            flash("설명은 1~1000자로 입력해주세요.")
            return redirect(url_for("new_product"))
        try:
            price = int(price_text)
        except ValueError:
            flash("가격은 숫자로 입력해주세요.")
            return redirect(url_for("new_product"))
        if not 1 <= price <= 1_000_000_000:
            flash("가격은 1원 이상 10억원 이하로 입력해주세요.")
            return redirect(url_for("new_product"))
        if not valid_image_url(image_url):
            flash("이미지 주소는 http 또는 https 주소만 사용할 수 있습니다.")
            return redirect(url_for("new_product"))

        db = get_db()
        db.execute(
            """
            INSERT INTO product (id, title, description, price, seller_id, image_url)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), title, description, str(price), user["id"], image_url or None),
        )
        db.commit()
        flash("상품이 등록되었습니다.")
        return redirect(url_for("dashboard"))
    return render_template("new_product.html")


@app.route("/product/<product_id>")
def view_product(product_id):
    db = get_db()
    product = db.execute(
        """
        SELECT product.*, user.username AS seller_name
        FROM product JOIN user ON product.seller_id = user.id
        WHERE product.id = ?
        """,
        (product_id,),
    ).fetchone()
    if product is None:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for("dashboard"))
    user = get_current_user()
    can_manage = bool(user and (user["id"] == product["seller_id"] or user["is_admin"]))
    if product["is_blocked"] and not can_manage:
        flash("차단된 상품입니다.")
        return redirect(url_for("dashboard"))
    return render_template("view_product.html", product=product, can_manage=can_manage)


@app.route("/product/<product_id>/edit", methods=["GET", "POST"])
@login_required
def edit_product(product_id):
    user = get_current_user()
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        abort(404)
    if user["id"] != product["seller_id"] and not user["is_admin"]:
        abort(403)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        price_text = request.form.get("price", "").strip()
        image_url = request.form.get("image_url", "").strip()
        try:
            price = int(price_text)
        except ValueError:
            flash("가격은 숫자로 입력해주세요.")
            return redirect(url_for("edit_product", product_id=product_id))
        if not 1 <= len(title) <= 100 or not 1 <= len(description) <= 1000:
            flash("상품명 또는 설명 길이가 올바르지 않습니다.")
            return redirect(url_for("edit_product", product_id=product_id))
        if not 1 <= price <= 1_000_000_000 or not valid_image_url(image_url):
            flash("가격 또는 이미지 주소가 올바르지 않습니다.")
            return redirect(url_for("edit_product", product_id=product_id))
        db.execute(
            "UPDATE product SET title = ?, description = ?, price = ?, image_url = ? WHERE id = ?",
            (title, description, str(price), image_url or None, product_id),
        )
        db.commit()
        flash("상품이 수정되었습니다.")
        return redirect(url_for("view_product", product_id=product_id))
    return render_template("edit_product.html", product=product)


@app.route("/product/<product_id>/delete", methods=["POST"])
@login_required
def delete_product(product_id):
    user = get_current_user()
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        abort(404)
    if user["id"] != product["seller_id"] and not user["is_admin"]:
        abort(403)
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for("dashboard"))


@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    reporter = get_current_user()
    db = get_db()
    if request.method == "POST":
        target_type = request.form.get("target_type", "")
        target_id = request.form.get("target_id", "").strip()
        reason = request.form.get("reason", "").strip()
        if target_type not in {"user", "product"}:
            flash("신고 대상 종류가 올바르지 않습니다.")
            return redirect(url_for("report"))
        if not 5 <= len(reason) <= 500:
            flash("신고 사유는 5~500자로 입력해주세요.")
            return redirect(url_for("report"))

        if target_type == "user":
            target = db.execute(
                "SELECT * FROM user WHERE id = ? OR username = ?", (target_id, target_id)
            ).fetchone()
            if target is None:
                flash("신고할 사용자를 찾을 수 없습니다.")
                return redirect(url_for("report"))
            if target["id"] == reporter["id"] or target["is_admin"]:
                flash("신고할 수 없는 사용자입니다.")
                return redirect(url_for("report"))
            resolved_target_id = target["id"]
        else:
            target = db.execute("SELECT * FROM product WHERE id = ?", (target_id,)).fetchone()
            if target is None:
                flash("신고할 상품을 찾을 수 없습니다.")
                return redirect(url_for("report"))
            resolved_target_id = target["id"]

        duplicate = db.execute(
            """
            SELECT id FROM report
            WHERE reporter_id = ? AND target_type = ? AND target_id = ?
            """,
            (reporter["id"], target_type, resolved_target_id),
        ).fetchone()
        if duplicate:
            flash("같은 대상을 중복 신고할 수 없습니다.")
            return redirect(url_for("report"))

        db.execute(
            """
            INSERT INTO report (id, reporter_id, target_id, reason, target_type, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (str(uuid.uuid4()), reporter["id"], resolved_target_id, reason, target_type),
        )
        count = db.execute(
            """
            SELECT COUNT(DISTINCT reporter_id) AS report_count
            FROM report WHERE target_type = ? AND target_id = ?
            """,
            (target_type, resolved_target_id),
        ).fetchone()["report_count"]
        if count >= REPORT_BLOCK_THRESHOLD:
            if target_type == "user":
                db.execute("UPDATE user SET is_active = 0 WHERE id = ?", (resolved_target_id,))
            else:
                db.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (resolved_target_id,))
        db.commit()
        flash("신고가 접수되었습니다.")
        return redirect(url_for("dashboard"))

    return render_template(
        "report.html",
        preset_type=request.args.get("type", ""),
        preset_target=request.args.get("target", ""),
    )


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    sender = get_current_user()
    db = get_db()
    if request.method == "POST":
        receiver_username = request.form.get("receiver_username", "").strip()
        amount_text = request.form.get("amount", "").strip()
        try:
            amount = int(amount_text)
        except ValueError:
            flash("송금 금액은 숫자로 입력해주세요.")
            return redirect(url_for("transfer"))
        if not 1 <= amount <= 100_000_000:
            flash("송금 금액 범위가 올바르지 않습니다.")
            return redirect(url_for("transfer"))

        receiver = db.execute(
            "SELECT * FROM user WHERE username = ? AND is_active = 1",
            (receiver_username,),
        ).fetchone()
        if receiver is None:
            flash("받는 사용자를 찾을 수 없습니다.")
            return redirect(url_for("transfer"))
        if sender["id"] == receiver["id"]:
            flash("자기 자신에게는 송금할 수 없습니다.")
            return redirect(url_for("transfer"))

        try:
            db.execute("BEGIN IMMEDIATE")
            result = db.execute(
                "UPDATE user SET balance = balance - ? WHERE id = ? AND balance >= ?",
                (amount, sender["id"], amount),
            )
            if result.rowcount != 1:
                db.rollback()
                flash("잔액이 부족합니다.")
                return redirect(url_for("transfer"))
            db.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver["id"]))
            db.execute(
                "INSERT INTO transfer (id, sender_id, receiver_id, amount) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), sender["id"], receiver["id"], amount),
            )
            db.commit()
        except sqlite3.Error:
            db.rollback()
            flash("송금 처리 중 오류가 발생했습니다.")
            return redirect(url_for("transfer"))

        flash(f"{receiver_username}님에게 {amount}포인트를 송금했습니다.")
        return redirect(url_for("transfer"))

    refreshed_user = db.execute("SELECT * FROM user WHERE id = ?", (sender["id"],)).fetchone()
    history = db.execute(
        """
        SELECT transfer.*, sender.username AS sender_name, receiver.username AS receiver_name
        FROM transfer
        JOIN user AS sender ON transfer.sender_id = sender.id
        JOIN user AS receiver ON transfer.receiver_id = receiver.id
        WHERE transfer.sender_id = ? OR transfer.receiver_id = ?
        ORDER BY transfer.created_at DESC LIMIT 20
        """,
        (sender["id"], sender["id"]),
    ).fetchall()
    return render_template("transfer.html", user=refreshed_user, history=history)


@app.route("/messages")
@login_required
def messages():
    user = get_current_user()
    db = get_db()
    users = db.execute(
        "SELECT id, username FROM user WHERE id != ? AND is_active = 1 ORDER BY username",
        (user["id"],),
    ).fetchall()
    recent = db.execute(
        """
        SELECT private_message.*, sender.username AS sender_name, receiver.username AS receiver_name
        FROM private_message
        JOIN user AS sender ON private_message.sender_id = sender.id
        JOIN user AS receiver ON private_message.receiver_id = receiver.id
        WHERE private_message.sender_id = ? OR private_message.receiver_id = ?
        ORDER BY private_message.created_at DESC LIMIT 20
        """,
        (user["id"], user["id"]),
    ).fetchall()
    return render_template("messages.html", users=users, recent=recent)


@app.route("/messages/<username>", methods=["GET", "POST"])
@login_required
def message_thread(username):
    user = get_current_user()
    db = get_db()
    other = db.execute(
        "SELECT * FROM user WHERE username = ? AND is_active = 1", (username,)
    ).fetchone()
    if other is None or other["id"] == user["id"]:
        flash("대화할 사용자를 찾을 수 없습니다.")
        return redirect(url_for("messages"))
    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not 1 <= len(content) <= 500:
            flash("메시지는 1~500자로 입력해주세요.")
            return redirect(url_for("message_thread", username=username))
        db.execute(
            "INSERT INTO private_message (id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), user["id"], other["id"], content),
        )
        db.commit()
        return redirect(url_for("message_thread", username=username))

    thread = db.execute(
        """
        SELECT private_message.*, sender.username AS sender_name
        FROM private_message
        JOIN user AS sender ON private_message.sender_id = sender.id
        WHERE (private_message.sender_id = ? AND private_message.receiver_id = ?)
           OR (private_message.sender_id = ? AND private_message.receiver_id = ?)
        ORDER BY private_message.created_at
        """,
        (user["id"], other["id"], other["id"], user["id"]),
    ).fetchall()
    return render_template("message_thread.html", other=other, thread=thread)


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute(
        """
        SELECT user.*,
            (SELECT COUNT(*) FROM report WHERE report.target_type = 'user' AND report.target_id = user.id) AS report_count
        FROM user ORDER BY username
        """
    ).fetchall()
    products = db.execute(
        """
        SELECT product.*, user.username AS seller_name,
            (SELECT COUNT(*) FROM report WHERE report.target_type = 'product' AND report.target_id = product.id) AS report_count
        FROM product JOIN user ON product.seller_id = user.id
        ORDER BY product.rowid DESC
        """
    ).fetchall()
    reports = db.execute(
        """
        SELECT report.*, reporter.username AS reporter_name
        FROM report JOIN user AS reporter ON report.reporter_id = reporter.id
        ORDER BY report.created_at DESC
        """
    ).fetchall()
    return render_template("admin.html", users=users, products=products, reports=reports)


@app.route("/admin/user/<user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    admin_user = get_current_user()
    db = get_db()
    target = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    if target["id"] == admin_user["id"] or target["is_admin"]:
        flash("관리자 계정 상태는 변경할 수 없습니다.")
        return redirect(url_for("admin"))
    db.execute(
        "UPDATE user SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?",
        (user_id,),
    )
    db.commit()
    flash("사용자 상태를 변경했습니다.")
    return redirect(url_for("admin"))


@app.route("/admin/product/<product_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_product(product_id):
    db = get_db()
    result = db.execute(
        "UPDATE product SET is_blocked = CASE WHEN is_blocked = 1 THEN 0 ELSE 1 END WHERE id = ?",
        (product_id,),
    )
    if result.rowcount != 1:
        abort(404)
    db.commit()
    flash("상품 차단 상태를 변경했습니다.")
    return redirect(url_for("admin"))


@app.route("/admin/report/<report_id>/delete", methods=["POST"])
@admin_required
def admin_delete_report(report_id):
    db = get_db()
    db.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash("신고 기록을 삭제했습니다.")
    return redirect(url_for("admin"))


@socketio.on("send_message")
def handle_send_message_event(data):
    user = get_current_user()
    if user is None or not isinstance(data, dict):
        return
    message = str(data.get("message", "")).strip()
    if not 1 <= len(message) <= 300:
        return
    now = time.monotonic()
    previous = last_chat_time.get(user["id"], 0)
    if now - previous < 1:
        return
    last_chat_time[user["id"]] = now
    send(
        {"message_id": str(uuid.uuid4()), "username": user["username"], "message": message},
        broadcast=True,
    )


def make_admin(username):
    with app.app_context():
        db = get_db()
        result = db.execute("UPDATE user SET is_admin = 1 WHERE username = ?", (username,))
        db.commit()
        print(f"{username} 계정에 관리자 권한을 부여했습니다." if result.rowcount == 1 else "해당 사용자를 찾을 수 없습니다.")


if __name__ == "__main__":
    init_db()
    if len(sys.argv) == 3 and sys.argv[1] == "--make-admin":
        make_admin(sys.argv[2])
        raise SystemExit(0)
    socketio.run(
        app,
        host="127.0.0.1",
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True,
    )
