import sqlite3
import uuid

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

DATABASE = 'market.db'
socketio = SocketIO(app)


# 데이터베이스 연결 관리
def get_db():
    db = getattr(g, '_database', None)

    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row

    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)

    if db is not None:
        db.close()


# 테이블 생성 및 기존 DB 구조 보완
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                balance INTEGER NOT NULL DEFAULT 100000
            )
        """)

        # 기존 DB에 balance 열이 없으면 추가
        cursor.execute("PRAGMA table_info(user)")
        user_columns = [
            column['name']
            for column in cursor.fetchall()
        ]

        if 'balance' not in user_columns:
            cursor.execute("""
                ALTER TABLE user
                ADD COLUMN balance INTEGER NOT NULL DEFAULT 100000
            """)

        # 상품 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)

        # 신고 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        # 송금 내역 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL CHECK(amount > 0),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.commit()


# 기본 페이지
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    return render_template('index.html')


# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        # 중복 사용자 확인
        cursor.execute(
            "SELECT * FROM user WHERE username = ?",
            (username,)
        )

        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())

        # 비밀번호를 해시값으로 변환
        password_hash = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO user (id, username, password)
            VALUES (?, ?, ?)
            """,
            (
                user_id,
                username,
                password_hash
            )
        )
        db.commit()

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')


# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            "SELECT * FROM user WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()

        # 입력한 비밀번호와 DB의 해시값 비교
        if user and check_password_hash(
            user['password'],
            password
        ):
            session['user_id'] = user['id']

            flash('로그인 성공!')
            return redirect(url_for('dashboard'))

        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))

    return render_template('login.html')


# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)

    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# 대시보드 및 상품 검색
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 조회
    cursor.execute(
        "SELECT * FROM user WHERE id = ?",
        (session['user_id'],)
    )
    current_user = cursor.fetchone()

    # 검색어 가져오기
    query = request.args.get('q', '').strip()

    if query:
        search_value = f'%{query}%'

        cursor.execute(
            """
            SELECT *
            FROM product
            WHERE title LIKE ?
               OR description LIKE ?
            """,
            (
                search_value,
                search_value
            )
        )
    else:
        cursor.execute(
            "SELECT * FROM product"
        )

    all_products = cursor.fetchall()

    return render_template(
        'dashboard.html',
        products=all_products,
        user=current_user,
        query=query
    )


# 프로필
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        bio = request.form.get('bio', '')

        cursor.execute(
            """
            UPDATE user
            SET bio = ?
            WHERE id = ?
            """,
            (
                bio,
                session['user_id']
            )
        )
        db.commit()

        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    cursor.execute(
        "SELECT * FROM user WHERE id = ?",
        (session['user_id'],)
    )
    current_user = cursor.fetchone()

    return render_template(
        'profile.html',
        user=current_user
    )


# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        db = get_db()
        cursor = db.cursor()

        product_id = str(uuid.uuid4())

        cursor.execute(
            """
            INSERT INTO product
            (
                id,
                title,
                description,
                price,
                seller_id
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                product_id,
                title,
                description,
                price,
                session['user_id']
            )
        )
        db.commit()

        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')


# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT * FROM product WHERE id = ?",
        (product_id,)
    )
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 판매자 정보 조회
    cursor.execute(
        "SELECT * FROM user WHERE id = ?",
        (product['seller_id'],)
    )
    seller = cursor.fetchone()

    return render_template(
        'view_product.html',
        product=product,
        seller=seller
    )


# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']

        db = get_db()
        cursor = db.cursor()

        report_id = str(uuid.uuid4())

        cursor.execute(
            """
            INSERT INTO report
            (
                id,
                reporter_id,
                target_id,
                reason
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                report_id,
                session['user_id'],
                target_id,
                reason
            )
        )
        db.commit()

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')


# 사용자 간 포인트 송금
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        receiver_username = request.form.get(
            'receiver_username',
            ''
        ).strip()

        amount_text = request.form.get(
            'amount',
            ''
        ).strip()

        # 금액이 숫자인지 확인
        try:
            amount = int(amount_text)

        except ValueError:
            flash('송금 금액은 숫자로 입력해주세요.')
            return redirect(url_for('transfer'))

        # 0원 및 음수 송금 차단
        if amount <= 0:
            flash('송금 금액은 0보다 커야 합니다.')
            return redirect(url_for('transfer'))

        # 지나치게 큰 금액 차단
        if amount > 100000000:
            flash('한 번에 송금할 수 있는 금액을 초과했습니다.')
            return redirect(url_for('transfer'))

        # 보내는 사용자 조회
        cursor.execute(
            "SELECT * FROM user WHERE id = ?",
            (session['user_id'],)
        )
        sender = cursor.fetchone()

        # 받는 사용자 조회
        cursor.execute(
            "SELECT * FROM user WHERE username = ?",
            (receiver_username,)
        )
        receiver = cursor.fetchone()

        if sender is None:
            session.clear()
            flash('사용자 정보를 찾을 수 없습니다.')
            return redirect(url_for('login'))

        if receiver is None:
            flash('받는 사용자를 찾을 수 없습니다.')
            return redirect(url_for('transfer'))

        if sender['id'] == receiver['id']:
            flash('자기 자신에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        if sender['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        transfer_id = str(uuid.uuid4())

        try:
            # 보내는 사람 잔액 차감
            cursor.execute(
                """
                UPDATE user
                SET balance = balance - ?
                WHERE id = ?
                  AND balance >= ?
                """,
                (
                    amount,
                    sender['id'],
                    amount
                )
            )

            if cursor.rowcount != 1:
                db.rollback()
                flash('잔액이 부족합니다.')
                return redirect(url_for('transfer'))

            # 받는 사람 잔액 증가
            cursor.execute(
                """
                UPDATE user
                SET balance = balance + ?
                WHERE id = ?
                """,
                (
                    amount,
                    receiver['id']
                )
            )

            # 송금 내역 저장
            cursor.execute(
                """
                INSERT INTO transfer
                (
                    id,
                    sender_id,
                    receiver_id,
                    amount
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    transfer_id,
                    sender['id'],
                    receiver['id'],
                    amount
                )
            )

            # 모든 작업이 성공한 경우에만 저장
            db.commit()

        except sqlite3.Error:
            db.rollback()
            flash('송금 처리 중 오류가 발생했습니다.')
            return redirect(url_for('transfer'))

        flash(
            f'{receiver_username}님에게 '
            f'{amount}포인트를 송금했습니다.'
        )
        return redirect(url_for('transfer'))

    # 현재 사용자 조회
    cursor.execute(
        "SELECT * FROM user WHERE id = ?",
        (session['user_id'],)
    )
    current_user = cursor.fetchone()

    # 최근 송금 내역 조회
    cursor.execute(
        """
        SELECT
            transfer.*,
            sender.username AS sender_name,
            receiver.username AS receiver_name
        FROM transfer
        JOIN user AS sender
          ON transfer.sender_id = sender.id
        JOIN user AS receiver
          ON transfer.receiver_id = receiver.id
        WHERE transfer.sender_id = ?
           OR transfer.receiver_id = ?
        ORDER BY transfer.created_at DESC
        LIMIT 20
        """,
        (
            session['user_id'],
            session['user_id']
        )
    )
    transfer_history = cursor.fetchall()

    return render_template(
        'transfer.html',
        user=current_user,
        history=transfer_history
    )


# 실시간 전체 채팅
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)