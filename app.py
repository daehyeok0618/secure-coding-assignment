import sqlite3
import bcrypt
import uuid
import re
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, DecimalField, HiddenField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect  # CSRF 보호 추가
from flask import render_template, request, flash
from flask_login import current_user, login_required  # current_user를 임포트해야 합니다.
from wtforms.validators import InputRequired
from wtforms import IntegerField
from datetime import timedelta
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'  # CSRF 보호를 위해 필요

DATABASE = 'market.db'
socketio = SocketIO(app)

# 15분 동안 아무 활동이 없으면 자동으로 logout됨.
app.permanent_session_lifetime = timedelta(minutes=15)

# CSRF 보호 활성화
csrf = CSRFProtect(app)

# 세션 쿠키 보안 설정
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True # 로컬 개발 중이라면 False로 두고 배포시 True
)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 보안 검사 함수
def message_filter(message):
    blocked_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'eval\(',
        r'alert\(',
        r'<.*?>',
        r'[\x00-\x1F\x7F]',
    ]
    if len(message) > 100:
        return False
    for pattern in blocked_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return False 
    return True

#테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                lock_until DATETIME,
                banned INTEGER DEFAULT 0
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

############################ 비밀번호, 아이디 제한 조건
def validate_username(username):
    pattern = r'^[a-zA-Z0-9-_]{3,20}$'
    return bool(re.fullmatch(pattern, username))

def validate_password(password):
    pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,20}$'
    return bool(re.fullmatch(pattern, password))
############################################


# 회원가입 폼 클래스 정의 (CSRF 보호 적용)
class RegisterForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])

# 비밀번호 해시화 함수
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# 비밀번호 검증 함수
def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():  # CSRF 토큰 검증
        username = form.username.data
        password = form.password.data

        # 사용자명 검증
        if not validate_username(username):
            flash('사용자명은 3~20자 길이의 영문 대소문자, 숫자, _ 또는 -만 포함해야 합니다.')
            return redirect(url_for('register'))

        # 비밀번호 검증
        if not validate_password(password):
            flash('비밀번호는 8~20자 길이로 대문자, 소문자, 숫자, 특수문자를 모두 포함해야 합니다.')
            return redirect(url_for('register'))
        
        ## 비밀번호 확인 검증
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        # 비밀번호 해시화
        hashed_password = hash_password(password)

        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username,hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        db = get_db()
        cursor = db.cursor()

        # 사용자 검색
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            # BAN 상태 확인
            if user['banned'] == 1:
                flash('이 계정은 정지되었습니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))

            # 계정 잠금 여부 확인 및 로그인 처리 (기존 로직 유지)
            lock_until = user['lock_until']
            if lock_until:
                try:
                    lock_until_dt = datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    lock_until_dt = None
                if lock_until_dt and datetime.now() < lock_until_dt:
                    flash('계정이 잠겨 있습니다. 나중에 다시 시도하세요.')
                    return redirect(url_for('login'))

            stored_password_hash = user['password']
            if check_password(stored_password_hash, password):
                # 로그인 성공: 실패 횟수 초기화 및 잠금 해제
                cursor.execute(
                    "UPDATE user SET failed_attempts = 0, lock_until = NULL WHERE id = ?",
                    (user['id'],)
                )
                db.commit()
                session.permanent = True
                session['user_id'] = user['id']
                session['is_admin'] = user['is_admin']
                session['username'] = user['username']
                flash('로그인 성공!')
                return redirect(url_for('dashboard'))
            else:
                # 비밀번호 틀림 (기존 로직 유지)
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= 5:
                    lock_time = datetime.now() + timedelta(minutes=15)
                    cursor.execute(
                        "UPDATE user SET failed_attempts = ?, lock_until = ? WHERE id = ?",
                        (failed_attempts, lock_time.strftime("%Y-%m-%d %H:%M:%S"), user['id'])
                    )
                    flash('5회 로그인 실패로 계정이 15분간 잠겼습니다.')
                else:
                    cursor.execute(
                        "UPDATE user SET failed_attempts = ? WHERE id = ?",
                        (failed_attempts, user['id'])
                    )
                    flash(f'비밀번호가 올바르지 않습니다. ({5 - failed_attempts}회 남음)')
                db.commit()
        else:
            flash('아이디가 존재하지 않습니다.')

        return redirect(url_for('login'))

    return render_template('login.html', form=form)


def get_user_by_username(username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        return dict(row)
    return None

def update_user(username, failed_attempts=None, lock_until=None):
    cur = conn.cursor()
    if failed_attempts is not None and lock_until is not None:
        cur.execute("UPDATE users SET failed_attempts=?, lock_until=? WHERE username=?",
                    (failed_attempts, lock_until, username))
    elif failed_attempts is not None:
        cur.execute("UPDATE users SET failed_attempts=? WHERE username=?",
                    (failed_attempts, username))
    conn.commit()


# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)


# 프로필 페이지: bio 업데이트 가능
class ProfileForm(FlaskForm):
    bio = TextAreaField('소개글', validators=[DataRequired()])


@app.route('/profile', methods=['GET', 'POST'])
@app.route('/profile/<username>', methods=['GET', 'POST'])
def profile(username=None):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 프로필을 조회할 사용자
    if username is None:
        user_id = session['user_id']  # 로그인한 사용자
        cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    else:
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user is None:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 현재 로그인한 사용자가 관리자 여부 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    is_admin = current_user and current_user['is_admin'] == 1

    form = ProfileForm()

    # 관리자가 BAN 버튼을 클릭했을 경우
    if request.method == 'POST' and is_admin and not user['is_admin']:
        cursor.execute("UPDATE user SET banned = 1 WHERE username = ?", (username,))
        db.commit()
        flash(f"사용자 '{username}'가 BAN되었습니다.")
        return redirect(url_for('dashboard'))

    return render_template('profile.html', user=user, form=form, is_admin=is_admin)

class UnbanForm(FlaskForm):
    username = HiddenField('Username')  # 숨겨진 필드로 사용자 이름 전달

# BAN 기능 구현
@app.route('/admin/ban_user', methods=['POST'])
def admin_ban_user():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    admin_id = session['user_id']
    target_username = request.form.get('username')

    db = get_db()
    cursor = db.cursor()

    # 관리자 권한 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (admin_id,))
    admin = cursor.fetchone()
    if not admin or admin['is_admin'] != 1:
        flash("권한이 없습니다: 관리자만 사용자 BAN이 가능합니다.")
        return redirect(url_for('dashboard'))

    # 대상 사용자 BAN 처리
    cursor.execute("UPDATE user SET banned = 1 WHERE username = ?", (target_username,))
    db.commit()
    
    flash(f"사용자 '{target_username}'가 BAN되었습니다.")
    return redirect(url_for('dashboard'))


@app.route('/admin/banned_users', methods=['GET', 'POST'])
def view_banned_users():
    if not is_admin():
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    # BAN된 사용자 조회
    cursor.execute("SELECT * FROM user WHERE banned = 1")
    banned_users = cursor.fetchall()

    # UnbanForm 생성
    forms = {user['username']: UnbanForm(username=user['username']) for user in banned_users}

    return render_template('view_banned_users.html', banned_users=banned_users, forms=forms)


@app.route('/admin/unban_user', methods=['POST'])
def unban_user():
    if not is_admin():
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('index'))

    form = UnbanForm()
    if form.validate_on_submit():  # CSRF 보호 및 폼 검증
        username = form.username.data

        db = get_db()
        cursor = db.cursor()
        # BAN 해제 처리
        cursor.execute("UPDATE user SET banned = 0 WHERE username = ?", (username,))
        db.commit()
        flash(f"사용자 '{username}'의 BAN이 해제되었습니다.")
        return redirect(url_for('view_banned_users'))

    flash("BAN 해제 요청이 실패했습니다.")
    return redirect(url_for('view_banned_users'))

# 로그 필터링 클래스 정의
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        # 민감 정보 키워드 제거
        sensitive_keywords = ['password', 'session']
        for keyword in sensitive_keywords:
            if keyword in record.getMessage():
                record.msg = record.msg.replace(keyword, '[REDACTED]')
        return True

# 로거 설정
logger = logging.getLogger('flask.app')
logger.addFilter(SensitiveDataFilter())

@app.errorhandler(500)
def internal_error(error):
    # Log a generic error message without including sensitive details
    app.logger.error("500 Internal Server Error 발생")

    # Show a generic error message to the user
    flash("서버에 문제가 발생했습니다. 잠시 후 다시 시도해 주세요.")

    # Redirect the user to the index page
    return redirect(url_for('index')), 500

@app.errorhandler(Exception)
def handle_general_exception(e):
    # Log a generic error message for unexpected exceptions
    app.logger.error("Unexpected error occurred")

    # Show a generic error message to the user
    flash("알 수 없는 문제가 발생했습니다. 잠시 후 다시 시도해 주세요.")

    # Redirect the user to the index page
    return redirect(url_for('index')), 500

# 상품 등록
# 상품 등록 폼 클래스 정의
class ProductForm(FlaskForm):
    title = StringField('상품명', validators=[DataRequired()])
    description = TextAreaField('상품 설명', validators=[DataRequired()])
    price = IntegerField('가격', validators=[DataRequired()])

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = ProductForm()  # 폼 객체 생성
    ################################## 가격 양수 확인 코드드
    if form.validate_on_submit():  # 폼 검증
        try:
            price = form.price.data  # IntegerField에서 가져온 값
            if price % 1 != 0 or price <= 0:  # 정수가 아니거나 0 이하이면 오류
                flash('가격은 양의 정수여야 합니다.')
                return render_template('new_product.html', form=form)
            price = int(price)  # 정수로 변환
        except (ValueError, TypeError):
            flash('올바른 가격을 입력하세요.')
            return render_template('new_product.html', form=form)

        title = form.title.data
        description = form.description.data
        ### message_filter를 이용한 XSS 방어
        if not message_filter(title) or not message_filter(description):
            flash('입력 내용에 허용되지 않는 문자가 포함되어 있습니다.')
            return render_template('new_product.html', form=form)

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html', form=form)  # 폼 객체 전달


# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 상품 삭제하기
@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    # 해당 상품이 현재 로그인한 사용자의 것인지 확인
    cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    product = cursor.fetchone()

    if not product:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('dashboard'))
    
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 가져오기
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 본인 상품인지 확인
    if product['seller_id'] != session['user_id']:
        flash('이 상품을 수정할 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    form = ProductForm(data={
        'title': product['title'],
        'description': product['description'],
        'price': int(product['price']) if product['price'] is not None else None,
    })

    if request.method == 'POST' and form.validate_on_submit():
        title = form.title.data.strip()
        description = form.description.data.strip()

        # message_filter로 XSS 등 필터링
        if not message_filter(title) or not message_filter(description):
            flash('입력 내용에 허용되지 않는 문자가 포함되어 있습니다.')
            return render_template('edit_product.html', form=form, product=product)

        try:
            price = int(form.price.data)
            if price <= 0:
                flash('가격은 양의 정수여야 합니다.')
                return render_template('edit_product.html', form=form, product=product)
        except (ValueError, TypeError):
            flash('올바른 가격을 입력하세요.')
            return render_template('edit_product.html', form=form, product=product)

        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, price = ?
            WHERE id = ?
        """, (title, description, price, product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('edit_product.html', form=form, product=product)

# 관리자 확인 함수
def is_admin():
    if 'user_id' not in session:
        return False
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return user and user['is_admin'] == 1


# 신고하기
class ReportForm(FlaskForm):
    target_id = StringField('신고 대상', validators=[InputRequired()])
    reason = TextAreaField('신고 사유', validators=[InputRequired()])

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    form = ReportForm()
    db = get_db()
    cursor = db.cursor()

    if form.validate_on_submit():
        reporter_id = session['user_id']
        target_id = form.target_id.data.strip()
        reason = form.reason.data.strip()

        # 입력 검증 및 방어 로직
        if len(target_id) > 36 or len(reason) > 300:
            flash('입력 값이 너무 깁니다. 다시 시도해주세요.')
            return render_template('report.html', form=form)

        # XSS 방지
        if not message_filter(reason):
            flash('신고 내용에 허용되지 않는 문자가 포함되어 있습니다.')
            return render_template('report.html', form=form)

        # 자기 자신 신고 방지
        if reporter_id == target_id:
            flash('자기 자신을 신고할 수 없습니다.')
            return render_template('report.html', form=form)

        # 동일 신고자-대상 중복 신고 방지 (최근 24시간 기준)
        cursor.execute("""
            SELECT COUNT(*) as count FROM report
            WHERE reporter_id = ? AND target_id = ? AND created_at >= datetime('now', '-1 day')
        """, (reporter_id, target_id))
        if cursor.fetchone()['count'] > 0:
            flash('최근 24시간 이내에 이미 신고한 사용자입니다.')
            return render_template('report.html', form=form)

        # 하루 신고 횟수 제한
        cursor.execute("""
            SELECT COUNT(*) as count FROM report
            WHERE reporter_id = ? AND DATE(created_at) = DATE('now')
        """, (reporter_id,))
        if cursor.fetchone()['count'] >= 5:
            flash('하루 신고 가능한 횟수를 초과했습니다.')
            return render_template('report.html', form=form)

        report_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_id, reason, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (report_id, reporter_id, target_id, reason))
        db.commit()
        flash('신고가 접수되었습니다. 관리자 검토 후 처리됩니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html', form=form)


# 신고자 확인을 위한 관리 페이지
@app.route('/admin/reports')
def view_reports():
    if not is_admin():
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    # JOIN으로 신고자와 대상의 username 가져오기
    cursor.execute("""
        SELECT r.id, r.reporter_id, r.target_id, r.reason,
               ru.username AS reporter_username,
               tu.username AS target_username
        FROM report r
        LEFT JOIN user ru ON r.reporter_id = ru.id
        LEFT JOIN user tu ON r.target_id = tu.id
    """)
    reports = cursor.fetchall()
    return render_template('view_reports.html', reports=reports)


####### 비밀번호 변경
# 비밀번호 변경 폼 클래스 정의
class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('현재 비밀번호', validators=[DataRequired()])
    new_password = PasswordField('새로운 비밀번호', validators=[DataRequired()])
    confirm_password = PasswordField('새로운 비밀번호 확인', validators=[DataRequired()])

@app.route('/changePassword', methods=['GET', 'POST'])
def pwchange():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    form = PasswordChangeForm()

    # 비밀번호 변경 처리
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data

        # 현재 비밀번호 확인
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
            flash('현재 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('pwchange'))
        if not validate_password(new_password):
            flash('올바르지 않은 비밀번호입니다.')
            return redirect(url_for('pwchange'))
        # 새로운 비밀번호 확인
        if new_password != confirm_password:
            flash('새로운 비밀번호가 일치하지 않습니다.')
            return redirect(url_for('pwchange'))

        # 새로운 비밀번호 해싱 후 저장
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_password, user_id))
        db.commit()

        session.pop('user_id', None)
        flash('비밀번호가 변경되어 로그아웃 됩니다.')
        return redirect(url_for('index'))
    
    return render_template('pwchange.html', user=user, form=form)


#매 요청마다 활동시간 갱신
@app.before_request
def make_session_permanent():
    session.permanent = True

# 보안 헤더 설정
@app.after_request
def set_security_headers(response):
    # Content-Security-Policy (CSP)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "  # 인라인 스타일 허용
        "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "  # 외부 폰트 허용
        "img-src 'self' data:; "  # 이미지와 데이터 URI 허용
    )
    
    # X-Frame-Options
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # X-Content-Type-Options
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # 추가 보안 헤더 (선택 사항)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response



# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    if not message_filter(data['message']): return;
    send(data, broadcast=True)

if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=443, ssl_context=('server.crt', 'server.key'))
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)

