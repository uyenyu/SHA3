import os
import sqlite3
import hashlib
import uuid
import json
from datetime import datetime
from flask import Flask, g, render_template, request, redirect, url_for, flash, session, abort, jsonify
from functools import wraps
from web3 import Web3
from flask_mail import Mail, Message
import random
from werkzeug.utils import secure_filename

PROVIDER_URL = "https://eth-sepolia.g.alchemy.com/v2/nS02cVKqcLkfeaeNtkjz2" 
CONTRACT_ADDRESS = "0x7fb3da7C50697FB2318f7DBE15690c5eB717b249" 
CONTRACT_ABI = """
[
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "string",
				"name": "voteHash",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "address",
				"name": "sender",
				"type": "address"
			}
		],
		"name": "VoteRecorded",
		"type": "event"
	},
	{
		"inputs": [],
		"name": "getVoteCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_voteHash",
				"type": "string"
			}
		],
		"name": "storeVote",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "voteHashes",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]
"""
SERVER_WALLET_ADDRESS = "0x609817767fba18ccf8114d8098420ad0f1209aaa" # Địa chỉ ví của máy chủ (tài khoản Ganache 0)
SERVER_WALLET_PRIVATE_KEY = os.getenv("SERVER_WALLET_KEY") # Chạy: set SERVER_WALLET_KEY=...
# -----------------------------------------------

# --- App Configuration ---
app = Flask(__name__)
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'evoting.db')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a-very-secret-key-that-you-should-change')


app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Hệ thống Bầu cử E-Voting', os.getenv('MAIL_USERNAME'))

mail = Mail(app)

# --- Hashing Helper ---
def sha3_256_hex(s: str) -> str:
    return hashlib.sha3_256(s.encode('utf-8')).hexdigest()

def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${hashed.hex()}"

def check_password(stored_password_hash: str, provided_password: str) -> bool:
    try:
        salt, stored_hash = stored_password_hash.split('$')
        hashed = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return hashed.hex() == stored_hash
    except (ValueError, IndexError):
        return False

# --- HÀM MỚI: Xử lý upload ảnh ---
def handle_avatar_upload(user_id, current_avatar_url):
    avatar_file = request.files.get('avatar')
    avatar_path = current_avatar_url 

    if avatar_file and avatar_file.filename != '' and allowed_file(avatar_file.filename):
        filename = secure_filename(f"user_{user_id}_{avatar_file.filename}")
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        avatar_file.save(save_path)
        avatar_path = f"/static/uploads/{filename}"
    elif avatar_file and not allowed_file(avatar_file.filename):
        flash('Loại tệp ảnh không hợp lệ. Chỉ chấp nhận .png, .jpg, .jpeg, .gif', 'error')

    return avatar_path

# --- Database Management ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with open(os.path.join(os.path.dirname(__file__), 'schema.sql'), 'r', encoding='utf-8') as f:
        db.executescript(f.read())

    superadmin = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    if superadmin is None:
        db.execute(
            '''INSERT INTO users (cccd, username, full_name, email, avatar_url, password_hash, user_hash, role)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (None, 'admin', 'Super Administrator', 'admin@example.com', None,
             hash_password('admin123456'), str(uuid.uuid4()), 'superadmin')
        )
        db.commit()
    print("Database initialized (with new User/Role model).")

@app.cli.command('initdb')
def initdb_command():
    init_db()

# --- Decorators for access control (PHIÊN BẢN ĐÚNG) ---
def admin_required(role="admin"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] == 'user':
                flash("Bạn không có quyền truy cập trang này.", "error")
                return redirect(url_for('user_dashboard'))

            admin_role = session.get('user_role')

            if admin_role == 'superadmin':
                return f(*args, **kwargs)

            if role == "superadmin" and admin_role != 'superadmin':
                flash("Chỉ Super Admin mới có quyền truy cập trang này.", "error")
                return redirect(url_for('admin_dashboard'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Vui lòng đăng nhập.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Main Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        db = get_db()

        # Chỉ tìm trong bảng USERS
        user = db.execute(
            'SELECT * FROM users WHERE cccd = ? OR username = ?', 
            (identifier, identifier)
        ).fetchone()

        if user and check_password(user['password_hash'], password):
            # --- LOGIC 2FA ---
            if not user['email']:
                flash('Tài khoản của bạn chưa đăng ký email để xác thực 2FA.', 'error')
                return render_template('login.html')

            otp_code = str(random.randint(100000, 999999))

            session['2fa_user_id'] = user['id']
            session['2fa_otp'] = otp_code
            session['2fa_timestamp'] = datetime.utcnow().timestamp()
            session['2fa_user_email'] = user['email'] 

            try:
                msg = Message(
                    'Mã Xác thực 2FA của bạn - Hệ thống Bầu cử',
                    recipients=[user['email']]
                )
                msg.html = f"""<p>Mã OTP của bạn là: <h2>{otp_code}</h2></p><p>Mã này sẽ hết hạn sau 5 phút.</p>"""
                mail.send(msg)
            except Exception as e:
                print(f"Lỗi Gửi Mail: {e}")
                flash('Lỗi hệ thống khi gửi email. Vui lòng thử lại sau.', 'error')
                return redirect(url_for('login'))

            flash('Mã xác thực 6 số đã được gửi đến email của bạn.', 'success')
            return redirect(url_for('verify_2fa'))

        flash('Sai Tên tài khoản/CCCD hoặc Mật khẩu.', 'error')
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        submitted_otp = request.form['otp']

        if (datetime.utcnow().timestamp() - session.get('2fa_timestamp', 0)) > 300:
            flash('Mã OTP đã hết hạn. Vui lòng đăng nhập lại.', 'error')
            session.pop('2fa_user_id', None)
            session.pop('2fa_otp', None)
            session.pop('2fa_timestamp', None)
            session.pop('2fa_user_email', None)
            return redirect(url_for('login'))

        if submitted_otp == session['2fa_otp']:
            user_id = session['2fa_user_id']
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

            session.clear() 
            session['user_id'] = user['id']
            session['user_name'] = user['full_name']
            session['user_role'] = user['role']
            session['user_organization_id'] = user['organization_id']
            session['user_avatar'] = user['avatar_url']

            flash('Xác thực 2 yếu tố thành công!', 'success')
            if user['role'] in ('superadmin', 'admin'):
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Mã OTP không chính xác. Vui lòng thử lại.', 'error')
            return redirect(url_for('verify_2fa'))

    return render_template('verify_2fa.html', user_email=session.get('2fa_user_email'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- User Registration Route ---
@app.route('/register', methods=['GET', 'POST'])
def user_register():
    db = get_db()
    organizations = db.execute('SELECT * FROM organizations ORDER BY name').fetchall()

    if request.method == 'POST':
        cccd = request.form['cccd']
        full_name = request.form['full_name']
        email = request.form.get('email')
        gender = request.form.get('gender')
        dob = request.form.get('dob')
        phone = request.form['phone']
        address = request.form['address']
        organization_id = request.form.get('organization_id')
        password = request.form['password']

        if not cccd or not full_name or not email or not phone or not organization_id or not password or not dob:
            flash('Vui lòng điền đầy đủ các trường bắt buộc.', 'error')
            return render_template('user/register.html', organizations=organizations, **request.form)
        if not cccd.isdigit() or len(cccd) != 12:
            flash('Số CCCD phải có đúng 12 chữ số.', 'error')
            return render_template('user/register.html', organizations=organizations, **request.form)
        if not phone.isdigit() or len(phone) != 10:
            flash('Số điện thoại phải có đúng 10 chữ số.', 'error')
            return render_template('user/register.html', organizations=organizations, **request.form)

        if db.execute('SELECT id FROM users WHERE cccd = ?', (cccd,)).fetchone():
            flash('Số CCCD này đã được đăng ký.', 'error')
            return render_template('user/register.html', organizations=organizations, **request.form)
        if db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
            flash('Email này đã được sử dụng.', 'error')
            return render_template('user/register.html', organizations=organizations, **request.form)

        password_hash = hash_password(password)
        user_hash = str(uuid.uuid4())

        db.execute(
            '''INSERT INTO users (cccd, full_name, email, gender, dob, phone, address, organization_id, avatar_url, password_hash, user_hash, role) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'user')''',
            (cccd, full_name, email, gender, dob, phone, address, organization_id, None, password_hash, user_hash)
        )
        db.commit()
        flash('Đăng ký thành công! Vui lòng đăng nhập.', 'success')
        return redirect(url_for('login'))

    return render_template('user/register.html', organizations=organizations)

# --- Admin Routes ---
@app.route('/admin/dashboard')
@admin_required()
def admin_dashboard():
    db = get_db()
    now_str = datetime.utcnow().isoformat()
    admin_role = session.get('user_role')
    admin_org_id = session.get('user_organization_id')

    query = '''
        SELECT e.*, o.name as org_name 
        FROM elections e 
        LEFT JOIN organizations o ON e.organization_id = o.id
        WHERE e.start_date <= ? AND e.end_date > ?
    '''
    params = [now_str, now_str]

    if admin_role == 'admin':
        query += " AND e.organization_id = ?"
        params.append(admin_org_id)

    query += " ORDER BY e.end_date ASC"
    ongoing_elections = db.execute(query, tuple(params)).fetchall()

    if admin_role == 'superadmin':
        total_users = db.execute('SELECT COUNT(id) FROM users WHERE role != ?', ('superadmin',)).fetchone()[0]
        total_elections = db.execute('SELECT COUNT(id) FROM elections').fetchone()[0]
    else:
        total_users = db.execute('SELECT COUNT(id) FROM users WHERE organization_id = ?', (admin_org_id,)).fetchone()[0]
        total_elections = db.execute('SELECT COUNT(id) FROM elections WHERE organization_id = ?', (admin_org_id,)).fetchone()[0]

    return render_template('admin/dashboard.html', 
                           ongoing_elections=ongoing_elections,
                           total_users=total_users,
                           total_elections=total_elections)

@app.route('/admin/api/election_stats/<int:election_id>')
@admin_required()
def api_election_stats(election_id):
    db = get_db()

    admin_role = session.get('user_role')
    admin_org_id = session.get('user_organization_id')

    election = db.execute('SELECT * FROM elections WHERE id = ?', (election_id,)).fetchone()
    if not election:
        return jsonify({"error": "Election not found"}), 404

    if admin_role == 'admin' and election['organization_id'] != admin_org_id:
        return jsonify({"error": "Access denied"}), 403

    results = db.execute('''
        SELECT u.full_name as name, COUNT(v.id) as vote_count
        FROM users u
        LEFT JOIN votes v ON u.id = v.voted_for_user_id
        WHERE v.election_id = ?
        GROUP BY u.id
        ORDER BY vote_count DESC
    ''', (election_id,)).fetchall()

    total_votes = db.execute('SELECT COUNT(id) FROM votes WHERE election_id = ?', (election_id,)).fetchone()[0]
    results_list = [dict(row) for row in results]

    return jsonify({
        "election_name": election['name'],
        "results": results_list,
        "total_votes": total_votes
    })

@app.route('/admin/elections', methods=['GET', 'POST'])
@admin_required()
def manage_elections():
    db = get_db()
    admin_role = session.get('user_role')
    admin_org_id = session.get('user_organization_id')

    organizations = []
    all_users = []
    if admin_role == 'superadmin':
        organizations = db.execute('SELECT * FROM organizations ORDER BY name').fetchall()
        all_users = db.execute('SELECT id, full_name, cccd FROM users WHERE role != ?', ('superadmin',)).fetchall()
    else:
        all_users = db.execute('SELECT id, full_name, cccd FROM users WHERE organization_id = ?', (admin_org_id,)).fetchall()

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        candidate_user_ids = request.form.getlist('candidate_user_ids') 

        organization_id = None
        if admin_role == 'superadmin':
            organization_id = request.form['organization_id']
        else:
            organization_id = admin_org_id

        if not organization_id:
            flash('Lỗi: Tài khoản Admin của bạn chưa được gán vào đơn vị nào.', 'error')
            return redirect(url_for('manage_elections'))

        if start_date >= end_date:
            flash('Lỗi: Ngày kết thúc phải sau ngày bắt đầu.', 'error')
            elections = get_admin_elections(db, admin_role, admin_org_id)
            return render_template('admin/manage_elections.html', elections=elections, organizations=organizations, all_users=all_users)

        election_code = str(uuid.uuid4())[:8].upper()
        cur = db.cursor()
        cur.execute(
            '''INSERT INTO elections (name, description, organization_id, start_date, end_date, election_code) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (name, description, organization_id, start_date, end_date, election_code)
        )
        new_election_id = cur.lastrowid 

        if candidate_user_ids:
            for user_id in candidate_user_ids:
                db.execute(
                    'INSERT INTO election_candidates (election_id, user_id, description) VALUES (?, ?, ?)',
                    (new_election_id, int(user_id), 'Ứng cử viên')
                )

        db.commit()
        flash('Tạo cuộc bầu cử thành công!', 'success')
        return redirect(url_for('manage_elections'))

    elections = get_admin_elections(db, admin_role, admin_org_id)
    return render_template(
        'admin/manage_elections.html', 
        elections=elections, 
        organizations=organizations, 
        all_users=all_users
    )

def get_admin_elections(db, admin_role, admin_org_id):
    """Hàm helper: Lấy danh sách bầu cử dựa trên quyền của admin."""
    base_query = '''
        SELECT e.*, o.name as org_name 
        FROM elections e 
        LEFT JOIN organizations o ON e.organization_id = o.id
    '''
    if admin_role == 'superadmin':
        return db.execute(f"{base_query} ORDER BY e.start_date DESC").fetchall()
    else:
        return db.execute(
            f"{base_query} WHERE e.organization_id = ? ORDER BY e.start_date DESC", 
            (admin_org_id,)
        ).fetchall()

@app.route('/admin/elections/delete/<int:election_id>', methods=['POST'])
@admin_required()
def delete_election(election_id):
    db = get_db()
    # TODO: Kiểm tra quyền sở hữu
    db.execute('DELETE FROM votes WHERE election_id = ?', (election_id,))
    db.execute('DELETE FROM election_candidates WHERE election_id = ?', (election_id,))
    db.execute('DELETE FROM elections WHERE id = ?', (election_id,))
    db.commit()
    flash('Cuộc bầu cử đã được xóa.', 'success')
    return redirect(url_for('manage_elections'))

@app.route('/admin/elections/<int:election_id>/candidates', methods=['GET', 'POST'])
@admin_required()
def manage_candidates(election_id):
    db = get_db()
    # TODO: Kiểm tra quyền sở hữu

    election = db.execute('SELECT * FROM elections WHERE id = ?', (election_id,)).fetchone()
    if not election: abort(404)

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        description = request.form['description']

        if not user_id:
            flash('Vui lòng chọn một người dùng.', 'error')
        else:
            existing = db.execute(
                'SELECT id FROM election_candidates WHERE user_id = ? AND election_id = ?',
                (user_id, election_id)
            ).fetchone()
            if existing:
                flash('Người dùng này đã là ứng viên.', 'error')
            else:
                db.execute(
                    'INSERT INTO election_candidates (election_id, user_id, description) VALUES (?, ?, ?)',
                    (election_id, user_id, description)
                )
                db.commit()
                flash('Thêm ứng viên thành công!', 'success')
        return redirect(url_for('manage_candidates', election_id=election_id))

    current_candidates = db.execute(
        '''SELECT ec.id, u.full_name, u.cccd, ec.description
           FROM election_candidates ec
           JOIN users u ON ec.user_id = u.id
           WHERE ec.election_id = ?''',
        (election_id,)
    ).fetchall()

    all_users = db.execute(
        'SELECT id, full_name, cccd FROM users WHERE organization_id = ?', 
        (election['organization_id'],)
    ).fetchall()

    return render_template(
        'admin/manage_candidates.html', 
        election=election, 
        current_candidates=current_candidates,
        all_users=all_users
    )

@app.route('/admin/candidates/delete/<int:candidate_link_id>', methods=['POST'])
@admin_required()
def delete_candidate(candidate_link_id):
    db = get_db()
    # TODO: Kiểm tra quyền sở hữu
    candidate = db.execute('SELECT election_id FROM election_candidates WHERE id = ?', (candidate_link_id,)).fetchone()
    if candidate:
        db.execute('DELETE FROM election_candidates WHERE id = ?', (candidate_link_id,))
        db.commit()
        flash('Ứng viên đã được xóa.', 'success')
        return redirect(url_for('manage_candidates', election_id=candidate['election_id']))
    return redirect(url_for('manage_elections'))

@app.route('/admin/elections/<int:election_id>/results')
@admin_required()
def election_results(election_id):
    db = get_db()
    # TODO: Kiểm tra quyền sở hữu
    election = db.execute('SELECT * FROM elections WHERE id = ?', (election_id,)).fetchone()
    if not election: abort(404)

    results = db.execute('''
        SELECT u.full_name as name, COUNT(v.id) as vote_count
        FROM users u
        LEFT JOIN votes v ON u.id = v.voted_for_user_id
        WHERE v.election_id = ?
        GROUP BY u.id
        ORDER BY vote_count DESC
    ''', (election_id,)).fetchall()

    total_votes = db.execute('SELECT COUNT(id) FROM votes WHERE election_id = ?', (election_id,)).fetchone()[0]

    return render_template('admin/election_results.html', election=election, results=results, total_votes=total_votes)

@app.route('/admin/users')
@admin_required()
def manage_users():
    db = get_db()
    admin_role = session.get('user_role')
    admin_org_id = session.get('user_organization_id')

    query = '''
        SELECT u.id, u.cccd, u.full_name, u.email, u.phone, u.dob, u.gender, o.name as org_name 
        FROM users u 
        LEFT JOIN organizations o ON u.organization_id = o.id 
        WHERE u.role != ?
    '''
    params = ['superadmin']

    if admin_role == 'admin':
        query += " AND u.organization_id = ?"
        params.append(admin_org_id)

    query += " ORDER BY u.full_name ASC"
    users = db.execute(query, tuple(params)).fetchall()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required()
def edit_user(user_id):
    db = get_db()
    # TODO: Kiểm tra quyền sở hữu

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        gender = request.form['gender']
        dob = request.form.get('dob')
        phone = request.form['phone']
        address = request.form['address']
        organization_id = request.form['organization_id']

        existing = db.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, user_id)).fetchone()
        if existing:
            flash('Email này đã được sử dụng bởi người dùng khác.', 'error')
            user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            organizations = db.execute('SELECT * FROM organizations ORDER BY name').fetchall()
            return render_template('admin/edit_user.html', user=user, organizations=organizations)

        db.execute(
                '''UPDATE users SET full_name=?, email=?, gender=?, dob=?, phone=?, address=?, 
                   organization_id=?, avatar_url=?
                   WHERE id = ?''',
                (full_name, email, gender, dob, phone, address, organization_id, avatar_path, user_id)
            )
        db.commit()
        flash('Cập nhật người dùng thành công.', 'success')
        return redirect(url_for('manage_users'))

    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user: abort(404)

    organizations = []
    if session.get('user_role') == 'superadmin':
         organizations = db.execute('SELECT * FROM organizations ORDER BY name').fetchall()
    else:
         organizations = db.execute('SELECT * FROM organizations WHERE id = ?', (session.get('user_organization_id'),)).fetchall()

    return render_template('admin/edit_user.html', user=user, organizations=organizations)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required()
def delete_user(user_id):
    db = get_db()
    # TODO: Kiểm tra quyền sở hữu
    db.execute('DELETE FROM votes WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('Người dùng đã được xóa.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/users/new', methods=['GET', 'POST'])
@admin_required()
def admin_add_user():
    db = get_db()
    admin_role = session.get('user_role')
    admin_org_id = session.get('user_organization_id')

    organizations = []
    if admin_role == 'superadmin':
        organizations = db.execute('SELECT * FROM organizations ORDER BY name').fetchall()
    else:
        organizations = db.execute('SELECT * FROM organizations WHERE id = ?', (admin_org_id,)).fetchall()

    if request.method == 'POST':
        cccd = request.form['cccd']
        full_name = request.form['full_name']
        email = request.form.get('email')
        gender = request.form.get('gender')
        dob = request.form.get('dob')
        phone = request.form['phone']
        address = request.form.get('address')
        organization_id = request.form.get('organization_id')
        password = request.form['password']
        role = request.form.get('role', 'user')

        if not cccd or not full_name or not email or not phone or not organization_id or not password or not dob:
            flash('Vui lòng điền đầy đủ các trường bắt buộc.', 'error')
            return render_template('admin/add_user.html', organizations=organizations, **request.form)

        if admin_role == 'admin' and role != 'user':
            flash('Bạn chỉ có quyền tạo tài khoản "User".', 'error')
            return render_template('admin/add_user.html', organizations=organizations, **request.form)
        if admin_role == 'admin' and int(organization_id) != admin_org_id:
            flash('Bạn chỉ có quyền thêm người dùng vào đơn vị của mình.', 'error')
            return render_template('admin/add_user.html', organizations=organizations, **request.form)

        if not cccd.isdigit() or len(cccd) != 12:
            flash('Số CCCD phải có đúng 12 chữ số.', 'error')
            return render_template('admin/add_user.html', organizations=organizations, **request.form)
        if not phone.isdigit() or len(phone) != 10:
            flash('Số điện thoại phải có đúng 10 chữ số.', 'error')
            return render_template('admin/add_user.html', organizations=organizations, **request.form)

        if db.execute('SELECT id FROM users WHERE cccd = ?', (cccd,)).fetchone():
            flash('Số CCCD này đã được đăng ký.', 'error')
            return render_template('admin/add_user.html', organizations=organizations, **request.form)
        if db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
            flash('Email này đã được sử dụng.', 'error')
            return render_template('admin/add_user.html', organizations=organizations, **request.form)

        password_hash = hash_password(password)
        user_hash = str(uuid.uuid4())

        db.execute(
            '''INSERT INTO users (cccd, full_name, email, gender, dob, phone, address, organization_id, avatar_url, password_hash, user_hash, role) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (cccd, full_name, email, gender, dob, phone, address, organization_id, None, password_hash, user_hash, role)
        )
        db.commit()
        flash('Tạo người dùng mới thành công!', 'success')
        return redirect(url_for('manage_users'))

    return render_template('admin/add_user.html', organizations=organizations)

# --- Quản lý Admin (Superadmin only) ---
@app.route('/admin/settings/organizations', methods=['GET', 'POST'])
@admin_required(role="superadmin")
def manage_organizations():
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        address = request.form.get('address')
        manager_user_id = request.form.get('manager_user_id')

        if not manager_user_id:
            manager_user_id = None

        if not name:
            flash('Tên đơn vị không được để trống.', 'error')
        elif db.execute('SELECT id FROM organizations WHERE name = ?', (name,)).fetchone():
            flash('Tên đơn vị này đã tồn tại.', 'error')
        else:
            db.execute('INSERT INTO organizations (name, address, manager_user_id) VALUES (?, ?, ?)', 
                       (name, address, manager_user_id))
            db.commit()
            flash('Đã thêm đơn vị mới.', 'success')
        return redirect(url_for('manage_organizations'))

    organizations = db.execute('''
        SELECT o.*, u.username as manager_name 
        FROM organizations o
        LEFT JOIN users u ON o.manager_user_id = u.id
        ORDER BY o.name
    ''').fetchall()

    admins = db.execute('SELECT id, username FROM users WHERE role = ? ORDER BY username', ('admin',)).fetchall()

    return render_template('admin/manage_organizations.html', organizations=organizations, admins=admins)

@app.route('/admin/settings/organizations/delete/<int:org_id>', methods=['POST'])
@admin_required(role="superadmin")
def delete_organization(org_id):
    db = get_db()
    db.execute('UPDATE users SET organization_id = NULL WHERE organization_id = ?', (org_id,))
    db.execute('UPDATE elections SET organization_id = NULL WHERE organization_id = ?', (org_id,))
    db.execute('DELETE FROM organizations WHERE id = ?', (org_id,))
    db.commit()
    flash('Đã xóa đơn vị.', 'success')
    return redirect(url_for('manage_organizations'))

@app.route('/admin/manage_roles', methods=['GET', 'POST'])
@admin_required(role="superadmin")
def manage_roles():
    db = get_db()
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('role')

        if not user_id or not new_role:
            flash('Vui lòng chọn user và vai trò.', 'error')
        elif int(user_id) == session['user_id']:
            flash('Không thể tự thay đổi vai trò của chính mình.', 'error')
        else:
            db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
            db.commit()
            flash('Cập nhật vai trò thành công.', 'success')
        return redirect(url_for('manage_roles'))

    all_users = db.execute(
        'SELECT id, full_name, username, cccd, role FROM users WHERE id != ? ORDER BY full_name',
        (session['user_id'],)
    ).fetchall()
    return render_template('admin/manage_roles.html', users=all_users)

@app.route('/admin/profile', methods=['GET', 'POST'])
@admin_required()
def admin_profile():
    admin_id = session['user_id']
    db = get_db()
    admin = db.execute('SELECT * FROM users WHERE id = ?', (admin_id,)).fetchone()

    if admin is None:
        flash('Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại.', 'error')
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        gender = request.form['gender']
        dob = request.form.get('dob')
        phone = request.form['phone']
        address = request.form['address']
        organization_id = request.form.get('organization_id')
        new_password = request.form['password']

        if not organization_id or not email or not phone or not dob or not full_name:
             flash('Vui lòng điền các trường bắt buộc.', 'error')
             return redirect(url_for('admin_profile'))
        existing = db.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, admin_id)).fetchone()
        if existing:
            flash('Email này đã được sử dụng bởi người dùng khác.', 'error')
            return redirect(url_for('admin_profile'))
        if not phone.isdigit() or len(phone) != 10:
            flash('Số điện thoại phải có đúng 10 chữ số.', 'error')
            return redirect(url_for('admin_profile'))

        avatar_path = handle_avatar_upload(admin_id, admin['avatar_url'])
        session['user_avatar'] = avatar_path

        if session['user_role'] == 'superadmin' and 'username' in request.form:
            new_username = request.form['username']
            existing_username = db.execute('SELECT id FROM users WHERE username = ? AND id != ?', (new_username, admin_id)).fetchone()
            if existing_username:
                flash('Tên đăng nhập đã tồn tại.', 'error')
            else:
                db.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, admin_id))
                session['user_name'] = new_username

        if new_password:
            password_hash = hash_password(new_password)
            db.execute(
                '''UPDATE users SET full_name=?, email=?, gender=?, dob=?, phone=?, address=?, 
                   organization_id=?, password_hash=?, avatar_url=?
                   WHERE id = ?''',
                (full_name, email, gender, dob, phone, address, organization_id, password_hash, avatar_path, admin_id)
            )
        else:
            db.execute(
                '''UPDATE users SET full_name=?, email=?, gender=?, dob=?, phone=?, address=?, 
                   organization_id=?, avatar_url=?
                   WHERE id = ?''',
                (full_name, email, gender, dob, phone, address, organization_id, avatar_path, admin_id)
            )
        db.commit()
        if session['user_role'] != 'superadmin':
            session['user_name'] = full_name
        flash('Hồ sơ của bạn đã được cập nhật.', 'success')
        return redirect(url_for('admin_profile'))

    organizations = db.execute('SELECT * FROM organizations ORDER BY name').fetchall()
    return render_template('admin/admin_profile.html', user=admin, organizations=organizations)

# --- User Routes ---
@app.route('/dashboard')
@user_required
def user_dashboard():
    db = get_db()
    user_id = session['user_id']
    user = db.execute('SELECT organization_id FROM users WHERE id = ?', (user_id,)).fetchone()
    user_org_id = user['organization_id'] if user else None

    ongoing_elections = []
    finished_elections = []

    if user_org_id:
        now_str = datetime.utcnow().isoformat()

        ongoing_elections = db.execute(
            '''SELECT e.*, o.name as org_name 
               FROM elections e LEFT JOIN organizations o ON e.organization_id = o.id
               WHERE e.organization_id = ? AND e.start_date <= ? AND e.end_date > ? 
               ORDER BY e.end_date ASC''', 
            (user_org_id, now_str, now_str)
        ).fetchall()

        finished_elections = db.execute(
            '''SELECT e.*, o.name as org_name 
               FROM elections e LEFT JOIN organizations o ON e.organization_id = o.id
               WHERE e.organization_id = ? AND e.end_date <= ? 
               ORDER BY e.end_date DESC''', 
            (user_org_id, now_str)
        ).fetchall()
    else:
        flash('Bạn chưa cập nhật "Đơn vị hoạt động". Vui lòng cập nhật hồ sơ để xem các cuộc bầu cử.', 'error')

    return render_template('user/dashboard.html', 
                           ongoing_elections=ongoing_elections, 
                           finished_elections=finished_elections)

@app.route('/profile', methods=['GET', 'POST'])
@user_required
def user_profile():
    user_id = session['user_id']
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if user is None:
        flash('Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại.', 'error')
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        gender = request.form['gender']
        dob = request.form.get('dob')
        phone = request.form['phone']
        address = request.form['address']
        organization_id = request.form['organization_id']
        new_password = request.form['password']

        if not organization_id or not email or not phone or not dob or not full_name:
             flash('Vui lòng điền các trường bắt buộc.', 'error')
             return redirect(url_for('user_profile'))

        existing = db.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, user_id)).fetchone()
        if existing:
            flash('Email này đã được sử dụng bởi người dùng khác.', 'error')
            return redirect(url_for('user_profile'))

        if not phone.isdigit() or len(phone) != 10:
            flash('Số điện thoại phải có đúng 10 chữ số.', 'error')
            return redirect(url_for('user_profile'))

        avatar_path = handle_avatar_upload(user_id, user['avatar_url'])
        session['user_avatar'] = avatar_path

        if new_password:
            password_hash = hash_password(new_password)
            db.execute(
                '''UPDATE users SET full_name=?, email=?, gender=?, dob=?, phone=?, address=?, 
                   organization_id=?, password_hash=?, avatar_url=?
                   WHERE id = ?''',
                (full_name, email, gender, dob, phone, address, organization_id, password_hash, avatar_path, user_id)
            )
        else:
            db.execute(
                '''UPDATE users SET full_name=?, email=?, gender=?, dob=?, phone=?, address=?, 
                   organization_id=?, avatar_url=?
                   WHERE id = ?''',
                (full_name, email, gender, dob, phone, address, organization_id, avatar_path, user_id)
            )

        db.commit()
        session['user_name'] = full_name
        flash('Hồ sơ của bạn đã được cập nhật.', 'success')
        return redirect(url_for('user_profile'))

    organizations = db.execute('SELECT * FROM organizations ORDER BY name').fetchall()
    return render_template('user/profile.html', user=user, organizations=organizations)

@app.route('/vote', methods=['POST'])
@user_required
def enter_election_code():
    election_code = request.form['election_code'].upper()
    db = get_db()
    election = db.execute('SELECT * FROM elections WHERE election_code = ?', (election_code,)).fetchone()
    if not election:
        flash('Mã cuộc bầu cử không hợp lệ.', 'error')
        return redirect(url_for('user_dashboard'))
    has_voted = db.execute('SELECT id FROM votes WHERE user_id = ? AND election_id = ?',
                           (session['user_id'], election['id'])).fetchone()
    if has_voted:
        flash('Bạn đã bỏ phiếu trong cuộc bầu cử này rồi.', 'error')
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('vote_page', election_id=election['id']))

@app.route('/vote/<int:election_id>', methods=['GET', 'POST'])
@user_required
def vote_page(election_id):
    db = get_db()
    election = db.execute('SELECT * FROM elections WHERE id = ?', (election_id,)).fetchone()
    if not election: abort(404)

    user = db.execute('SELECT organization_id FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if election['organization_id'] != user['organization_id']:
        flash('Bạn không thuộc đơn vị tổ chức cuộc bầu cử này.', 'error')
        return redirect(url_for('user_dashboard'))

    now_str = datetime.utcnow().isoformat()
    if now_str < election['start_date']:
        flash('Cuộc bầu cử này chưa bắt đầu.', 'error')
        return redirect(url_for('user_dashboard'))
    if now_str > election['end_date']:
        flash('Cuộc bầu cử này đã kết thúc.', 'error')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        submitted_code = request.form.get('election_code', '').upper()
        if submitted_code != election['election_code']:
            flash('Mã cuộc bầu cử không chính xác. Vui lòng liên hệ Admin để lấy mã.', 'error')
            candidates = get_election_candidates(db, election_id)
            return render_template('user/vote.html', election=election, candidates=candidates)

        candidate_user_id = request.form.get('candidate_user_id')
        if not candidate_user_id:
            flash('Vui lòng chọn một ứng viên.', 'error')
            candidates = get_election_candidates(db, election_id)
            return render_template('user/vote.html', election=election, candidates=candidates)

        user_id = session['user_id']
        has_voted = db.execute('SELECT id FROM votes WHERE user_id = ? AND election_id = ?',
                               (user_id, election_id)).fetchone()
        if has_voted:
            flash('Bạn đã bỏ phiếu trong cuộc bầu cử này rồi.', 'error')
            return redirect(url_for('user_dashboard'))

        candidate_user_id = int(candidate_user_id)
        timestamp = datetime.utcnow().isoformat() + "Z"
        vote_data = {
            "election_id": election_id,
            "voter_user_id": user_id, 
            "candidate_user_id": candidate_user_id,
            "timestamp": timestamp
        }
        vote_data_string = json.dumps(vote_data, sort_keys=True, separators=(',', ':'))
        vote_hash = sha3_256_hex(vote_data_string)

        # Write to blockchain
        try:
            w3 = Web3(Web3.HTTPProvider(PROVIDER_URL))
            if not w3.is_connected():
                flash('Không thể kết nối đến Blockchain node.', 'error')
                return redirect(url_for('vote_page', election_id=election_id))

            try:
                checksum_address = w3.to_checksum_address(SERVER_WALLET_ADDRESS)
            except Exception:
                flash('Lỗi cấu hình: Địa chỉ ví máy chủ không hợp lệ.', 'error')
                return redirect(url_for('vote_page', election_id=election_id))

            contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
            nonce = w3.eth.get_transaction_count(checksum_address)
            tx = contract.functions.storeVote(vote_hash).build_transaction({
                'chainId': w3.eth.chain_id,
                'gas': 70000,
                'gasPrice': w3.eth.gas_price,
                'from': checksum_address,
                'nonce': nonce
            })

            if not SERVER_WALLET_PRIVATE_KEY:
                flash('Lỗi cấu hình máy chủ: Thiếu khóa bí mật.', 'error')
                return redirect(url_for('vote_page', election_id=election_id))

            signed_tx = w3.eth.account.sign_transaction(tx, private_key=SERVER_WALLET_PRIVATE_KEY)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash)

        except Exception as e:
            print(f"Blockchain Error: {e}")
            flash('Lỗi nghiêm trọng: Không thể ghi phiếu lên Blockchain.', 'error')
            return redirect(url_for('vote_page', election_id=election_id))

        db.execute(
            '''INSERT INTO votes (user_id, election_id, voted_for_user_id, vote_hash, vote_data) 
               VALUES (?, ?, ?, ?, ?)''',
            (user_id, election_id, candidate_user_id, vote_hash, vote_data_string)
        )
        db.commit()
        flash('Cảm ơn bạn! Lá phiếu của bạn đã được ghi nhận an toàn.', 'success')
        return redirect(url_for('user_dashboard'))

    candidates = get_election_candidates(db, election_id)
    return render_template('user/vote.html', election=election, candidates=candidates)

def get_election_candidates(db, election_id):
    return db.execute(
        '''SELECT u.id, u.full_name, ec.description 
           FROM users u
           JOIN election_candidates ec ON u.id = ec.user_id
           WHERE ec.election_id = ?''',
        (election_id,)
    ).fetchall()

@app.route('/audit/<int:election_id>')
def audit_log(election_id):
    db = get_db()
    election = db.execute('SELECT name FROM elections WHERE id = ?', (election_id,)).fetchone()
    if not election: abort(404)
    votes = db.execute(
        'SELECT vote_hash, voted_at FROM votes WHERE election_id = ? ORDER BY voted_at ASC',
        (election_id,)
    ).fetchall()
    return render_template('audit_log.html', votes=votes, election=election)

@app.route('/results/<int:election_id>')
@user_required
def user_election_results(election_id):
    db = get_db()
    user_id = session['user_id']
    user = db.execute('SELECT organization_id FROM users WHERE id = ?', (user_id,)).fetchone()
    user_org_id = user['organization_id'] if user else None

    election = db.execute('SELECT * FROM elections WHERE id = ?', (election_id,)).fetchone()
    if not election:
        abort(404)

    if election['organization_id'] != user_org_id:
        flash('Bạn không thuộc đơn vị của cuộc bầu cử này.', 'error')
        return redirect(url_for('user_dashboard'))

    now_str = datetime.utcnow().isoformat()
    if now_str <= election['end_date']:
        flash('Bạn chỉ có thể xem kết quả sau khi cuộc bầu cử đã kết thúc.', 'info')
        return redirect(url_for('user_dashboard'))

    results = db.execute('''
        SELECT u.full_name as name, COUNT(v.id) as vote_count
        FROM users u
        LEFT JOIN votes v ON u.id = v.voted_for_user_id
        WHERE v.election_id = ?
        GROUP BY u.id
        ORDER BY vote_count DESC
    ''', (election_id,)).fetchall()

    total_votes = db.execute('SELECT COUNT(id) FROM votes WHERE election_id = ?', (election_id,)).fetchone()[0]

    my_vote = db.execute('''
        SELECT v.vote_hash, u.full_name as candidate_name
        FROM votes v
        JOIN users u ON v.voted_for_user_id = u.id
        WHERE v.election_id = ? AND v.user_id = ?
    ''', (election_id, user_id)).fetchone()

    return render_template('user/results.html', 
                           election=election, 
                           results=results, 
                           total_votes=total_votes,
                           my_vote=my_vote)

if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        with app.app_context():
            init_db()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)