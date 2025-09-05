from flask import Flask, render_template_string, request, redirect, url_for, flash, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz
import json
import os
from sqlalchemy import func, text

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

PK_TZ = pytz.timezone('Asia/Karachi')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(150))
    role = db.Column(db.String(20))
    department = db.Column(db.String(100))
    signature_filename = db.Column(db.String(200))  # e.g. 'muneeb.png'
    email = db.Column(db.String(255), unique=True, nullable=True)  # email field

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class AccountsBatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(PK_TZ))
    total_amount = db.Column(db.Float, default=0.0)
    items_json = db.Column(db.Text)  # aggregated items: dept, item_description, price, qty, total, req_id, date
    requisition_ids = db.Column(db.Text)  # JSON list of requisition IDs
    notes = db.Column(db.Text)

    created_by = db.relationship('User')

class Requisition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    department = db.Column(db.String(100))
    items_json = db.Column(db.Text)
    total_amount = db.Column(db.Float)
    status = db.Column(db.String(30), default='Pending Manager Approval')
    claimed_signature = db.Column(db.Text)  # creator's signature path or empty string
    manager_signature = db.Column(db.String(200))
    countryhead_signature = db.Column(db.String(200))
    ceo_signature = db.Column(db.String(200))
    vendor_details = db.Column(db.String(300))
    phone = db.Column(db.String(50))
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(PK_TZ))
    pending_date = db.Column(db.DateTime)
    decision_date = db.Column(db.DateTime)
    countryhead_approval_needed = db.Column(db.Boolean, default=False)

    # For Accounts
    accounts_status = db.Column(db.String(50))          # e.g., "New Requisition", "Merged"
    accounts_batch_id = db.Column(db.Integer)           # link to AccountsBatch.id

    created_by = db.relationship('User', backref='requisitions')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def format_datetime_pk(dt):
    if not dt:
        return '-'
    dt_pk = dt.astimezone(PK_TZ)
    return dt_pk.strftime('%d/%m/%Y %H:%M')

def get_signature_path(user):
    """
    Resolve a user's signature image path relative to /static.
    Priority:
      1) user.signature_filename (if exists under static/signatures)
      2) static/signatures/<username>.png (case-insensitive match)
    If found and user.signature_filename is empty/different, update it.
    Returns '' if not found.
    """
    if not user:
        return ''
    static_folder = current_app.static_folder if current_app else app.static_folder
    candidates = []

    if user.signature_filename:
        candidates.append(user.signature_filename.strip())

    if user.username:
        uname = user.username.strip()
        candidates.extend([f"{uname}.png", f"{uname.lower()}.png", f"{uname.upper()}.png"])

    for name in candidates:
        if not name:
            continue
        base = os.path.basename(name)
        rel = f"signatures/{base}"
        abs_path = os.path.join(static_folder, rel)
        if os.path.exists(abs_path):
            if user.signature_filename != base:
                try:
                    user.signature_filename = base
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            return rel
    return ''

# Debug routes
@app.route('/debug/signature-filename')
@login_required
def debug_signature_filename():
    return f"User: {current_user.username}, Signature filename: {current_user.signature_filename}"

@app.route('/debug/requisition/<int:req_id>')
@login_required
def debug_requisition(req_id):
    req = Requisition.query.get(req_id)
    if not req:
        return "Requisition not found"
    return f"""
    Claimed signature: {req.claimed_signature}<br>
    Manager signature: {req.manager_signature}<br>
    Countryhead signature: {req.countryhead_signature}<br>
    CEO signature: {req.ceo_signature}<br>
    Accounts status: {req.accounts_status}<br>
    Accounts batch id: {req.accounts_batch_id}
    """

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_redirect'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard_redirect'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard_redirect():
    # Accounts department gets Accounts dashboard (no new role created)
    if (current_user.department or '').strip().lower() == 'accounts':
        return redirect(url_for('dashboard_accounts'))

    if current_user.role == 'employee':
        return redirect(url_for('dashboard_employee'))
    elif current_user.role == 'manager':
        return redirect(url_for('dashboard_manager'))
    elif current_user.role == 'countryhead':
        return redirect(url_for('dashboard_countryhead'))
    elif current_user.role == 'ceo':
        return redirect(url_for('dashboard_ceo'))
    elif current_user.role == 'superadmin':
        return redirect(url_for('dashboard_superadmin'))
    else:
        flash('Unknown role.', 'danger')
        return redirect(url_for('logout'))

@app.route('/dashboard/employee')
@login_required
def dashboard_employee():
    if current_user.role != 'employee':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    requisitions = Requisition.query.filter_by(created_by_id=current_user.id).order_by(Requisition.created_at.desc()).all()
    return render_template_string(EMPLOYEE_DASHBOARD_TEMPLATE, user=current_user, requisitions=requisitions, format_datetime_pk=format_datetime_pk)

@app.route('/dashboard/manager')
@login_required
def dashboard_manager():
    if current_user.role != 'manager':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    pending_reqs = Requisition.query.filter_by(department=current_user.department, status='Pending Manager Approval').all()
    previous_reqs = Requisition.query.filter(
        Requisition.department == current_user.department,
        Requisition.status.in_(['Approved', 'Rejected'])
    ).order_by(Requisition.created_at.desc()).all()
    return render_template_string(MANAGER_DASHBOARD_TEMPLATE, user=current_user, pending_reqs=pending_reqs, previous_reqs=previous_reqs, format_datetime_pk=format_datetime_pk)

@app.route('/dashboard/countryhead')
@login_required
def dashboard_countryhead():
    if current_user.role != 'countryhead':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    pending_reqs = Requisition.query.filter_by(status='Pending Countryhead Approval', countryhead_approval_needed=True).all()
    previous_reqs = Requisition.query.filter(
        Requisition.countryhead_approval_needed == True,
        Requisition.status.in_(['Approved', 'Rejected'])
    ).order_by(Requisition.created_at.desc()).all()
    return render_template_string(COUNTRYHEAD_DASHBOARD_TEMPLATE, user=current_user, pending_reqs=pending_reqs, previous_reqs=previous_reqs, format_datetime_pk=format_datetime_pk)

@app.route('/dashboard/countryhead/previous')
@login_required
def countryhead_previous_requisitions():
    if current_user.role != 'countryhead':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    requisitions = Requisition.query.filter(
        Requisition.countryhead_approval_needed == True,
        Requisition.status.in_(['Approved', 'Rejected'])
    ).order_by(Requisition.created_at.desc()).all()
    return render_template_string(COUNTRYHEAD_PREVIOUS_REQUISITIONS_TEMPLATE, user=current_user, requisitions=requisitions, format_datetime_pk=format_datetime_pk)

@app.route('/dashboard/ceo')
@login_required
def dashboard_ceo():
    if current_user.role != 'ceo':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    pending_reqs = Requisition.query.filter_by(status='Pending CEO Approval').all()
    previous_reqs = Requisition.query.filter(
        Requisition.status.in_(['Approved', 'Rejected'])
    ).order_by(Requisition.created_at.desc()).all()
    return render_template_string(CEO_DASHBOARD_TEMPLATE, user=current_user, pending_reqs=pending_reqs, previous_reqs=previous_reqs, format_datetime_pk=format_datetime_pk)

@app.route('/dashboard/superadmin', methods=['GET', 'POST'])
@login_required
def dashboard_superadmin():
    if current_user.role != 'superadmin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create':
            username = request.form['username'].strip()
            password = request.form['password'].strip()
            role = request.form['role'].strip()
            department = request.form.get('department', '').strip()
            email = request.form.get('email', '').strip()

            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
            elif email and db.session.query(User.id).filter(func.lower(User.email) == email.lower()).first():
                flash('Email already exists.', 'danger')
            else:
                u = User(username=username, role=role, department=department or None, email=email or None)
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                flash('User created.', 'success')

        elif action == 'delete':
            uid = int(request.form['user_id'])
            if uid == current_user.id:
                flash('You cannot delete yourself.', 'danger')
            else:
                user = User.query.get(uid)
                if user:
                    db.session.delete(user)
                    db.session.commit()
                    flash('User deleted.', 'success')

        elif action == 'reset_password':
            uid = int(request.form['user_id'])
            new_password = request.form['new_password']
            user = User.query.get(uid)
            if user:
                user.set_password(new_password)
                db.session.commit()
                flash('Password reset.', 'success')

        elif action == 'rename':
            uid = int(request.form['user_id'])
            new_username = request.form['new_username'].strip()
            if User.query.filter_by(username=new_username).first():
                flash('Username already exists.', 'danger')
            else:
                user = User.query.get(uid)
                if user:
                    user.username = new_username
                    db.session.commit()
                    flash('Username updated.', 'success')

        elif action == 'update_email':
            uid = int(request.form['user_id'])
            new_email = request.form.get('new_email', '').strip()
            if new_email and db.session.query(User.id).filter(func.lower(User.email) == new_email.lower(), User.id != uid).first():
                flash('Email already in use.', 'danger')
            else:
                user = User.query.get(uid)
                if user:
                    user.email = new_email or None
                    db.session.commit()
                    flash('Email updated.', 'success')

        else:
            flash('Unknown action.', 'danger')

        return redirect(url_for('dashboard_superadmin'))

    users = User.query.order_by(User.id.asc()).all()
    return render_template_string(SUPERADMIN_DASHBOARD_TEMPLATE, user=current_user, users=users)

@app.route('/superadmin/requisitions')
@login_required
def superadmin_requisitions():
    if current_user.role != 'superadmin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    requisitions = Requisition.query.order_by(Requisition.created_at.desc()).all()
    return render_template_string(SUPERADMIN_REQUISITIONS_TEMPLATE, user=current_user, requisitions=requisitions)

@app.route('/requisitions/previous')
@login_required
def previous_requisitions():
    if current_user.role == 'ceo':
        requisitions = Requisition.query.filter(
            Requisition.status.in_(['Approved', 'Rejected'])
        ).order_by(Requisition.created_at.desc()).all()
    else:
        requisitions = Requisition.query.filter_by(created_by_id=current_user.id).order_by(Requisition.created_at.desc()).all()
    return render_template_string(PREVIOUS_REQUISITIONS_TEMPLATE, user=current_user, requisitions=requisitions, format_datetime_pk=format_datetime_pk)

@app.route('/requisition/create', methods=['GET', 'POST'])
@login_required
def create_requisition():
    if current_user.role not in ['employee', 'manager']:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    if request.method == 'POST':
        try:
            items = json.loads(request.form['items_json'])
            vendor_details = request.form.get('vendor_details', '')
            phone = request.form.get('phone', '')
            remarks = request.form.get('remarks', '')
            countryhead_approval_needed = request.form.get('countryhead_approval_needed') == 'on'
        except Exception:
            flash('Invalid form data.', 'danger')
            return redirect(url_for('create_requisition'))
        total_amount = 0
        for item in items:
            try:
                total_amount += float(item.get('total_price', 0))
            except:
                pass

        claimed_signature = get_signature_path(current_user)

        manager_signature = ''
        countryhead_signature = ''
        if current_user.role == 'employee':
            status = 'Pending Manager Approval'
        elif current_user.role == 'manager':
            if countryhead_approval_needed:
                status = 'Pending Countryhead Approval'
            else:
                status = 'Pending CEO Approval'

        req = Requisition(
            created_by_id=current_user.id,
            department=current_user.department,
            items_json=json.dumps(items),
            total_amount=total_amount,
            status=status,
            claimed_signature=claimed_signature,
            manager_signature=manager_signature,
            countryhead_signature=countryhead_signature,
            vendor_details=vendor_details,
            phone=phone,
            remarks=remarks,
            pending_date=datetime.now(PK_TZ),
            countryhead_approval_needed=countryhead_approval_needed
        )
        db.session.add(req)
        db.session.commit()
        flash('Requisition created.', 'success')
        return redirect(url_for('dashboard_redirect'))
    return render_template_string(CREATE_REQUISITION_TEMPLATE, user=current_user, claimed_signature_path=get_signature_path(current_user))

@app.route('/requisition/<int:req_id>', methods=['GET', 'POST'])
@login_required
def view_requisition(req_id):
    req = Requisition.query.get_or_404(req_id)

    # Allow Accounts department users to view any requisition (read-only)
    is_accounts = (current_user.department or '').strip().lower() == 'accounts'

    if not is_accounts:
        if current_user.role == 'employee' and req.created_by_id != current_user.id:
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard_redirect'))
        if current_user.role == 'manager':
            if req.created_by_id != current_user.id and req.department != current_user.department:
                flash('Access denied.', 'danger')
                return redirect(url_for('dashboard_redirect'))

    if request.method == 'POST':
        # Accounts can view but not approve/reject
        if is_accounts:
            flash('Accounts cannot approve/reject this requisition.', 'danger')
            return redirect(url_for('view_requisition', req_id=req_id))

        action = request.form['action']
        password = request.form['password']
        if not current_user.check_password(password):
            flash('Password incorrect.', 'danger')
            return redirect(url_for('view_requisition', req_id=req_id))

        signature_path = get_signature_path(current_user)

        if current_user.role == 'manager' and req.status == 'Pending Manager Approval' and req.department == current_user.department:
            if action == 'approve':
                if req.countryhead_approval_needed:
                    req.status = 'Pending Countryhead Approval'
                else:
                    req.status = 'Pending CEO Approval'
                req.manager_signature = signature_path
                req.pending_date = datetime.now(PK_TZ)
                req.decision_date = datetime.now(PK_TZ)
            elif action == 'reject':
                req.status = 'Rejected'
                req.manager_signature = signature_path
                req.decision_date = datetime.now(PK_TZ)
            db.session.commit()
            flash(f'Requisition {action}d.', 'success')
            return redirect(url_for('dashboard_manager'))

        elif current_user.role == 'countryhead' and req.status == 'Pending Countryhead Approval':
            if action == 'approve':
                req.status = 'Pending CEO Approval'
                req.countryhead_signature = signature_path
                req.pending_date = datetime.now(PK_TZ)
                req.decision_date = datetime.now(PK_TZ)
            elif action == 'reject':
                req.status = 'Rejected'
                req.countryhead_signature = signature_path
                req.decision_date = datetime.now(PK_TZ)
            db.session.commit()
            flash(f'Requisition {action}d.', 'success')
            return redirect(url_for('dashboard_countryhead'))

        elif current_user.role == 'ceo' and req.status == 'Pending CEO Approval':
            if action == 'approve':
                req.status = 'Approved'
                req.ceo_signature = signature_path
                req.decision_date = datetime.now(PK_TZ)
                # Send to Accounts pipeline
                req.accounts_status = 'New Requisition'
            elif action == 'reject':
                req.status = 'Rejected'
                req.ceo_signature = signature_path
                req.decision_date = datetime.now(PK_TZ)
            db.session.commit()
            flash(f'Requisition {action}d.', 'success')
            return redirect(url_for('dashboard_ceo'))

        else:
            flash('You cannot approve/reject this requisition.', 'danger')
            return redirect(url_for('dashboard_redirect'))

    items = json.loads(req.items_json)
    return render_template_string(VIEW_REQUISITION_TEMPLATE, user=current_user, req=req, items=items, enumerate=enumerate)

# ACCOUNTS: dashboard available to any user whose department is Accounts
@app.route('/dashboard/accounts', methods=['GET', 'POST'])
@login_required
def dashboard_accounts():
    if (current_user.department or '').strip().lower() != 'accounts':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'merge':
            req_ids = request.form.getlist('req_ids')
            if not req_ids:
                flash('Please select at least one requisition to merge.', 'warning')
                return redirect(url_for('dashboard_accounts'))
            try:
                ids = [int(x) for x in req_ids]
            except:
                flash('Invalid selection.', 'danger')
                return redirect(url_for('dashboard_accounts'))

            reqs = Requisition.query.filter(
                Requisition.id.in_(ids),
                Requisition.status == 'Approved',
                (Requisition.accounts_batch_id.is_(None))
            ).all()
            if not reqs:
                flash('No valid approved requisitions found in selection.', 'danger')
                return redirect(url_for('dashboard_accounts'))

            # Aggregate items
            items = []
            total_sum = 0.0
            for r in reqs:
                try:
                    r_items = json.loads(r.items_json)
                except Exception:
                    r_items = []
                for it in r_items:
                    price = float(it.get('price', 0) or 0)
                    qty = int(it.get('quantity', 0) or 0)
                    t = float(it.get('total_price', price * qty) or 0)
                    total_sum += t
                    items.append({
                        'req_id': r.id,
                        'department': r.department,
                        'date': it.get('date', ''),
                        'item_description': it.get('item_description', ''),
                        'price': price,
                        'quantity': qty,
                        'total_price': t
                    })

            batch = AccountsBatch(
                created_by_id=current_user.id,
                total_amount=total_sum,
                items_json=json.dumps(items),
                requisition_ids=json.dumps(ids),
                notes=''
            )
            db.session.add(batch)
            db.session.commit()

            # Mark requisitions as merged and link to batch
            for r in reqs:
                r.accounts_status = 'Merged'
                r.accounts_batch_id = batch.id
            db.session.commit()

            flash(f'Merged {len(reqs)} requisition(s) into batch #{batch.id}.', 'success')
            return redirect(url_for('view_accounts_batch', batch_id=batch.id))

    # Approved and not merged yet (show as "New Requisition")
    new_reqs = Requisition.query.filter(
        Requisition.status == 'Approved',
        (Requisition.accounts_batch_id.is_(None))
    ).order_by(Requisition.decision_date.desc().nullslast()).all()

    batches = AccountsBatch.query.order_by(AccountsBatch.created_at.desc()).all()
    return render_template_string(ACCOUNTS_DASHBOARD_TEMPLATE, user=current_user, new_reqs=new_reqs, batches=batches, format_datetime_pk=format_datetime_pk)

@app.route('/accounts/batch/<int:batch_id>')
@login_required
def view_accounts_batch(batch_id):
    # Allow Accounts dept, superadmin, CEO to view; others denied
    allowed = (current_user.role in ['superadmin', 'ceo']) or ((current_user.department or '').strip().lower() == 'accounts')
    if not allowed:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))

    batch = AccountsBatch.query.get_or_404(batch_id)
    try:
        items = json.loads(batch.items_json or '[]')
    except Exception:
        items = []
    try:
        req_ids = json.loads(batch.requisition_ids or '[]')
    except Exception:
        req_ids = []

    # Per-requisition totals (show each requisition whole price)
    req_summaries = []
    if req_ids:
        req_records = Requisition.query.filter(Requisition.id.in_(req_ids)).all()
        for r in req_records:
            req_summaries.append({
                'id': r.id,
                'department': r.department,
                'employee': r.created_by.username if r.created_by else '-',
                'total_amount': r.total_amount or 0.0
            })

    return render_template_string(
        ACCOUNTS_BATCH_VIEW_TEMPLATE,
        user=current_user,
        batch=batch,
        items=items,
        req_ids=req_ids,
        req_summaries=req_summaries,
        enumerate=enumerate,
        format_datetime_pk=format_datetime_pk  # ensure helper exists in Jinja
    )

# Templates (full content)

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Login - TOGETHER Requisition</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">

  <style>
    :root {
      --brand: #0ea5e9;
      --brand-dark: #0284c7;
      --brand-light: #e0f2fe;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: 'Poppins', system-ui, -apple-system, Segoe UI, Roboto, 'Helvetica Neue', Arial, 'Noto Sans', 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji', sans-serif;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(1200px 600px at 85% -20%, rgba(14,165,233,0.15), transparent 60%),
                  radial-gradient(1000px 500px at -10% 120%, rgba(99,102,241,0.12), transparent 60%),
                  linear-gradient(135deg, #f8fbff 0%, #f2fbff 60%, #eef7ff 100%);
    }

    .auth-wrap {
      width: min(980px, 96vw);
      display: grid;
      grid-template-columns: 1.15fr 1fr;
      gap: 0;
      border-radius: 18px;
      overflow: hidden;
      box-shadow: 0 20px 60px rgba(2,132,199,0.18);
      background: #fff;
      border: 1px solid rgba(2,132,199,0.08);
    }

    .brand-panel {
      background: linear-gradient(135deg, var(--brand) 0%, #38bdf8 60%, #22d3ee 100%);
      color: #fff;
      padding: 40px 34px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: relative;
      overflow: hidden;
    }
    .brand-panel::before,
    .brand-panel::after {
      content: '';
      position: absolute;
      border-radius: 50%;
      filter: blur(40px);
      opacity: 0.25;
      pointer-events: none;
    }
    .brand-panel::before {
      width: 380px; height: 380px;
      background: #ffffff;
      top: -90px; right: -120px;
    }
    .brand-panel::after {
      width: 300px; height: 300px;
      background: #0ea5e9;
      bottom: -80px; left: -80px;
      opacity: 0.18;
    }
    .brand-head {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .brand-logo {
      background: rgba(255,255,255,0.18);
      backdrop-filter: blur(6px);
      border-radius: 12px;
      padding: 10px 14px;
      display: inline-flex;
      align-items: center;
      box-shadow: inset 0 0 0 1px rgba(255,255,255,0.2);
    }
    .brand-logo img {
      height: 56px;
      width: auto;
      display: block;
    }
    .brand-title h1 {
      font-weight: 700;
      margin: 0;
      letter-spacing: 0.5px;
      font-size: 28px;
    }
    .brand-title small {
      display: block;
      opacity: 0.9;
      margin-top: 4px;
      font-weight: 500;
    }
    .brand-bullets {
      margin-top: 28px;
      display: grid;
      gap: 10px;
      font-size: 14px;
    }
    .brand-bullets .item {
      display: flex;
      align-items: center;
      gap: 10px;
      opacity: 0.95;
    }
    .brand-bullets .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: #fff;
      box-shadow: 0 0 0 3px rgba(255,255,255,0.25);
    }
    .brand-footer {
      font-size: 12px;
      opacity: 0.85;
    }

    .form-panel {
      padding: 40px 34px;
      background: #ffffff;
    }
    .form-card {
      background: #ffffff;
      border: 1px solid rgba(2,132,199,0.08);
      border-radius: 14px;
      padding: 26px 24px;
      box-shadow: 0 10px 30px rgba(2,132,199,0.06);
    }
    .form-card h2 {
      font-weight: 700;
      font-size: 24px;
      margin: 0 0 8px 0;
      letter-spacing: 0.2px;
      color: #0f172a;
    }
    .subtitle {
      color: #334155;
      opacity: 0.85;
      font-size: 14px;
      margin-bottom: 18px;
    }

    .form-label {
      font-weight: 600;
      color: #0f172a;
    }
    .form-control {
      border-radius: 10px;
      padding: 10px 12px;
      border: 1px solid rgba(2,132,199,0.24);
    }
    .form-control:focus {
      border-color: var(--brand);
      box-shadow: 0 0 0 .2rem rgba(14,165,233,.15);
    }
    .btn-brand {
      background: var(--brand);
      border: none;
      color: #fff;
      border-radius: 10px;
      padding: 10px 14px;
      font-weight: 600;
      transition: transform .08s ease, box-shadow .2s ease, background .2s ease;
      box-shadow: 0 8px 18px rgba(14,165,233,0.25);
    }
    .btn-brand:hover { background: var(--brand-dark); transform: translateY(-1px); }
    .btn-brand:active { transform: translateY(0); }

    .alerts { margin-bottom: 12px; }
    .alert {
      border-radius: 10px;
      padding: 10px 12px;
    }

    @media (max-width: 900px) {
      .auth-wrap { grid-template-columns: 1fr; width: min(560px, 94vw); }
      .brand-panel { padding: 26px 24px; }
      .form-panel { padding: 26px 24px; }
      .brand-title h1 { font-size: 24px; }
      .brand-logo img { height: 48px; }
    }
  </style>
</head>
<body>
  <div class="auth-wrap">
    <div class="brand-panel">
      <div>
        <div class="brand-head">
          <span class="brand-logo">
            <img src="{{ url_for('static', filename='logo.png') }}" alt="TOGETHER Logo">
          </span>
          <div class="brand-title">
            <h1>TOGETHER</h1>
            <small>Requisition System</small>
          </div>
        </div>

        <div class="brand-bullets">
          <div class="item"><span class="dot"></span> Secure approvals workflow</div>
          <div class="item"><span class="dot"></span> Fast, simple, and reliable</div>
          <div class="item"><span class="dot"></span> Designed for your team</div>
        </div>
      </div>
      <div class="brand-footer">
        © <span id="year"></span> TOGETHER. All rights reserved.
      </div>
    </div>

    <div class="form-panel">
      <div class="form-card">
        <h2>Welcome back</h2>
        <div class="subtitle">Sign in to continue</div>

        <div class="alerts">
          {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
              {% for category, message in messages %}
                <div class="alert alert-{{ category }}">{{ message }}</div>
              {% endfor %}
            {% endif %}
          {% endwith %}
        </div>

        <form method="POST" autocomplete="off" novalidate>
          <div class="mb-3">
            <label for="username" class="form-label">Username</label>
            <input type="text" class="form-control" id="username" name="username" required autofocus>
          </div>
          <div class="mb-3">
            <label for="password" class="form-label">Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
          </div>
          <button type="submit" class="btn btn-brand w-100">Login</button>
        </form>
      </div>
      <div class="text-center mt-3" style="color:#475569; font-size:12px;">
        Need help? Contact Admin
      </div>
    </div>
  </div>

  <script>
    (function(){ var el = document.getElementById('year'); if (el) el.textContent = new Date().getFullYear(); })();
  </script>
</body>
</html>
"""

CREATE_REQUISITION_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Create Requisition - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .signatures-container {
      display: flex;
      gap: 20px;
      margin-top: 20px;
      margin-bottom: 20px;
    }
    .signature-block {
      flex: 1;
      border: 1px solid #ccc;
      padding: 10px;
      min-height: 100px;
      position: relative;
      text-align: center;
    }
    .signature-label {
      font-weight: bold;
      margin-bottom: 8px;
      display: block;
    }
    .signature-img {
      max-height: 100px;
      max-width: 100%;
      object-fit: contain;
    }
    .total-amount-container {
      display: flex;
      align-items: center;
      margin-top: 15px;
      margin-bottom: 15px;
    }
    .total-amount-container label {
      font-weight: bold;
      margin-right: 10px;
      white-space: nowrap;
    }
    .total-amount-container input {
      max-width: 150px;
    }
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }

    .print-only { display: none !important; }
    .hide-on-print { }

    @media print {
      @page { margin: 12mm; }
      * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      body { font-size: 12px; }
      nav.navbar { display: none !important; }
      .print-only { display: block !important; }
      h1, h2, h3, .form-label, label { font-size: 13px !important; }
      .table, .form-control, .btn, .badge, .navbar-text, .signature-label { font-size: 12px !important; }
      .hide-on-print { display: none !important; }
      #itemsTable th:last-child, #itemsTable td:last-child { display: none !important; }
      #countryhead_check_container { display: none !important; }
      .vm-row { display: flex; gap: 16px; }
      .vm-row .vm-col { flex: 1; }
      .page-title { display: none !important; }
      .print-header { text-align: center; margin-bottom: 8px; }
      .print-header img { height: 40px; margin-bottom: 4px; }
      .print-title { font-weight: 700; font-size: 16px; letter-spacing: 0.3px; }
      input, textarea, select { border: 1px solid #aaa !important; box-shadow: none !important; }
      #remarks { height: 60px !important; }
      .print-footer {
        position: fixed;
        bottom: 6mm;
        left: 0; right: 0;
        text-align: center;
        font-size: 11px;
        color: #555;
      }
    }
  </style>
  <script>
    function addItemRow() {
      const tbody = document.getElementById('itemsBody');
      const row = tbody.insertRow();
      row.innerHTML = `
        <td><input type="date" name="date" class="form-control" required></td>
        <td><input type="text" name="item_description" class="form-control" required></td>
        <td><input type="number" name="price" class="form-control" step="0.01" min="0" required oninput="updateTotal(this)"></td>
        <td><input type="number" name="quantity" class="form-control" min="1" required oninput="updateTotal(this)"></td>
        <td><input type="number" name="total_price" class="form-control" step="0.01" min="0" readonly></td>
        <td><button type="button" class="btn btn-danger btn-sm" onclick="removeItemRow(this)">Remove</button></td>
      `;
    }
    function removeItemRow(btn) {
      const row = btn.parentNode.parentNode;
      row.parentNode.removeChild(row);
      updateGrandTotal();
    }
    function updateTotal(input) {
      const row = input.parentNode.parentNode;
      const price = parseFloat(row.querySelector('input[name="price"]').value) || 0;
      const qty = parseInt(row.querySelector('input[name="quantity"]').value) || 0;
      const total = price * qty;
      row.querySelector('input[name="total_price"]').value = total.toFixed(2);
      updateGrandTotal();
    }
    function updateGrandTotal() {
      let sum = 0;
      document.querySelectorAll('input[name="total_price"]').forEach(input => {
        sum += parseFloat(input.value) || 0;
      });
      document.getElementById('grandTotal').value = sum.toFixed(2);
    }
    function submitForm() {
      const items = [];
      const tbody = document.getElementById('itemsBody');
      for (let row of tbody.rows) {
        items.push({
          date: row.querySelector('input[name="date"]').value,
          item_description: row.querySelector('input[name="item_description"]').value,
          price: parseFloat(row.querySelector('input[name="price"]').value) || 0,
          quantity: parseInt(row.querySelector('input[name="quantity"]').value) || 0,
          total_price: parseFloat(row.querySelector('input[name="total_price"]').value) || 0
        });
      }
      document.getElementById('items_json').value = JSON.stringify(items);
      return true;
    }

    (function(){
      var originalTitle = document.title;
      window.onbeforeprint = function(){ document.title = ''; };
      window.onafterprint  = function(){ document.title = originalTitle; };
    })();

    window.addEventListener('DOMContentLoaded', function(){
      addItemRow();
    });
  </script>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_redirect') }}">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} ({{ user.role.capitalize() }})</span>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>

<div class="print-only print-header">
  <img src="{{ url_for('static', filename='logo.png') }}" alt="TOGETHER Logo">
  <div class="print-title">{{ user.department or '-' }} - Requisition</div>
</div>

<div class="container mt-4" style="max-width: 900px;">
  <h3 class="page-title">Create Requisition</h3>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="POST" onsubmit="return submitForm()">
    <table class="table table-bordered" id="itemsTable">
      <thead class="table-light">
        <tr>
          <th>Date</th>
          <th>Item Description</th>
          <th>Price</th>
          <th>Quantity</th>
          <th>Total Price</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="itemsBody"></tbody>
    </table>
    <button type="button" id="addRowBtn" class="btn btn-secondary mb-3 hide-on-print" onclick="addItemRow()">+ Add More Row</button>

    {% if user.role == 'manager' %}
    <div class="form-check mb-3" id="countryhead_check_container">
      <input class="form-check-input" type="checkbox" id="countryhead_approval_needed" name="countryhead_approval_needed">
      <label class="form-check-label" for="countryhead_approval_needed">
        Countryhead approval needed before CEO approval
      </label>
    </div>
    {% endif %}

    <div class="signatures-container">
      <div class="signature-block">
        <label class="signature-label">Claimed By Signature</label>
        {% if claimed_signature_path %}
          <img src="{{ url_for('static', filename=claimed_signature_path) }}" alt="Claimed Signature" class="signature-img">
        {% endif %}
      </div>
      <div class="signature-block">
        <label class="signature-label" id="manager_signature_label">Verify/Manager Signature</label>
      </div>
      <div class="signature-block">
        <label class="signature-label">CEO Signature</label>
      </div>
    </div>

    <div class="vm-row">
      <div class="vm-col">
        <div class="mb-3">
          <label for="vendor_details" class="form-label">Vendor details</label>
          <input type="text" class="form-control" id="vendor_details" name="vendor_details" placeholder="e.g. Mr. Abdullah - Shop no 49A, Hafeez Center, Lahore">
        </div>
      </div>
      <div class="vm-col">
        <div class="mb-3">
          <label for="phone" class="form-label">Phone</label>
          <input type="text" class="form-control" id="phone" name="phone" placeholder="0302-XXXXXXX">
        </div>
      </div>
    </div>

    <div class="mb-3">
      <label for="remarks" class="form-label">Remarks</label>
      <textarea class="form-control" id="remarks" name="remarks" rows="3"></textarea>
    </div>

    <div class="total-amount-container">
      <label for="grandTotal">Total Amount:</label>
      <input type="text" id="grandTotal" name="total_amount" class="form-control" readonly>
    </div>

    <input type="hidden" id="items_json" name="items_json">
    <button type="submit" id="submitBtn" class="btn btn-primary hide-on-print">Submit Requisition</button>
    <button type="button" class="btn btn-secondary float-end hide-on-print" onclick="window.print()">Print / Save as PDF</button>

    <div class="print-only print-footer">
      Logged in as {{ user.username }} ({{ user.role.capitalize() }})
    </div>
  </form>
</div>

<script>
  (function(){
    function updateSigLabel() {
      var checkbox = document.getElementById('countryhead_approval_needed');
      var labelEl  = document.getElementById('manager_signature_label');
      if (!labelEl) return;
      labelEl.textContent = (checkbox && checkbox.checked)
        ? 'Countryhead Signature'
        : 'Verify/Manager Signature';
    }

    document.addEventListener('DOMContentLoaded', function(){
      updateSigLabel();
      var checkbox = document.getElementById('countryhead_approval_needed');
      if (checkbox) {
        checkbox.addEventListener('change', updateSigLabel);
        checkbox.addEventListener('input',  updateSigLabel);
      }
      window.addEventListener('beforeprint', updateSigLabel);
      if (window.matchMedia) {
        var mq = window.matchMedia('print');
        if (mq && mq.addListener) mq.addListener(updateSigLabel);
      }
    });
  })();
</script>
</body>
</html>
"""

EMPLOYEE_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Employee Dashboard - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_employee') }}">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} (Employee)</span>
      <a href="{{ url_for('create_requisition') }}" class="btn btn-success me-2">Create Requisition</a>
      <a href="{{ url_for('previous_requisitions') }}" class="btn btn-info me-2">Previous Requisitions</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Your Requisitions</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% if requisitions %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>ID</th>
        <th>Department</th>
        <th>Total Amount</th>
        <th>Status</th>
        <th>Created At</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in requisitions %}
      <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.department }}</td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td>
          {% if r.status == 'Approved' %}
            <span class="badge bg-success">{{ r.status }}</span>
          {% elif r.status == 'Rejected' %}
            <span class="badge bg-danger">{{ r.status }}</span>
          {% else %}
            <span class="badge bg-warning text-dark">{{ r.status }}</span>
          {% endif %}
        </td>
        <td>{{ r.created_at.strftime('%d/%m/%Y %H:%M') }}</td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No requisitions found.</p>
  {% endif %}
</div>
</body>
</html>
"""

MANAGER_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Manager Dashboard - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_manager') }}">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} (Manager)</span>
      <a href="{{ url_for('create_requisition') }}" class="btn btn-success me-2">Create Requisition</a>
      <a href="{{ url_for('previous_requisitions') }}" class="btn btn-info me-2">Previous Requisitions</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Requisitions Pending Your Approval (Department: {{ user.department }})</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% if pending_reqs %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>Department</th>
        <th>Employee</th>
        <th>Total Amount</th>
        <th>Status</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in pending_reqs %}
      <tr>
        <td>{{ r.department }}</td>
        <td>{{ r.created_by.username }}</td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td><span class="badge bg-warning text-dark">{{ r.status }}</span></td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No requisitions pending approval.</p>
  {% endif %}

  <h3>Previous Requisitions (Approved/Rejected)</h3>
  {% if previous_reqs %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>Department</th>
        <th>Employee</th>
        <th>Status</th>
        <th>Total Amount</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in previous_reqs %}
      <tr>
        <td>{{ r.department }}</td>
        <td>{{ r.created_by.username }}</td>
        <td>
          {% if r.status == 'Approved' %}
            <span class="badge bg-success">{{ r.status }}</span>
          {% else %}
            <span class="badge bg-danger">{{ r.status }}</span>
          {% endif %}
        </td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No previous requisitions found.</p>
  {% endif %}
</div>
</body>
</html>
"""

COUNTRYHEAD_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Countryhead Dashboard - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .badge { font-size: 0.9em; }
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_countryhead') }}">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} (Countryhead)</span>
      <a href="{{ url_for('countryhead_previous_requisitions') }}" class="btn btn-info me-2">Previous Requisitions</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Requisitions Pending Your Approval</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% if pending_reqs %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>Department</th>
        <th>Employee</th>
        <th>Total Amount</th>
        <th>Status</th>
        <th>Date</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in pending_reqs %}
      <tr>
        <td>{{ r.department }}</td>
        <td>{{ r.created_by.username }}</td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td><span class="badge bg-info text-dark">{{ r.status }}</span></td>
        <td>
          <div><strong>Pending:</strong> {{ r.pending_date.strftime('%d/%m/%Y %H:%M') if r.pending_date else '-' }}</div>
          <div><strong>Decision:</strong> {{ r.decision_date.strftime('%d/%m/%Y %H:%M') if r.decision_date else '-' }}</div>
        </td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No requisitions pending approval.</p>
  {% endif %}
</div>
</body>
</html>
"""

COUNTRYHEAD_PREVIOUS_REQUISITIONS_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Countryhead Previous Requisitions - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_countryhead') }}">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} (Countryhead)</span>
      <a href="{{ url_for('dashboard_countryhead') }}" class="btn btn-secondary me-2">Dashboard</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Previous Requisitions (Approved/Rejected)</h3>
  {% if requisitions %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>ID</th>
        <th>Department</th>
        <th>Employee</th>
        <th>Status</th>
        <th>Total Amount</th>
        <th>Created At</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in requisitions %}
      <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.department }}</td>
        <td>{{ r.created_by.username }}</td>
        <td>
          {% if r.status == 'Approved' %}
            <span class="badge bg-success">{{ r.status }}</span>
          {% else %}
            <span class="badge bg-danger">{{ r.status }}</span>
          {% endif %}
        </td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td>{{ format_datetime_pk(r.created_at) }}</td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No previous requisitions found.</p>
  {% endif %}
</div>
</body>
</html>
"""

CEO_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>CEO Dashboard - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .badge { font-size: 0.9em; }
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_ceo') }}">Together Requisition</a>
    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>
    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} (CEO)</span>
      <a href="{{ url_for('previous_requisitions') }}" class="btn btn-info me-2">Previous Requisitions</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Requisitions Pending Your Approval</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% if pending_reqs %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>Department</th>
        <th>Employee</th>
        <th>Total Amount</th>
        <th>Status</th>
        <th>Date</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in pending_reqs %}
      <tr>
        <td>{{ r.department }}</td>
        <td>{{ r.created_by.username }}</td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td><span class="badge bg-info text-dark">{{ r.status }}</span></td>
        <td>
          <div><strong>Pending:</strong> {{ r.pending_date.strftime('%d/%m/%Y %H:%M') if r.pending_date else '-' }}</div>
          <div><strong>Decision:</strong> {{ r.decision_date.strftime('%d/%m/%Y %H:%M') if r.decision_date else '-' }}</div>
        </td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No requisitions pending approval.</p>
  {% endif %}

  <h3>Previous Requisitions (Approved/Rejected)</h3>
  {% if previous_reqs %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>Department</th>
        <th>Employee</th>
        <th>Status</th>
        <th>Total Amount</th>
        <th>Date</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in previous_reqs %}
      <tr>
        <td>{{ r.department }}</td>
        <td>{{ r.created_by.username }}</td>
        <td>
          {% if r.status == 'Approved' %}
            <span class="badge bg-success">{{ r.status }}</span>
          {% else %}
            <span class="badge bg-danger">{{ r.status }}</span>
          {% endif %}
        </td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td>
          <div><strong>Pending:</strong> {{ r.pending_date.strftime('%d/%m/%Y %H:%M') if r.pending_date else '-' }}</div>
          <div><strong>Decision:</strong> {{ r.decision_date.strftime('%d/%m/%Y %H:%M') if r.decision_date else '-' }}</div>
        </td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No previous requisitions found.</p>
  {% endif %}
</div>
</body>
</html>
"""

SUPERADMIN_REQUISITIONS_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>All Requisitions - Superadmin - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_superadmin') }}">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} (Superadmin)</span>
      <a href="{{ url_for('dashboard_superadmin') }}" class="btn btn-secondary me-2">Dashboard</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>All Requisitions</h3>
  {% if requisitions %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>ID</th>
        <th>Created By</th>
        <th>Department</th>
        <th>Total Amount</th>
        <th>Status</th>
        <th>Created At</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in requisitions %}
      <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.created_by.username }}</td>
        <td>{{ r.department }}</td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td>
          {% if r.status == 'Approved' %}
            <span class="badge bg-success">{{ r.status }}</span>
          {% elif r.status == 'Rejected' %}
            <span class="badge bg-danger">{{ r.status }}</span>
          {% else %}
            <span class="badge bg-warning text-dark">{{ r.status }}</span>
          {% endif %}
        </td>
        <td>{{ r.created_at.strftime('%d/%m/%Y %H:%M') }}</td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No requisitions found.</p>
  {% endif %}
</div>
</body>
</html>
"""

SUPERADMIN_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Superadmin Dashboard - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .form-inline > * { margin-right: 10px; }
    .modal-backdrop.show { opacity: 0.5; }
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} (Superadmin)</span>
      <a href="{{ url_for('superadmin_requisitions') }}" class="btn btn-info me-2">View All Requisitions</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>User Management</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="POST" class="mb-4">
    <input type="hidden" name="action" value="create">
    <div class="row g-2 align-items-center">
      <div class="col-auto">
        <input type="text" name="username" placeholder="Username" required class="form-control" autocomplete="off">
      </div>
      <div class="col-auto">
        <input type="password" name="password" placeholder="Password" required class="form-control" autocomplete="new-password">
      </div>
      <div class="col-auto">
        <input type="email" name="email" placeholder="Email (optional)" class="form-control" autocomplete="email">
      </div>
      <div class="col-auto">
        <select name="role" class="form-select" required>
          <option value="" disabled selected>Select Role</option>
          <option value="employee">Employee</option>
          <option value="manager">Manager</option>
          <option value="countryhead">Countryhead</option>
          <option value="ceo">CEO</option>
          <option value="superadmin">Superadmin</option>
        </select>
      </div>
      <div class="col-auto">
        <select name="department" class="form-select">
          <option value="" selected>Department (optional)</option>
          <option value="IT">IT</option>
          <option value="Admin">Admin</option>
          <option value="HR">HR</option>
          <option value="Accounts">Accounts</option>
          <option value="Sales">Sales</option>
          <option value="Development">Development</option>
          <option value="Designing">Designing</option>
        </select>
      </div>
      <div class="col-auto">
        <button type="submit" class="btn btn-primary">Create User</button>
      </div>
    </div>
  </form>

  <h4>Existing Users</h4>
  <table class="table table-bordered table-hover align-middle">
    <thead class="table-light">
      <tr>
        <th>ID</th>
        <th>Username</th>
        <th>Email</th>
        <th>Role</th>
        <th>Department</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {% for u in users %}
      <tr>
        <td>{{ u.id }}</td>
        <td>{{ u.username }}</td>
        <td>{{ u.email or '-' }}</td>
        <td>{{ u.role }}</td>
        <td>{{ u.department or '-' }}</td>
        <td>
          <form method="POST" style="display:inline-block;" onsubmit="return confirm('Delete user {{ u.username }}?');">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="user_id" value="{{ u.id }}">
            <button type="submit" class="btn btn-danger btn-sm">Delete</button>
          </form>
          <button class="btn btn-secondary btn-sm" onclick="showResetPassword({{ u.id }}, '{{ u.username }}')">Reset Password</button>
          <button class="btn btn-info btn-sm" onclick="showRenameUser({{ u.id }}, '{{ u.username }}')">Rename</button>
          <button class="btn btn-warning btn-sm" onclick="showChangeEmail({{ u.id }}, {{ (u.email or '')|tojson }})">Change Email</button>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div class="modal" tabindex="-1" id="resetPasswordModal">
  <div class="modal-dialog">
    <div class="modal-content">
      <form method="POST" id="resetPasswordForm">
        <div class="modal-header">
          <h5 class="modal-title">Reset Password</h5>
          <button type="button" class="btn-close" aria-label="Close" onclick="hideResetPassword()"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="action" value="reset_password">
          <input type="hidden" name="user_id" id="resetUserId">
          <div class="mb-3">
            <label for="new_password" class="form-label">New Password</label>
            <input type="password" name="new_password" id="new_password" class="form-control" required autocomplete="new-password">
          </div>
        </div>
        <div class="modal-footer">
          <button type="submit" class="btn btn-primary">Reset</button>
          <button type="button" class="btn btn-secondary" onclick="hideResetPassword()">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</div>

<div class="modal" tabindex="-1" id="renameUserModal">
  <div class="modal-dialog">
    <div class="modal-content">
      <form method="POST" id="renameUserForm">
        <div class="modal-header">
          <h5 class="modal-title">Rename User</h5>
          <button type="button" class="btn-close" aria-label="Close" onclick="hideRenameUser()"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="action" value="rename">
          <input type="hidden" name="user_id" id="renameUserId">
          <div class="mb-3">
            <label for="new_username" class="form-label">New Username</label>
            <input type="text" name="new_username" id="new_username" class="form-control" required autocomplete="off">
          </div>
        </div>
        <div class="modal-footer">
          <button type="submit" class="btn btn-primary">Rename</button>
          <button type="button" class="btn btn-secondary" onclick="hideRenameUser()">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</div>

<div class="modal" tabindex="-1" id="changeEmailModal">
  <div class="modal-dialog">
    <div class="modal-content">
      <form method="POST" id="changeEmailForm">
        <div class="modal-header">
          <h5 class="modal-title">Change Email</h5>
          <button type="button" class="btn-close" aria-label="Close" onclick="hideChangeEmail()"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="action" value="update_email">
          <input type="hidden" name="user_id" id="changeEmailUserId">
          <div class="mb-3">
            <label for="new_email" class="form-label">New Email</label>
            <input type="email" name="new_email" id="new_email" class="form-control" placeholder="user@example.com">
            <div class="form-text">Leave blank to clear the email.</div>
          </div>
        </div>
        <div class="modal-footer">
          <button type="submit" class="btn btn-primary">Save</button>
          <button type="button" class="btn btn-secondary" onclick="hideChangeEmail()">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</div>

<script>
  function showResetPassword(userId, username) {
    document.getElementById('resetUserId').value = userId;
    document.getElementById('new_password').value = '';
    var modal = new bootstrap.Modal(document.getElementById('resetPasswordModal'));
    modal.show();
  }
  function hideResetPassword() {
    var modal = bootstrap.Modal.getInstance(document.getElementById('resetPasswordModal'));
    if(modal) modal.hide();
  }
  function showRenameUser(userId, username) {
    document.getElementById('renameUserId').value = userId;
    document.getElementById('new_username').value = username;
    var modal = new bootstrap.Modal(document.getElementById('renameUserModal'));
    modal.show();
  }
  function hideRenameUser() {
    var modal = bootstrap.Modal.getInstance(document.getElementById('renameUserModal'));
    if(modal) modal.hide();
  }
  function showChangeEmail(userId, email) {
    document.getElementById('changeEmailUserId').value = userId;
    document.getElementById('new_email').value = email || '';
    var modal = new bootstrap.Modal(document.getElementById('changeEmailModal'));
    modal.show();
  }
  function hideChangeEmail() {
    var modal = bootstrap.Modal.getInstance(document.getElementById('changeEmailModal'));
    if(modal) modal.hide();
  }
</script>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

PREVIOUS_REQUISITIONS_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Previous Requisitions - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_redirect') }}">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} ({{ user.role.capitalize() }})</span>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Previous Requisitions (Approved/Rejected)</h3>
  {% if requisitions %}
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>ID</th>
        <th>Department</th>
        <th>Total Amount</th>
        <th>Status</th>
        <th>Created At</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for r in requisitions %}
      <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.department }}</td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
        <td>
          {% if r.status == 'Approved' %}
            <span class="badge bg-success">{{ r.status }}</span>
          {% elif r.status == 'Rejected' %}
            <span class="badge bg-danger">{{ r.status }}</span>
          {% else %}
            <span class="badge bg-warning text-dark">{{ r.status }}</span>
          {% endif %}
        </td>
        <td>{{ format_datetime_pk(r.created_at) }}</td>
        <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-primary btn-sm">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No previous requisitions found.</p>
  {% endif %}
</div>
</body>
</html>
"""

VIEW_REQUISITION_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>View Requisition - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .compact { font-size: 0.95rem; }
    .compact .table { font-size: 0.92rem; }
    .compact .table th, .compact .table td { padding: .45rem; }
    .compact .form-control { padding: 6px 10px; font-size: 0.92rem; }

    .department-row {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
    }
    .department-row label { margin-bottom: 0; white-space: nowrap; }
    .department-row .dept-input { max-width: 320px; }

    .signatures-container {
      display: flex;
      gap: 16px;
      margin-top: 16px;
      margin-bottom: 16px;
    }
    .signature-block {
      flex: 1;
      border: 1px solid #ccc;
      padding: 8px;
      min-height: 70px;
      position: relative;
      text-align: center;
    }
    .signature-label {
      font-weight: 600;
      margin-bottom: 6px;
      display: block;
      font-size: 0.95rem;
    }
    .signature-img {
      max-height: 60px;
      max-width: 100%;
      object-fit: contain;
    }

    .vm-row { display: flex; gap: 12px; }
    .vm-row .vm-col { flex: 1; }
    #remarks { height: 70px; }

    .table thead th, .table tbody td {
      vertical-align: middle;
      text-align: center;
    }
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }

    .print-only { display: none !important; }
    .hide-on-print { }
    .createdby-row { display: none; }

    @media (max-width: 576px) {
      .department-row { flex-direction: column; align-items: stretch; }
      .department-row .dept-input { max-width: 100%; }
      .vm-row { flex-direction: column; }
    }

    @media print {
      @page { margin: 12mm; }
      * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      body { font-size: 12px; }

      nav.navbar { display: none !important; }
      .print-only { display: block !important; }

      h1, h2, h3, .form-label, label { font-size: 13px !important; }
      .table, .form-control, .btn, .badge, .navbar-text, .signature-label { font-size: 12px !important; }

      .hide-on-print { display: none !important; }
      .approval-form { display: none !important; }

      .vm-row { display: flex; gap: 16px; }
      .vm-row .vm-col { flex: 1; }

      .screen-header { display: none !important; }
      .print-header { text-align: center; margin-bottom: 8px; }
      .print-header img { height: 52px; margin-bottom: 6px; }
      .print-title { font-weight: 700; font-size: 16px; letter-spacing: 0.3px; }

      #remarks { height: 60px !important; }

      .department-row { display: none !important; }
      .createdby-row { display: block !important; margin-bottom: 8px; }
      .createdby-inline {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 13px;
      }
      .createdby-inline b { white-space: nowrap; }

      .table { border-collapse: collapse !important; }
      .table, .table th, .table td {
        border: 1.2px solid #000 !important;
      }
      .table thead th {
        background: #e9ecef !important;
        color: #111827 !important;
      }
      .signature-block {
        border: 1.2px solid #000 !important;
        min-height: 80px !important;
        padding: 8px !important;
      }
      .signature-img { max-height: 70px !important; }
      .form-control {
        border: 1.2px solid #000 !important;
        box-shadow: none !important;
      }
      div[style*="background-color:#d6e6db"] {
        border: 1.2px solid #000 !important;
      }

      .print-footer {
        position: fixed;
        bottom: 6mm;
        left: 0; right: 0;
        text-align: center;
        font-size: 11px;
        color: #555;
      }
    }
  </style>
  <script>
    (function(){
      var originalTitle = document.title;
      window.onbeforeprint = function(){ document.title = ''; };
      window.onafterprint  = function(){ document.title = originalTitle; };
    })();
  </script>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">Together Requisition</a>

    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>

    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} ({{ user.role.capitalize() }})</span>
      <a href="{{ url_for('dashboard_redirect') }}" class="btn btn-outline-light">Dashboard</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light ms-2">Logout</a>
    </div>
  </div>
</nav>

<div class="print-only print-header">
  <img src="{{ url_for('static', filename='logo.png') }}" alt="TOGETHER Logo">
  <div class="print-title">{{ req.department }} - Requisition</div>
</div>

<div class="container mt-4 compact" style="max-width: 1000px;">
  <h4 class="mb-3 text-white bg-info p-2 text-center screen-header" style="font-size:1.1rem;">TOGETHER-REQUISITION</h4>

  <div class="department-row">
    <label><b>Department:</b></label>
    <input type="text" class="form-control dept-input" value="{{ req.department }}" readonly>
  </div>

  <div class="createdby-row print-only">
    <div class="createdby-inline">
      <b>Created By:</b>
      <span>{{ req.created_by.username }}</span>
    </div>
  </div>

  <table class="table table-bordered" id="itemsTable">
    <thead class="table-light">
      <tr>
        <th>Sr.No</th>
        <th>Date</th>
        <th>Item Description</th>
        <th>Price</th>
        <th>Quantity</th>
        <th>Total Price</th>
      </tr>
    </thead>
    <tbody>
      {% for idx, item in enumerate(items, 1) %}
      <tr>
        <td>{{ idx }}</td>
        <td>{{ item.date }}</td>
        <td style="text-align:left;">{{ item.item_description }}</td>
        <td>{{ "%.2f"|format(item.price) }}</td>
        <td>{{ item.quantity }}</td>
        <td>{{ "%.2f"|format(item.total_price) }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="d-flex justify-content-end align-items-center mb-3" style="background-color:#d6e6db; padding:8px;">
    <b class="me-3">TOTAL</b>
    <input type="number" class="form-control" style="max-width: 180px;" value="{{ "%.2f"|format(req.total_amount) }}" readonly>
  </div>

  <div class="signatures-container">
    <div class="signature-block">
      <label class="signature-label">Claimed By Signature</label>
      {% if req.claimed_signature %}
        <img src="{{ url_for('static', filename=req.claimed_signature) }}" alt="Claimed Signature" class="signature-img">
      {% endif %}
    </div>
    <div class="signature-block">
      <label class="signature-label">
        {% if req.countryhead_approval_needed %}
          Countryhead Signature
        {% else %}
          Manager Signature
        {% endif %}
      </label>
      {% if req.countryhead_approval_needed %}
        {% if req.countryhead_signature %}
          <img src="{{ url_for('static', filename=req.countryhead_signature) }}" alt="Countryhead Signature" class="signature-img">
        {% endif %}
      {% else %}
        {% if req.manager_signature %}
          <img src="{{ url_for('static', filename=req.manager_signature) }}" alt="Manager Signature" class="signature-img">
        {% endif %}
      {% endif %}
    </div>
    <div class="signature-block">
      <label class="signature-label">CEO Signature</label>
      {% if req.ceo_signature %}
        <img src="{{ url_for('static', filename=req.ceo_signature) }}" alt="CEO Signature" class="signature-img">
      {% endif %}
    </div>
  </div>

  <div class="vm-row">
    <div class="vm-col">
      <div class="mb-2">
        <label><b>Vendor details:</b></label>
        <input type="text" class="form-control" value="{{ req.vendor_details or '-' }}" readonly>
      </div>
    </div>
    <div class="vm-col">
      <div class="mb-2">
        <label><b>Phone:</b></label>
        <input type="text" class="form-control" value="{{ req.phone or '-' }}" readonly>
      </div>
    </div>
  </div>

  <div class="mb-2">
    <label><b>Remarks:</b></label>
    <textarea id="remarks" class="form-control" rows="3" readonly>{{ req.remarks or '' }}</textarea>
  </div>

  {% if (user.role == 'manager' and req.status == 'Pending Manager Approval' and req.department == user.department) or
        (user.role == 'countryhead' and req.status == 'Pending Countryhead Approval') or
        (user.role == 'ceo' and req.status == 'Pending CEO Approval') %}
  <form method="POST" class="approval-form mb-3">
    <input type="password" name="password" class="form-control" placeholder="Confirm Password" required>
    <button type="submit" name="action" value="approve" class="btn btn-success me-2 mt-2">Approve</button>
    <button type="submit" name="action" value="reject" class="btn btn-danger mt-2">Reject</button>
  </form>
  {% endif %}

  <button class="btn btn-secondary hide-on-print" onclick="window.print()">Print / Save as PDF</button>

  <div class="print-only print-footer">
    Logged in as {{ user.username }} ({{ user.role.capitalize() }})
  </div>
</div>
</body>
</html>
"""

ACCOUNTS_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Accounts - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
    .small-text { font-size: 0.92rem; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_accounts') }}">Together Requisition</a>
    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>
    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} ({{ user.department }})</span>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>

<div class="container mt-4">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  <h4>New Approved Requisitions (to merge)</h4>
  {% if new_reqs %}
  <form method="POST" class="mb-4">
    <input type="hidden" name="action" value="merge">
    <table class="table table-bordered table-hover small-text">
      <thead class="table-light">
        <tr>
          <th><input type="checkbox" id="select_all" onclick="toggleAll(this)"></th>
          <th>ID</th>
          <th>Department</th>
          <th>Employee</th>
          <th>Status</th>
          <th>Total Amount</th>
          <th>Approved On</th>
          <th>View</th>
        </tr>
      </thead>
      <tbody>
        {% for r in new_reqs %}
        <tr>
          <td><input type="checkbox" name="req_ids" value="{{ r.id }}"></td>
          <td>{{ r.id }}</td>
          <td>{{ r.department }}</td>
          <td>{{ r.created_by.username }}</td>
          <td><span class="badge bg-primary">New Requisition</span></td>
          <td>{{ "%.2f"|format(r.total_amount) }}</td>
          <td>{{ r.decision_date.strftime('%d/%m/%Y %H:%M') if r.decision_date else '-' }}</td>
          <td><a href="{{ url_for('view_requisition', req_id=r.id) }}" class="btn btn-sm btn-outline-primary">View</a></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <button type="submit" class="btn btn-primary">Merge Selected</button>
  </form>
  {% else %}
    <p>No new approved requisitions to merge.</p>
  {% endif %}

  <h4>Merged Batches</h4>
  {% if batches %}
  <table class="table table-bordered table-hover small-text">
    <thead class="table-light">
      <tr>
        <th>Batch #</th>
        <th>Created By</th>
        <th>Created At</th>
        <th>Total Amount</th>
        <th>View</th>
      </tr>
    </thead>
    <tbody>
      {% for b in batches %}
      <tr>
        <td>{{ b.id }}</td>
        <td>{{ b.created_by.username if b.created_by else '-' }}</td>
        <td>{{ format_datetime_pk(b.created_at) }}</td>
        <td>{{ "%.2f"|format(b.total_amount) }}</td>
        <td><a href="{{ url_for('view_accounts_batch', batch_id=b.id) }}" class="btn btn-sm btn-outline-primary">View</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p>No merged batches yet.</p>
  {% endif %}
</div>

<script>
  function toggleAll(master){
    document.querySelectorAll('input[name="req_ids"]').forEach(cb => cb.checked = master.checked);
  }
</script>
</body>
</html>
"""

ACCOUNTS_BATCH_VIEW_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Accounts Batch - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .navbar .container-fluid { position: relative; }
    .navbar-center { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); }
    .navbar-logo { height: 36px; }
    .table thead th, .table tbody td { vertical-align: middle; text-align: center; }
    .total-strip { background-color:#d6e6db; padding:8px; }

    @media print {
      @page { margin: 12mm; }
      nav.navbar { display:none !important; }
      .print-header { text-align:center; margin-bottom:10px; }
      .print-header img { height:52px; margin-bottom:6px; }
      .table { border-collapse: collapse !important; }
      .table, .table th, .table td { border: 1.2px solid #000 !important; }
      .table thead th { background: #e9ecef !important; color:#111827 !important; }
      .total-strip { border: 1.2px solid #000 !important; }
    }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_accounts') }}">Together Requisition</a>
    <div class="navbar-center">
      <img src="{{ url_for('static', filename='logo.png') }}" class="navbar-logo" alt="TOGETHER Logo">
    </div>
    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} ({{ user.role.capitalize() }})</span>
      <a href="{{ url_for('dashboard_accounts') }}" class="btn btn-outline-light">Dashboard</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light ms-2">Logout</a>
    </div>
  </div>
</nav>

<div class="container mt-4" style="max-width: 1100px;">
  <div class="print-header">
    <img src="{{ url_for('static', filename='logo.png') }}" alt="TOGETHER Logo">
    <div style="font-weight:700; font-size: 16px;">Accounts Batch #{{ batch.id }}</div>
  </div>

  <div class="row mb-3">
    <div class="col-md-4"><b>Batch #:</b> {{ batch.id }}</div>
    <div class="col-md-4"><b>Created By:</b> {{ batch.created_by.username if batch.created_by else '-' }}</div>
    <div class="col-md-4"><b>Created At:</b> {{ format_datetime_pk(batch.created_at) }}</div>
  </div>

  <h6>Items (all selected requisitions)</h6>
  <table class="table table-bordered">
    <thead class="table-light">
      <tr>
        <th>Sr.No</th>
        <th>Req ID</th>
        <th>Department</th>
        <th>Date</th>
        <th>Item Description</th>
        <th>Price</th>
        <th>Qty</th>
        <th>Total</th>
      </tr>
    </thead>
    <tbody>
      {% for idx, it in enumerate(items, 1) %}
      <tr>
        <td>{{ idx }}</td>
        <td>{{ it.req_id }}</td>
        <td>{{ it.department }}</td>
        <td>{{ it.date }}</td>
        <td style="text-align:left;">{{ it.item_description }}</td>
        <td>{{ "%.2f"|format(it.price) }}</td>
        <td>{{ it.quantity }}</td>
        <td>{{ "%.2f"|format(it.total_price) }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="d-flex justify-content-end align-items-center mb-3 total-strip">
    <b class="me-3">BATCH TOTAL</b>
    <input type="text" class="form-control" style="max-width: 220px;" value="{{ "%.2f"|format(batch.total_amount) }}" readonly>
  </div>

  <h6>Requisition Totals</h6>
  <table class="table table-bordered">
    <thead class="table-light">
      <tr>
        <th>Req ID</th>
        <th>Department</th>
        <th>Employee</th>
        <th>Requisition Total</th>
      </tr>
    </thead>
    <tbody>
      {% for r in req_summaries %}
      <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.department }}</td>
        <td>{{ r.employee }}</td>
        <td>{{ "%.2f"|format(r.total_amount) }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <button class="btn btn-secondary" onclick="window.print()">Print / Save as PDF</button>
</div>
</body>
</html>
"""

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Lightweight migrations for added columns (SQLite safe)
        try:
            user_cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(user)"))]
            if 'email' not in user_cols:
                db.session.execute(text("ALTER TABLE user ADD COLUMN email VARCHAR(255)"))
                db.session.commit()
        except Exception as e:
            print("Email column migration check failed:", e)

        try:
            req_cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(requisition)"))]
            if 'accounts_status' not in req_cols:
                db.session.execute(text("ALTER TABLE requisition ADD COLUMN accounts_status VARCHAR(50)"))
            if 'accounts_batch_id' not in req_cols:
                db.session.execute(text("ALTER TABLE requisition ADD COLUMN accounts_batch_id INTEGER"))
            db.session.commit()
        except Exception as e:
            print("Requisition accounts columns migration check failed:", e)

        if not User.query.filter_by(role='superadmin').first():
            sa = User(username='superadmin', role='superadmin', department='')
            sa.set_password('superadmin')
            db.session.add(sa)
            db.session.commit()
            print("Created default superadmin with username 'superadmin' and password 'superadmin'")

    app.run(debug=True)