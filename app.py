from flask import Flask, render_template_string, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz
import json

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
    signature_filename = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Requisition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    department = db.Column(db.String(100))
    items_json = db.Column(db.Text)
    total_amount = db.Column(db.Float)
    status = db.Column(db.String(20), default='Pending Manager Approval')
    claimed_signature = db.Column(db.Text)
    manager_signature = db.Column(db.String(200))
    ceo_signature = db.Column(db.String(200))
    vendor_details = db.Column(db.String(300))
    phone = db.Column(db.String(50))
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(PK_TZ))
    pending_date = db.Column(db.DateTime)
    decision_date = db.Column(db.DateTime)

    created_by = db.relationship('User', backref='requisitions')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def format_datetime_pk(dt):
    if not dt:
        return '-'
    dt_pk = dt.astimezone(PK_TZ)
    return dt_pk.strftime('%d/%m/%Y %H:%M')

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
    if current_user.role == 'employee':
        return redirect(url_for('dashboard_employee'))
    elif current_user.role == 'manager':
        return redirect(url_for('dashboard_manager'))
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

@app.route('/dashboard/superadmin', methods=['GET', 'POST'])
@login_required
def dashboard_superadmin():
    if current_user.role != 'superadmin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    users = User.query.all()
    requisitions = Requisition.query.order_by(Requisition.created_at.desc()).all()
    if request.method == 'POST':
        action = request.form['action']
        if action == 'create':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            department = request.form.get('department', '')
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
            else:
                new_user = User(username=username, role=role, department=department)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('User created.', 'success')
        elif action == 'delete':
            user_id = int(request.form['user_id'])
            if user_id == current_user.id:
                flash('Cannot delete yourself.', 'danger')
            else:
                user = User.query.get(user_id)
                if user:
                    db.session.delete(user)
                    db.session.commit()
                    flash('User deleted.', 'success')
        elif action == 'reset_password':
            user_id = int(request.form['user_id'])
            new_password = request.form['new_password']
            user = User.query.get(user_id)
            if user:
                user.set_password(new_password)
                db.session.commit()
                flash('Password reset.', 'success')
        elif action == 'rename':
            user_id = int(request.form['user_id'])
            new_username = request.form['new_username']
            if User.query.filter_by(username=new_username).first():
                flash('Username already exists.', 'danger')
            else:
                user = User.query.get(user_id)
                if user:
                    user.username = new_username
                    db.session.commit()
                    flash('Username changed.', 'success')
        return redirect(url_for('dashboard_superadmin'))
    return render_template_string(SUPERADMIN_DASHBOARD_TEMPLATE, user=current_user, users=users, requisitions=requisitions)

@app.route('/dashboard/superadmin/requisitions')
@login_required
def superadmin_requisitions():
    if current_user.role != 'superadmin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    requisitions = Requisition.query.order_by(Requisition.created_at.desc()).all()
    return render_template_string(SUPERADMIN_REQUISITIONS_TEMPLATE, user=current_user, requisitions=requisitions, format_datetime_pk=format_datetime_pk)

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
        except Exception:
            flash('Invalid form data.', 'danger')
            return redirect(url_for('create_requisition'))
        total_amount = 0
        for item in items:
            try:
                total_amount += float(item.get('total_price', 0))
            except:
                pass
        claimed_signature = ''
        manager_signature = ''
        if current_user.role == 'employee':
            claimed_signature = f"Claimed by {current_user.username}"
        elif current_user.role == 'manager':
            manager_signature = f"Verified by {current_user.username}"
        req = Requisition(
            created_by_id=current_user.id,
            department=current_user.department,
            items_json=json.dumps(items),
            total_amount=total_amount,
            status='Pending Manager Approval' if current_user.role == 'employee' else 'Pending CEO Approval',
            claimed_signature=claimed_signature,
            manager_signature=manager_signature,
            vendor_details=vendor_details,
            phone=phone,
            remarks=remarks,
            pending_date=datetime.now(PK_TZ)
        )
        db.session.add(req)
        db.session.commit()
        flash('Requisition created.', 'success')
        return redirect(url_for('dashboard_redirect'))
    return render_template_string(CREATE_REQUISITION_TEMPLATE, user=current_user)

@app.route('/requisition/<int:req_id>', methods=['GET', 'POST'])
@login_required
def view_requisition(req_id):
    req = Requisition.query.get_or_404(req_id)
    if current_user.role == 'employee' and req.created_by_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    if current_user.role == 'manager':
        if req.created_by_id != current_user.id and req.department != current_user.department:
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard_redirect'))
    if request.method == 'POST':
        action = request.form['action']
        password = request.form['password']
        if not current_user.check_password(password):
            flash('Password incorrect.', 'danger')
            return redirect(url_for('view_requisition', req_id=req_id))
        if current_user.role == 'manager' and req.status == 'Pending Manager Approval' and req.department == current_user.department:
            if action == 'approve':
                req.status = 'Pending CEO Approval'
                req.manager_signature = current_user.signature_filename
                req.pending_date = datetime.now(PK_TZ)
                req.decision_date = datetime.now(PK_TZ)
            elif action == 'reject':
                req.status = 'Rejected'
                req.manager_signature = current_user.signature_filename
                req.decision_date = datetime.now(PK_TZ)
            db.session.commit()
            flash(f'Requisition {action}d.', 'success')
            return redirect(url_for('dashboard_manager'))
        elif current_user.role == 'ceo' and req.status == 'Pending CEO Approval':
            if action == 'approve':
                req.status = 'Approved'
                req.ceo_signature = current_user.signature_filename
                req.decision_date = datetime.now(PK_TZ)
            elif action == 'reject':
                req.status = 'Rejected'
                req.ceo_signature = current_user.signature_filename
                req.decision_date = datetime.now(PK_TZ)
            db.session.commit()
            flash(f'Requisition {action}d.', 'success')
            return redirect(url_for('dashboard_ceo'))
        else:
            flash('You cannot approve/reject this requisition.', 'danger')
            return redirect(url_for('dashboard_redirect'))
    items = json.loads(req.items_json)
    return render_template_string(VIEW_REQUISITION_TEMPLATE, user=current_user, req=req, items=items, enumerate=enumerate)

# Templates (full content)

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Login - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5" style="max-width: 400px;">
  <h2 class="mb-4">Login</h2>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="POST">
    <div class="mb-3">
      <label for="username" class="form-label">Username</label>
      <input type="text" class="form-control" id="username" name="username" required autofocus>
    </div>
    <div class="mb-3">
      <label for="password" class="form-label">Password</label>
      <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary w-100">Login</button>
  </form>
</div>
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
    }
    .signature-label {
      font-weight: bold;
      margin-bottom: 8px;
      display: block;
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
    window.onload = function() {
      addItemRow();
    }
  </script>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_redirect') }}">Together Requisition</a>
    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} ({{ user.role.capitalize() }})</span>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4" style="max-width: 900px;">
  <h3>Create Requisition</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="POST" onsubmit="return submitForm()">
    <table class="table table-bordered">
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
    <button type="button" class="btn btn-secondary mb-3" onclick="addItemRow()">+ Add More Row</button>

    <div class="signatures-container">
      <div class="signature-block">
        <label class="signature-label" for="claimed_signature">Claimed By Signature</label>
        <textarea id="claimed_signature" name="claimed_signature" class="form-control" rows="3" readonly>Claimed by {{ user.username }}</textarea>
      </div>
      <div class="signature-block">
        <label class="signature-label" for="manager_signature">Verify/Manager Signature</label>
        <textarea id="manager_signature" name="manager_signature" class="form-control" rows="3" readonly></textarea>
      </div>
      <div class="signature-block">
        <label class="signature-label" for="ceo_signature">CEO Signature</label>
        <textarea id="ceo_signature" name="ceo_signature" class="form-control" rows="3" readonly></textarea>
      </div>
    </div>

    <div class="mb-3">
      <label for="vendor_details" class="form-label">Vendor details</label>
      <input type="text" class="form-control" id="vendor_details" name="vendor_details" placeholder="e.g. Mr. Abdullah - Shop no 49A, Hafeez Center, Lahore">
    </div>
    <div class="mb-3">
      <label for="phone" class="form-label">Phone</label>
      <input type="text" class="form-control" id="phone" name="phone" placeholder="0302-XXXXXXX">
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
    <button type="submit" class="btn btn-primary">Submit Requisition</button>
    <button type="button" class="btn btn-secondary float-end" onclick="window.print()">Print / Save as PDF</button>
  </form>
</div>
</body>
</html>
"""

EMPLOYEE_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Employee Dashboard - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_employee') }}">Together Requisition</a>
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
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_manager') }}">Together Requisition</a>
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

CEO_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>CEO Dashboard - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .badge {
      font-size: 0.9em;
    }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_ceo') }}">Together Requisition</a>
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
SUPERADMIN_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Superadmin Dashboard - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .form-inline > * {
      margin-right: 10px;
    }
    .modal-backdrop.show {
      opacity: 0.5;
    }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">Together Requisition</a>
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
        <select name="role" class="form-select" required>
          <option value="" disabled selected>Select Role</option>
          <option value="employee">Employee</option>
          <option value="manager">Manager</option>
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
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<!-- Reset Password Modal -->
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

<!-- Rename User Modal -->
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
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_redirect') }}">Together Requisition</a>
    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} ({{ user.role.capitalize() }})</span>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Previous Requisitions</h3>
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
    .table thead th, .table tbody td {
      vertical-align: middle;
      text-align: center;
    }
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
    }
    .signature-label {
      font-weight: bold;
      margin-bottom: 8px;
      display: block;
    }
    .approval-form input[type="password"] {
      margin-bottom: 10px;
    }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">Together Requisition</a>
    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} ({{ user.role.capitalize() }})</span>
      <a href="{{ url_for('dashboard_redirect') }}" class="btn btn-outline-light">Dashboard</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light ms-2">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4" style="max-width: 1000px;">
  <h4 class="mb-3 text-white bg-info p-2 text-center">TOGETHER-REQUISITION</h4>
  <div class="mb-3">
    <label><b>Department Name:</b></label>
    <input type="text" class="form-control" value="{{ req.department }}" readonly>
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
        <td>{{ item.item_description }}</td>
        <td>{{ "%.2f"|format(item.price) }}</td>
        <td>{{ item.quantity }}</td>
        <td>{{ "%.2f"|format(item.total_price) }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <div class="d-flex justify-content-end align-items-center mb-3" style="background-color:#d6e6db; padding:10px;">
    <b class="me-3">TOTAL</b>
    <input type="number" class="form-control" style="max-width: 200px;" value="{{ "%.2f"|format(req.total_amount) }}" readonly>
  </div>

  <div class="signatures-container">
    <div class="signature-block">
      <label class="signature-label" for="claimed_signature">Claimed By Signature</label>
      <textarea id="claimed_signature" name="claimed_signature" class="form-control" rows="3" readonly>{{ req.claimed_signature or '-' }}</textarea>
    </div>
    <div class="signature-block">
      <label class="signature-label" for="manager_signature">Manager Signature</label>
      {% if req.manager_signature %}
        <img src="{{ url_for('static', filename=req.manager_signature) }}" alt="Manager Signature" class="signature-img" style="max-height: 100px;">
      {% else %}
        <textarea id="manager_signature" name="manager_signature" class="form-control" rows="3" readonly></textarea>
      {% endif %}
    </div>
    <div class="signature-block">
      <label class="signature-label" for="ceo_signature">CEO Signature</label>
      {% if req.ceo_signature %}
        <img src="{{ url_for('static', filename=req.ceo_signature) }}" alt="CEO Signature" class="signature-img" style="max-height: 100px;">
      {% else %}
        <textarea id="ceo_signature" name="ceo_signature" class="form-control" rows="3" readonly></textarea>
      {% endif %}
    </div>
  </div>

  <div class="row mb-3">
    <div class="col-md-6">
      <label><b>Vendor details:</b></label>
      <input type="text" class="form-control" value="{{ req.vendor_details or '-' }}" readonly>
    </div>
    <div class="col-md-6">
      <label><b>Phone:</b></label>
      <input type="text" class="form-control" value="{{ req.phone or '-' }}" readonly>
    </div>
  </div>

  <div class="mb-3">
    <label><b>Remarks:</b></label>
    <textarea class="form-control" rows="3" readonly>{{ req.remarks or '' }}</textarea>
  </div>

  {% if (user.role == 'manager' and req.status == 'Pending Manager Approval' and req.department == user.department) or
        (user.role == 'ceo' and req.status == 'Pending CEO Approval') %}
  <form method="POST" class="approval-form mb-3">
    <input type="password" name="password" class="form-control" placeholder="Confirm Password" required>
    <button type="submit" name="action" value="approve" class="btn btn-success me-2 mt-2">Approve</button>
    <button type="submit" name="action" value="reject" class="btn btn-danger mt-2">Reject</button>
  </form>
  {% endif %}

  <button class="btn btn-secondary" onclick="window.print()">Print / Save as PDF</button>
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
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard_superadmin') }}">Together Requisition</a>
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role='superadmin').first():
            sa = User(username='superadmin', role='superadmin', department='')
            sa.set_password('superadmin')
            db.session.add(sa)
            db.session.commit()
            print("Created default superadmin with username 'superadmin' and password 'superadmin'")
    app.run(debug=True)