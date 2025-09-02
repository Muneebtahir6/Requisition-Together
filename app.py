from flask import Flask, render_template_string, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(150))
    role = db.Column(db.String(20))  # 'employee', 'manager', 'ceo', 'superadmin'
    department = db.Column(db.String(100))  # For employees/managers
    signature_filename = db.Column(db.String(200))  # Store signature image filename relative to static/

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Requisition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    department = db.Column(db.String(100))
    items_json = db.Column(db.Text)  # JSON list of items with date, desc, price, qty, total
    total_amount = db.Column(db.Float)
    status = db.Column(db.String(20), default='Pending Manager Approval')  # or 'Pending CEO Approval', 'Approved', 'Rejected'
    claimed_signature = db.Column(db.Text)  # text or base64 image placeholder
    manager_signature = db.Column(db.String(200))  # filename string for signature image
    ceo_signature = db.Column(db.String(200))      # filename string for signature image
    vendor_details = db.Column(db.String(300))
    phone = db.Column(db.String(50))
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    created_by = db.relationship('User', backref='requisitions')

# --- User loader ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

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

# Employee dashboard
@app.route('/dashboard/employee')
@login_required
def dashboard_employee():
    if current_user.role != 'employee':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    requisitions = Requisition.query.filter_by(created_by_id=current_user.id).order_by(Requisition.created_at.desc()).all()
    return render_template_string(EMPLOYEE_DASHBOARD_TEMPLATE, user=current_user, requisitions=requisitions)

# Manager dashboard
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

    return render_template_string(MANAGER_DASHBOARD_TEMPLATE, user=current_user, pending_reqs=pending_reqs, previous_reqs=previous_reqs)

# CEO dashboard
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

    return render_template_string(CEO_DASHBOARD_TEMPLATE, user=current_user, pending_reqs=pending_reqs, previous_reqs=previous_reqs)

# Superadmin dashboard
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

# Create requisition
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
            remarks=remarks
        )
        db.session.add(req)
        db.session.commit()
        flash('Requisition created.', 'success')
        return redirect(url_for('dashboard_redirect'))

    return render_template_string(CREATE_REQUISITION_TEMPLATE, user=current_user)

# View requisition details + approval form
@app.route('/requisition/<int:req_id>', methods=['GET', 'POST'])
@login_required
def view_requisition(req_id):
    req = Requisition.query.get_or_404(req_id)

    # Access control
    if current_user.role == 'employee' and req.created_by_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard_redirect'))
    if current_user.role == 'manager':
        if req.created_by_id != current_user.id and req.department != current_user.department:
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard_redirect'))
    # CEO and Superadmin no restriction

    if request.method == 'POST':
        action = request.form['action']
        password = request.form['password']
        if not current_user.check_password(password):
            flash('Password incorrect.', 'danger')
            return redirect(url_for('view_requisition', req_id=req_id))

        if current_user.role == 'manager' and req.status == 'Pending Manager Approval' and req.department == current_user.department:
            if action == 'approve':
                req.status = 'Pending CEO Approval'
                req.manager_signature = current_user.signature_filename  # Save filename
            elif action == 'reject':
                req.status = 'Rejected'
                req.manager_signature = current_user.signature_filename
            db.session.commit()
            flash(f'Requisition {action}d.', 'success')
            return redirect(url_for('dashboard_manager'))

        elif current_user.role == 'ceo' and req.status == 'Pending CEO Approval':
            if action == 'approve':
                req.status = 'Approved'
                req.ceo_signature = current_user.signature_filename  # Save filename
            elif action == 'reject':
                req.status = 'Rejected'
                req.ceo_signature = current_user.signature_filename
            db.session.commit()
            flash(f'Requisition {action}d.', 'success')
            return redirect(url_for('dashboard_ceo'))

        else:
            flash('You cannot approve/reject this requisition.', 'danger')
            return redirect(url_for('dashboard_redirect'))

    items = json.loads(req.items_json)
    return render_template_string(VIEW_REQUISITION_TEMPLATE, user=current_user, req=req, items=items, enumerate=enumerate)

# Previous requisitions
@app.route('/requisitions/previous')
@login_required
def previous_requisitions():
    requisitions = Requisition.query.filter_by(created_by_id=current_user.id).order_by(Requisition.created_at.desc()).all()
    return render_template_string(PREVIOUS_REQUISITIONS_TEMPLATE, user=current_user, requisitions=requisitions)

# --- Templates ---

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
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">Together Requisition</a>
    <div class="d-flex">
      <span class="navbar-text me-3">Logged in as {{ user.username }} (Superadmin)</span>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Manage Users</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="POST" class="mb-4">
    <input type="hidden" name="action" value="create">
    <div class="form-inline">
      <input type="text" name="username" placeholder="Username" required class="form-control">
      <input type="password" name="password" placeholder="Password" required class="form-control">
      <select name="role" class="form-control" required>
        <option value="">Select Role</option>
        <option value="employee">Employee</option>
        <option value="manager">Manager</option>
        <option value="ceo">CEO</option>
        <option value="superadmin">Superadmin</option>
      </select>
      <input type="text" name="department" placeholder="Department (optional)" class="form-control">
      <button type="submit" class="btn btn-primary">Create User</button>
    </div>
  </form>

  <h4>Existing Users</h4>
  <table class="table table-bordered table-hover">
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
          <form method="POST" style="display:inline-block;">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="user_id" value="{{ u.id }}">
            <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete user?')">Delete</button>
          </form>
          <button class="btn btn-secondary btn-sm" onclick="showResetPassword({{ u.id }})">Reset Password</button>
          <button class="btn btn-info btn-sm" onclick="showRenameUser({{ u.id }}, '{{ u.username }}')">Rename</button>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <!-- Reset Password Modal -->
  <div id="resetPasswordModal" style="display:none; position:fixed; top:20%; left:50%; transform:translateX(-50%); background:#fff; padding:20px; border:1px solid #ccc; z-index:1000;">
    <h5>Reset Password</h5>
    <form method="POST" id="resetPasswordForm">
      <input type="hidden" name="action" value="reset_password">
      <input type="hidden" name="user_id" id="resetUserId">
      <div class="mb-3">
        <input type="password" name="new_password" placeholder="New Password" required class="form-control">
      </div>
      <button type="submit" class="btn btn-primary">Reset</button>
      <button type="button" class="btn btn-secondary" onclick="hideResetPassword()">Cancel</button>
    </form>
  </div>

  <!-- Rename User Modal -->
  <div id="renameUserModal" style="display:none; position:fixed; top:20%; left:50%; transform:translateX(-50%); background:#fff; padding:20px; border:1px solid #ccc; z-index:1000;">
    <h5>Rename User</h5>
    <form method="POST" id="renameUserForm">
      <input type="hidden" name="action" value="rename">
      <input type="hidden" name="user_id" id="renameUserId">
      <div class="mb-3">
        <input type="text" name="new_username" placeholder="New Username" required class="form-control" id="renameUsernameInput">
      </div>
      <button type="submit" class="btn btn-primary">Rename</button>
      <button type="button" class="btn btn-secondary" onclick="hideRenameUser()">Cancel</button>
    </form>
  </div>

</div>
<script>
  function showResetPassword(userId) {
    document.getElementById('resetUserId').value = userId;
    document.getElementById('resetPasswordModal').style.display = 'block';
  }
  function hideResetPassword() {
    document.getElementById('resetPasswordModal').style.display = 'none';
  }
  function showRenameUser(userId, username) {
    document.getElementById('renameUserId').value = userId;
    document.getElementById('renameUsernameInput').value = username;
    document.getElementById('renameUserModal').style.display = 'block';
  }
  function hideRenameUser() {
    document.getElementById('renameUserModal').style.display = 'none';
  }
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
  <script>
    function addItemRow() {
      const tbody = document.getElementById('itemsBody');
      const rowCount = tbody.rows.length;
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
      <tbody id="itemsBody">
      </tbody>
    </table>
    <button type="button" class="btn btn-secondary mb-3" onclick="addItemRow()">Add Item</button>
    <div class="mb-3">
      <label for="vendor_details" class="form-label">Vendor Details</label>
      <input type="text" class="form-control" id="vendor_details" name="vendor_details">
    </div>
    <div class="mb-3">
      <label for="phone" class="form-label">Phone</label>
      <input type="text" class="form-control" id="phone" name="phone">
    </div>
    <div class="mb-3">
      <label for="remarks" class="form-label">Remarks</label>
      <textarea class="form-control" id="remarks" name="remarks" rows="3"></textarea>
    </div>
    <div class="mb-3 d-flex align-items-center">
      <label class="me-3"><b>Total Amount:</b></label>
      <input type="text" id="grandTotal" class="form-control" style="max-width: 200px;" readonly>
    </div>
    <input type="hidden" id="items_json" name="items_json">
    <button type="submit" class="btn btn-primary">Submit Requisition</button>
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
    <a class="navbar-brand" href="#">Together Requisition</a>
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
        <td>{{ r.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
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

PREVIOUS_REQUISITIONS_TEMPLATE = EMPLOYEE_DASHBOARD_TEMPLATE  # For simplicity, reuse employee dashboard template

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
    <a class="navbar-brand" href="#">Together Requisition</a>
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
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-info">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">Together Requisition</a>
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

VIEW_REQUISITION_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>View Requisition - Together Requisition</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .signature-img {
      max-height: 100px;
      margin-top: 5px;
    }
    .table thead th, .table tbody td {
      vertical-align: middle;
      text-align: center;
    }
    /* Horizontal signature layout */
    .signatures-container {
      display: flex;
      gap: 40px;
      margin-top: 20px;
      margin-bottom: 20px;
    }
    .signature-block {
      flex: 1;
      text-align: center;
    }
    .signature-label {
      font-weight: bold;
      margin-bottom: 5px;
      display: block;
      text-align: left;
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
      <span class="signature-label">Claimed By Signature:</span>
      <div>{{ req.claimed_signature or '-' }}</div>
    </div>
    <div class="signature-block">
      <span class="signature-label">Manager Signature:</span>
      {% if req.manager_signature %}
        <img src="{{ url_for('static', filename=req.manager_signature) }}" alt="Manager Signature" class="signature-img">
      {% else %}
        <div>-</div>
      {% endif %}
    </div>
    <div class="signature-block">
      <span class="signature-label">CEO Signature:</span>
      {% if req.ceo_signature %}
        <img src="{{ url_for('static', filename=req.ceo_signature) }}" alt="CEO Signature" class="signature-img">
      {% else %}
        <div>-</div>
      {% endif %}
    </div>
  </div>

  <div class="mb-3">
    <b>Vendor details:</b> {{ req.vendor_details or '-' }}
  </div>
  <div class="mb-3">
    <b>Phone:</b> {{ req.phone or '-' }}
  </div>
  <div class="mb-3">
    <b>Remarks:</b>
    <textarea class="form-control" rows="3" readonly>{{ req.remarks or '' }}</textarea>
  </div>

  {% if (user.role == 'manager' and req.status == 'Pending Manager Approval' and req.department == user.department) or
        (user.role == 'ceo' and req.status == 'Pending CEO Approval') %}
  <form method="POST" class="mb-3">
    <div class="mb-2">
      <input type="password" name="password" class="form-control" placeholder="Confirm Password" required>
    </div>
    <button type="submit" name="action" value="approve" class="btn btn-success me-2">Approve</button>
    <button type="submit" name="action" value="reject" class="btn btn-danger">Reject</button>
  </form>
  {% endif %}

  <button class="btn btn-secondary" onclick="window.print()">Print / Save as PDF</button>
</div>
</body>
</html>
"""

# --- Run app ---

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