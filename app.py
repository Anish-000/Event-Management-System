import sqlite3
import os
from flask import Flask, render_template, request, redirect, session, flash, url_for
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = "your_super_secret_key_change_in_production"
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# ── Database Connection ────────────────────────────────────────────────────────

def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


# ── Initialize Database ────────────────────────────────────────────────────────

def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'vendor', 'user')),
            category TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            image TEXT,
            FOREIGN KEY (vendor_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total_amount REAL NOT NULL,
            payment_method TEXT NOT NULL,
            name TEXT,
            email TEXT,
            address TEXT,
            city TEXT,
            state TEXT,
            pincode TEXT,
            status TEXT NOT NULL DEFAULT 'Received',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS membership (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('6_months', '1_year', '2_years')),
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS guest_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            guest_name TEXT NOT NULL,
            guest_email TEXT,
            guest_phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


# ── Auth Helpers ───────────────────────────────────────────────────────────────

def login_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect("/login")
            if session.get("role") != role:
                return render_template("403.html"), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


def _check_password(incoming: str, stored: str) -> bool:
    """Compare incoming SHA-256 hash (from JS) with stored password."""
    return incoming == stored


# ── Root ───────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    if "user_id" in session:
        role = session.get("role")
        if role == "admin":
            return redirect("/admin/dashboard")
        elif role == "vendor":
            return redirect("/vendor/dashboard")
        else:
            return redirect("/user/dashboard")
    return redirect("/login")


# ── Auth — Login ───────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect("/")

    if request.method == "POST":
        email         = request.form.get("email", "").strip()
        password_hash = request.form.get("password_hash", "").strip()

        if not email or not password_hash:
            flash("Email and password are required.", "error")
            return render_template("auth/login.html")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user and _check_password(password_hash, user["password"]):
            session["user_id"] = user["id"]
            session["role"]    = user["role"]
            session["name"]    = user["name"]
            return redirect("/")

        flash("Invalid email or password.", "error")
        return render_template("auth/login.html")

    return render_template("auth/login.html")


# ── Auth — Signup ──────────────────────────────────────────────────────────────

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect("/")

    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip()
        role     = request.form.get("role", "user")
        category = request.form.get("category", "").strip() or None
        password = request.form.get("password_hash") or request.form.get("password")

        if not all([name, email, password]):
            flash("All fields are required.", "error")
            return render_template("auth/signup.html")

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (name, email, password, role, category) VALUES (?, ?, ?, ?, ?)",
                (name, email, password, role, category)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Email already registered.", "error")
            return render_template("auth/signup.html")

        conn.close()
        flash("Account created! Please log in.", "success")
        return redirect("/login")

    return render_template("auth/signup.html")


# ── Auth — Logout ──────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/dashboard")
@login_required("admin")
def admin_dashboard():
    return render_template("admin/dashboard.html")


# Admin — Maintain Users ───────────────────────────────────────────────────────

@app.route("/admin/maintain_users")
@login_required("admin")
def maintain_users():
    conn  = get_db_connection()
    users = conn.execute("SELECT * FROM users WHERE role = 'user'").fetchall()
    conn.close()
    return render_template("admin/maintain_user.html", users=users)


@app.route("/admin/add_user", methods=["GET", "POST"])
@login_required("admin")
def admin_add_user():
    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password_hash") or request.form.get("password")

        if not all([name, email, password]):
            flash("All fields are required.", "error")
            return render_template("admin/add_user.html")

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'user')",
                (name, email, password)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Email already exists.", "error")
            return render_template("admin/add_user.html")

        conn.close()
        flash("User added successfully.", "success")
        return redirect("/admin/maintain_users")

    return render_template("admin/add_user.html")


@app.route("/admin/update_user/<int:id>", methods=["GET", "POST"])
@login_required("admin")
def admin_update_user(id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (id,)).fetchone()

    if not user:
        conn.close()
        flash("User not found.", "error")
        return redirect("/admin/maintain_users")

    if request.method == "POST":
        name  = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        conn.execute("UPDATE users SET name = ?, email = ? WHERE id = ?", (name, email, id))
        conn.commit()
        conn.close()
        flash("User updated.", "success")
        return redirect("/admin/maintain_users")

    conn.close()
    return render_template("admin/update_user.html", user=user)


@app.route("/admin/delete_user/<int:id>")
@login_required("admin")
def delete_user(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ? AND role = 'user'", (id,))
    conn.commit()
    conn.close()
    flash("User deleted.", "success")
    return redirect("/admin/maintain_users")


# Admin — Maintain Vendors ─────────────────────────────────────────────────────

@app.route("/admin/maintain_vendors")
@login_required("admin")
def maintain_vendors():
    conn    = get_db_connection()
    vendors = conn.execute("SELECT * FROM users WHERE role = 'vendor'").fetchall()
    conn.close()
    return render_template("admin/maintain_vendor.html", vendors=vendors)


@app.route("/admin/add_vendor", methods=["GET", "POST"])
@login_required("admin")
def admin_add_vendor():
    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip()
        category = request.form.get("category", "").strip()
        password = request.form.get("password_hash") or request.form.get("password")

        if not all([name, email, password, category]):
            flash("All fields are required.", "error")
            return render_template("admin/add_vendor.html")

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (name, email, password, role, category) VALUES (?, ?, ?, 'vendor', ?)",
                (name, email, password, category)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Email already exists.", "error")
            return render_template("admin/add_vendor.html")

        conn.close()
        flash("Vendor added successfully.", "success")
        return redirect("/admin/maintain_vendors")

    return render_template("admin/add_vendor.html")


@app.route("/admin/update_vendor/<int:id>", methods=["GET", "POST"])
@login_required("admin")
def admin_update_vendor(id):
    conn   = get_db_connection()
    vendor = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'vendor'", (id,)).fetchone()

    if not vendor:
        conn.close()
        flash("Vendor not found.", "error")
        return redirect("/admin/maintain_vendors")

    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip()
        category = request.form.get("category", "").strip()
        conn.execute(
            "UPDATE users SET name = ?, email = ?, category = ? WHERE id = ?",
            (name, email, category, id)
        )
        conn.commit()
        conn.close()
        flash("Vendor updated.", "success")
        return redirect("/admin/maintain_vendors")

    conn.close()
    return render_template("admin/update_vendor.html", vendor=vendor)


@app.route("/admin/delete_vendor/<int:id>")
@login_required("admin")
def delete_vendor(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ? AND role = 'vendor'", (id,))
    conn.commit()
    conn.close()
    flash("Vendor deleted.", "success")
    return redirect("/admin/maintain_vendors")


# Admin — Membership ───────────────────────────────────────────────────────────

@app.route("/admin/membership_add", methods=["GET", "POST"])
@login_required("admin")
def membership_add():
    conn  = get_db_connection()
    users = conn.execute("SELECT * FROM users WHERE role = 'user'").fetchall()

    if request.method == "POST":
        user_id         = request.form.get("user_id")
        membership_type = request.form.get("type", "6_months")
        start_date      = datetime.now()
        duration_map    = {"6_months": 180, "1_year": 365, "2_years": 730}
        end_date        = start_date + timedelta(days=duration_map.get(membership_type, 180))

        conn.execute("""
            INSERT INTO membership (user_id, type, start_date, end_date)
            VALUES (?, ?, ?, ?)
        """, (user_id, membership_type,
              start_date.strftime("%Y-%m-%d"),
              end_date.strftime("%Y-%m-%d")))
        conn.commit()
        conn.close()
        flash("Membership added successfully.", "success")
        return redirect("/admin/dashboard")

    conn.close()
    return render_template("admin/membership_add.html", users=users)


@app.route("/admin/membership_update", methods=["GET", "POST"])
@login_required("admin")
def membership_update():
    conn = get_db_connection()

    if request.method == "POST":
        membership_id = request.form.get("membership_id")
        action        = request.form.get("action", "extend")

        membership = conn.execute(
            "SELECT * FROM membership WHERE id = ?", (membership_id,)
        ).fetchone()

        if membership:
            if action == "extend" and membership["status"] != "cancelled":
                new_end = datetime.strptime(membership["end_date"], "%Y-%m-%d") + timedelta(days=180)
                conn.execute(
                    "UPDATE membership SET end_date = ? WHERE id = ?",
                    (new_end.strftime("%Y-%m-%d"), membership_id)
                )
                flash("Membership extended by 6 months.", "success")
            elif action == "cancel":
                conn.execute(
                    "UPDATE membership SET status = 'cancelled' WHERE id = ?",
                    (membership_id,)
                )
                flash("Membership cancelled.", "success")

        conn.commit()

    memberships = conn.execute("""
        SELECT membership.*, users.name AS user_name
        FROM membership
        JOIN users ON membership.user_id = users.id
    """).fetchall()

    conn.close()
    return render_template("admin/membership_update.html", memberships=memberships)


# Admin — Orders ───────────────────────────────────────────────────────────────

@app.route("/admin/orders")
@login_required("admin")
def admin_orders():
    conn   = get_db_connection()
    orders = conn.execute("""
        SELECT orders.*, users.name AS user_name, users.email AS user_email
        FROM orders
        JOIN users ON orders.user_id = users.id
        ORDER BY orders.created_at DESC
    """).fetchall()
    conn.close()
    return render_template("admin/orders.html", orders=orders)


@app.route("/admin/update_status/<int:order_id>", methods=["POST"])
@login_required("admin")
def admin_update_status(order_id):
    new_status = request.form.get("status")
    conn = get_db_connection()
    conn.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))
    conn.commit()
    conn.close()
    return redirect("/admin/orders")


# ══════════════════════════════════════════════════════════════════════════════
#  VENDOR
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/vendor/dashboard")
@login_required("vendor")
def vendor_dashboard():
    return render_template("vendor/dashboard.html")


@app.route("/vendor/products")
@login_required("vendor")
def vendor_products():
    conn     = get_db_connection()
    products = conn.execute(
        "SELECT * FROM products WHERE vendor_id = ?", (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("vendor/product_list.html", products=products)


@app.route("/vendor/add_product", methods=["GET", "POST"])
@login_required("vendor")
def add_product():
    if request.method == "POST":
        name  = request.form.get("name", "").strip()
        price = request.form.get("price", "").strip()
        image = request.files.get("image")
        image_filename = None

        if not name or not price:
            flash("Product name and price are required.", "error")
            return render_template("vendor/add_product.html")

        if image and image.filename:
            image_filename = f"{datetime.now().timestamp()}_{image.filename}"
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], image_filename))

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO products (vendor_id, name, price, image) VALUES (?, ?, ?, ?)",
            (session["user_id"], name, float(price), image_filename)
        )
        conn.commit()
        conn.close()
        flash("Product added successfully.", "success")
        return redirect("/vendor/products")

    return render_template("vendor/add_product.html")


@app.route("/vendor/delete_product/<int:id>")
@login_required("vendor")
def delete_product(id):
    conn = get_db_connection()
    conn.execute(
        "DELETE FROM products WHERE id = ? AND vendor_id = ?", (id, session["user_id"])
    )
    conn.commit()
    conn.close()
    flash("Product deleted.", "success")
    return redirect("/vendor/products")


@app.route("/vendor/orders")
@login_required("vendor")
def vendor_orders():
    conn   = get_db_connection()
    orders = conn.execute("""
        SELECT DISTINCT orders.*, users.name AS user_name, users.email AS user_email
        FROM orders
        JOIN order_items ON orders.id = order_items.order_id
        JOIN products ON order_items.product_id = products.id
        JOIN users ON orders.user_id = users.id
        WHERE products.vendor_id = ?
        ORDER BY orders.created_at DESC
    """, (session["user_id"],)).fetchall()
    conn.close()
    return render_template("vendor/update_status.html", orders=orders)


@app.route("/vendor/update_status/<int:order_id>", methods=["POST"])
@login_required("vendor")
def update_status(order_id):
    new_status = request.form.get("status")
    conn = get_db_connection()
    conn.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))
    conn.commit()
    conn.close()
    flash("Order status updated.", "success")
    return redirect("/vendor/orders")


# ══════════════════════════════════════════════════════════════════════════════
#  USER
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/user/dashboard")
@login_required("user")
def user_dashboard():
    return render_template("user/dashboard.html")


@app.route("/user/vendors")
@login_required("user")
def user_vendors():
    conn    = get_db_connection()
    vendors = conn.execute(
        "SELECT id, name, category FROM users WHERE role = 'vendor'"
    ).fetchall()
    conn.close()
    return render_template("user/vendor_list.html", vendors=vendors)


@app.route("/user/vendor_products/<int:vendor_id>")
@login_required("user")
def vendor_products_for_user(vendor_id):
    conn     = get_db_connection()
    vendor   = conn.execute("SELECT * FROM users WHERE id = ?", (vendor_id,)).fetchone()
    products = conn.execute(
        "SELECT * FROM products WHERE vendor_id = ?", (vendor_id,)
    ).fetchall()
    conn.close()
    return render_template("user/product_list.html", products=products, vendor=vendor)


@app.route("/user/add_to_cart/<int:product_id>")
@login_required("user")
def add_to_cart(product_id):
    conn     = get_db_connection()
    existing = conn.execute(
        "SELECT * FROM cart WHERE user_id = ? AND product_id = ?",
        (session["user_id"], product_id)
    ).fetchone()

    if existing:
        conn.execute("UPDATE cart SET quantity = quantity + 1 WHERE id = ?", (existing["id"],))
    else:
        conn.execute(
            "INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)",
            (session["user_id"], product_id)
        )

    conn.commit()
    conn.close()
    return redirect(request.referrer or "/user/vendors")


@app.route("/user/cart")
@login_required("user")
def view_cart():
    conn       = get_db_connection()
    cart_items = conn.execute("""
        SELECT cart.id, cart.quantity, products.name, products.price, products.image
        FROM cart
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = ?
    """, (session["user_id"],)).fetchall()
    total = sum(item["price"] * item["quantity"] for item in cart_items)
    conn.close()
    return render_template("user/cart.html", cart_items=cart_items, total=total)


@app.route("/user/update_cart/<int:cart_id>", methods=["POST"])
@login_required("user")
def update_cart(cart_id):
    quantity = int(request.form.get("quantity", 1))
    conn     = get_db_connection()
    if quantity < 1:
        conn.execute("DELETE FROM cart WHERE id = ? AND user_id = ?", (cart_id, session["user_id"]))
    else:
        conn.execute(
            "UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?",
            (quantity, cart_id, session["user_id"])
        )
    conn.commit()
    conn.close()
    return redirect("/user/cart")


@app.route("/user/remove_from_cart/<int:id>")
@login_required("user")
def remove_from_cart(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM cart WHERE id = ? AND user_id = ?", (id, session["user_id"]))
    conn.commit()
    conn.close()
    return redirect("/user/cart")


@app.route("/user/clear_cart")
@login_required("user")
def clear_cart():
    conn = get_db_connection()
    conn.execute("DELETE FROM cart WHERE user_id = ?", (session["user_id"],))
    conn.commit()
    conn.close()
    return redirect("/user/cart")


@app.route("/user/checkout", methods=["GET", "POST"])
@login_required("user")
def checkout():
    conn       = get_db_connection()
    cart_items = conn.execute("""
        SELECT cart.*, products.price, products.id AS product_id, products.name AS product_name
        FROM cart
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = ?
    """, (session["user_id"],)).fetchall()

    if not cart_items:
        conn.close()
        flash("Your cart is empty.", "error")
        return redirect("/user/cart")

    total = sum(item["price"] * item["quantity"] for item in cart_items)

    if request.method == "POST":
        name           = request.form.get("name", "").strip()
        email          = request.form.get("email", "").strip()
        address        = request.form.get("address", "").strip()
        city           = request.form.get("city", "").strip()
        state          = request.form.get("state", "").strip()
        pincode        = request.form.get("pincode", "").strip()
        payment_method = request.form.get("payment_method", "Cash")

        if not all([name, email, address, city, state, pincode]):
            flash("All fields are required.", "error")
            conn.close()
            return render_template("user/checkout.html", total=total, cart_items=cart_items)

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO orders (user_id, total_amount, payment_method, name, email, address, city, state, pincode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session["user_id"], total, payment_method, name, email, address, city, state, pincode))
        order_id = cursor.lastrowid

        for item in cart_items:
            cursor.execute(
                "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
                (order_id, item["product_id"], item["quantity"], item["price"])
            )

        cursor.execute("DELETE FROM cart WHERE user_id = ?", (session["user_id"],))
        conn.commit()
        conn.close()

        return render_template("user/success.html",
                               total=total, name=name, email=email,
                               address=address, city=city, state=state,
                               pincode=pincode, payment_method=payment_method)

    conn.close()
    return render_template("user/checkout.html", total=total, cart_items=cart_items)


@app.route("/user/orders")
@login_required("user")
def user_orders():
    conn   = get_db_connection()
    orders = conn.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("user/order_status.html", orders=orders)


@app.route("/user/guestlist")
@login_required("user")
def view_guestlist():
    conn   = get_db_connection()
    guests = conn.execute(
        "SELECT * FROM guest_list WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("user/guest_list.html", guests=guests)


@app.route("/user/add_guest", methods=["GET", "POST"])
@login_required("user")
def add_guest():
    if request.method == "POST":
        name  = request.form.get("guest_name", "").strip()
        email = request.form.get("guest_email", "").strip()
        phone = request.form.get("guest_phone", "").strip()

        if not name:
            flash("Guest name is required.", "error")
            return render_template("user/add_guest.html")

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO guest_list (user_id, guest_name, guest_email, guest_phone)
            VALUES (?, ?, ?, ?)
        """, (session["user_id"], name, email, phone))
        conn.commit()
        conn.close()
        flash("Guest added.", "success")
        return redirect("/user/guestlist")

    return render_template("user/add_guest.html")


@app.route("/user/update_guest/<int:id>", methods=["GET", "POST"])
@login_required("user")
def update_guest(id):
    conn  = get_db_connection()
    guest = conn.execute(
        "SELECT * FROM guest_list WHERE id = ? AND user_id = ?",
        (id, session["user_id"])
    ).fetchone()

    if not guest:
        conn.close()
        flash("Guest not found.", "error")
        return redirect("/user/guestlist")

    if request.method == "POST":
        name  = request.form.get("guest_name", "").strip()
        email = request.form.get("guest_email", "").strip()
        phone = request.form.get("guest_phone", "").strip()
        conn.execute("""
            UPDATE guest_list SET guest_name = ?, guest_email = ?, guest_phone = ?
            WHERE id = ? AND user_id = ?
        """, (name, email, phone, id, session["user_id"]))
        conn.commit()
        conn.close()
        flash("Guest updated.", "success")
        return redirect("/user/guestlist")

    conn.close()
    return render_template("user/update_guest.html", guest=guest)


@app.route("/user/delete_guest/<int:id>")
@login_required("user")
def delete_guest(id):
    conn = get_db_connection()
    conn.execute(
        "DELETE FROM guest_list WHERE id = ? AND user_id = ?", (id, session["user_id"])
    )
    conn.commit()
    conn.close()
    flash("Guest removed.", "success")
    return redirect("/user/guestlist")


# ── Error Pages ────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


# ── Run ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(debug=True)