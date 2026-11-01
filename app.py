
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, make_response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import date
from io import BytesIO
from xml.sax.saxutils import escape
import sqlite3
import secrets

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

app = Flask(__name__)
app.secret_key = "change-this-secret-key-for-your-project"

app.config.update(
    SESSION_PERMANENT=False,
    SESSION_COOKIE_NAME="electricity_bill_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

SERVER_SESSION_ID = secrets.token_hex(32)
DATABASE = "electricity.db"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin@123"


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            phone TEXT,
            units INTEGER NOT NULL DEFAULT 0,
            bill REAL NOT NULL DEFAULT 0,
            payment_status TEXT NOT NULL DEFAULT 'Unpaid'
        )
    """)

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(customers)"
        ).fetchall()
    }

    if "username" not in columns:
        connection.execute(
            "ALTER TABLE customers ADD COLUMN username TEXT"
        )

    if "password_hash" not in columns:
        connection.execute(
            "ALTER TABLE customers ADD COLUMN password_hash TEXT"
        )

    connection.execute("""
        CREATE TABLE IF NOT EXISTS bills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            billing_month TEXT NOT NULL,
            units INTEGER NOT NULL,
            bill_amount REAL NOT NULL,
            payment_status TEXT NOT NULL DEFAULT 'Unpaid',
            UNIQUE(customer_id, billing_month),
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )
    """)

    current_month = date.today().strftime("%Y-%m")

    connection.execute("""
        INSERT OR IGNORE INTO bills (
            customer_id, billing_month, units,
            bill_amount, payment_status
        )
        SELECT id, ?, units, bill, payment_status
        FROM customers
        WHERE units > 0
    """, (current_month,))

    connection.commit()
    connection.close()


# --------------------------------------------------
# BILL CALCULATION
# --------------------------------------------------

def calculate_bill(units):
    remaining = units
    bill = 0

    slab = min(remaining, 100)
    bill += slab * 3
    remaining -= slab

    if remaining > 0:
        slab = min(remaining, 100)
        bill += slab * 5
        remaining -= slab

    if remaining > 0:
        slab = min(remaining, 300)
        bill += slab * 7
        remaining -= slab

    if remaining > 0:
        bill += remaining * 8

    return round(bill, 2)


# --------------------------------------------------
# SESSION VALIDATION
# --------------------------------------------------

@app.before_request
def invalidate_old_sessions():
    if "role" in session:
        if session.get("_server_session_id") != SERVER_SESSION_ID:
            session.clear()
            flash(
                "Your previous session has expired. Please log in again.",
                "error"
            )
            return redirect(url_for("login"))


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Please log in as an administrator.", "error")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def customer_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if session.get("role") != "customer":
            flash("Please log in as a customer.", "error")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/")
def login():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    if session.get("role") == "customer":
        return redirect(url_for("customer_dashboard"))

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def process_login():
    role = request.form.get("role", "")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Enter both username and password.", "error")
        return redirect(url_for("login"))

    if role == "admin":
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()
            session["role"] = "admin"
            session["username"] = username
            session["_server_session_id"] = SERVER_SESSION_ID
            return redirect(url_for("admin_dashboard"))

        flash("Invalid administrator credentials.", "error")
        return redirect(url_for("login"))

    if role == "customer":
        connection = get_db()

        records = connection.execute("""
            SELECT password_hash
            FROM customers
            WHERE username = ?
              AND password_hash IS NOT NULL
        """, (username,)).fetchall()

        connection.close()

        valid_login = any(
            check_password_hash(record["password_hash"], password)
            for record in records
        )

        if valid_login:
            session.clear()
            session["role"] = "customer"
            session["username"] = username
            session["_server_session_id"] = SERVER_SESSION_ID
            return redirect(url_for("customer_dashboard"))

        flash("Invalid customer credentials.", "error")
        return redirect(url_for("login"))

    flash("Please select a valid login type.", "error")
    return redirect(url_for("login"))


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    connection = get_db()

    customers = connection.execute("""
        SELECT *
        FROM customers
        WHERE username IS NOT NULL
        ORDER BY id DESC
    """).fetchall()

    bills = connection.execute("""
        SELECT
            bills.id,
            bills.billing_month,
            bills.units,
            bills.bill_amount,
            bills.payment_status,
            customers.id AS customer_id,
            customers.name,
            customers.username
        FROM bills
        JOIN customers ON customers.id = bills.customer_id
        WHERE customers.username IS NOT NULL
          AND bills.payment_status != 'Paid'
        ORDER BY bills.billing_month DESC, bills.id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "index.html",
        customers=customers,
        bills=bills
    )


# --------------------------------------------------
# ADMIN: DELETE A REGISTERED CUSTOMER
# --------------------------------------------------

@app.route("/delete-customer/<int:customer_id>", methods=["POST"])
@admin_required
def delete_customer(customer_id):
    connection = get_db()

    try:
        # Confirm that this is a registered customer.
        customer = connection.execute("""
            SELECT id, name
            FROM customers
            WHERE id = ?
              AND username IS NOT NULL
        """, (customer_id,)).fetchone()

        if not customer:
            connection.close()
            flash("Customer not found or already deleted.", "error")
            return redirect(url_for("admin_dashboard"))

        # Start one transaction so both deletions succeed together.
        connection.execute("BEGIN")

        # Delete all bills for this customer:
        # unpaid bills, paid bills and complete bill history.
        connection.execute("""
            DELETE FROM bills
            WHERE customer_id = ?
        """, (customer_id,))

        # Delete the registered customer account.
        connection.execute("""
            DELETE FROM customers
            WHERE id = ?
              AND username IS NOT NULL
        """, (customer_id,))

        connection.commit()

        customer_name = customer["name"]

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Customer deletion failed.")
        connection.close()
        flash(
            "Could not delete the customer. No changes were saved.",
            "error"
        )
        return redirect(url_for("admin_dashboard"))

    connection.close()

    flash(
        f"Customer '{customer_name}', their account, and all associated "
        "bills and bill history have been permanently deleted.",
        "success"
    )
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# ADMIN: CUSTOMER BILL HISTORY
# --------------------------------------------------

@app.route("/admin/customer/<int:customer_id>/bill-history")
@admin_required
def customer_bill_history(customer_id):
    connection = get_db()

    customer = connection.execute("""
        SELECT id, name, address, phone, username
        FROM customers
        WHERE id = ? AND username IS NOT NULL
    """, (customer_id,)).fetchone()

    if not customer:
        connection.close()
        flash("Customer record not found.", "error")
        return redirect(url_for("admin_dashboard"))

    bills = connection.execute("""
        SELECT id, billing_month, units, bill_amount, payment_status
        FROM bills
        WHERE customer_id = ?
        ORDER BY billing_month DESC, id DESC
    """, (customer_id,)).fetchall()

    connection.close()

    return render_template(
        "bill_history.html",
        customer=customer,
        bills=bills
    )


# --------------------------------------------------
# DOWNLOAD A BILL AS PDF
# --------------------------------------------------

@app.route("/download-bill/<int:bill_id>")
def download_bill_pdf(bill_id):
    role = session.get("role")

    if role not in ("admin", "customer"):
        flash("Please log in to download a bill.", "error")
        return redirect(url_for("login"))

    connection = get_db()

    bill = connection.execute("""
        SELECT
            bills.id,
            bills.billing_month,
            bills.units,
            bills.bill_amount,
            bills.payment_status,
            customers.id AS customer_id,
            customers.name,
            customers.address,
            customers.username
        FROM bills
        JOIN customers ON customers.id = bills.customer_id
        WHERE bills.id = ?
          AND customers.username IS NOT NULL
    """, (bill_id,)).fetchone()

    connection.close()

    if not bill:
        abort(404)

    if role == "customer" and bill["username"] != session.get("username"):
        abort(403)

    pdf_buffer = BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=22 * mm,
        leftMargin=22 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "BillTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        leading=25,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        "BillSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=18
    )

    normal_style = styles["BodyText"]

    story = [
        Paragraph("ELECTRICITY BILL", title_style),
        Paragraph("Electricity Bill Management System", subtitle_style),
        Spacer(1, 5 * mm)
    ]

    customer_details = [
        ["CUSTOMER DETAILS", "BILL DETAILS"],
        [
            Paragraph(
                f"<b>Name:</b> {escape(str(bill['name']))}",
                normal_style
            ),
            Paragraph(
                f"<b>Bill ID:</b> {bill['id']}",
                normal_style
            )
        ],
        [
            Paragraph(
                f"<b>Customer ID:</b> {bill['customer_id']}",
                normal_style
            ),
            Paragraph(
                f"<b>Billing Month:</b> "
                f"{escape(str(bill['billing_month']))}",
                normal_style
            )
        ],
        [
            Paragraph(
                f"<b>Address:</b> "
                f"{escape(str(bill['address'] or '-'))}",
                normal_style
            ),
            ""
        ]
    ]

    details_table = Table(
        customer_details,
        colWidths=[82 * mm, 82 * mm]
    )

    details_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
    ]))

    story.append(details_table)
    story.append(Spacer(1, 12 * mm))

    bill_rows = [
        ["DESCRIPTION", "DETAILS"],
        ["Units Consumed", f"{bill['units']} kWh"],
        ["Payment Status", str(bill["payment_status"])],
        ["Total Amount", f"Rs. {bill['bill_amount']:.2f}"]
    ]

    bill_table = Table(
        bill_rows,
        colWidths=[82 * mm, 82 * mm]
    )

    bill_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#eff6ff")),
        ("PADDING", (0, 0), (-1, -1), 11),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
    ]))

    story.append(bill_table)

    document.build(story)
    pdf_buffer.seek(0)

    response = make_response(pdf_buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="electricity_bill_{bill["id"]}.pdf"'
    )

    return response


# --------------------------------------------------
# REGISTER A CUSTOMER
# --------------------------------------------------

@app.route("/add", methods=["POST"])
@admin_required
def add_customer():
    name = request.form.get("name", "").strip()
    address = request.form.get("address", "").strip()
    phone = request.form.get("phone", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not name or not address or not username or not password:
        flash(
            "Name, address, username and password are required.",
            "error"
        )
        return redirect(url_for("admin_dashboard"))

    if len(password) < 6:
        flash(
            "Customer password must be at least 6 characters.",
            "error"
        )
        return redirect(url_for("admin_dashboard"))

    connection = get_db()

    existing = connection.execute("""
        SELECT id FROM customers WHERE username = ? LIMIT 1
    """, (username,)).fetchone()

    if existing:
        connection.close()
        flash(
            "That username already exists. Choose another username.",
            "error"
        )
        return redirect(url_for("admin_dashboard"))

    password_hash = generate_password_hash(password)

    connection.execute("""
        INSERT INTO customers (
            name, address, phone, units, bill,
            payment_status, username, password_hash
        )
        VALUES (?, ?, ?, 0, 0, 'Unpaid', ?, ?)
    """, (name, address, phone, username, password_hash))

    connection.commit()
    connection.close()

    flash("Customer registered successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# GENERATE A MONTHLY BILL
# --------------------------------------------------

@app.route("/add-bill", methods=["POST"])
@admin_required
def add_bill():
    customer_id = request.form.get("customer_id", "")
    billing_month = request.form.get("billing_month", "")
    units_text = request.form.get("units", "")

    try:
        customer_id = int(customer_id)
        units = int(units_text)
        parsed_month = date.fromisoformat(billing_month + "-01")

        if parsed_month.strftime("%Y-%m") != billing_month:
            raise ValueError

        if units < 0:
            raise ValueError

    except (ValueError, TypeError):
        flash(
            "Enter a valid customer, month and non-negative unit count.",
            "error"
        )
        return redirect(url_for("admin_dashboard"))

    connection = get_db()

    customer = connection.execute("""
        SELECT id FROM customers
        WHERE id = ? AND username IS NOT NULL
    """, (customer_id,)).fetchone()

    if not customer:
        connection.close()
        flash("Please select a valid customer.", "error")
        return redirect(url_for("admin_dashboard"))

    amount = calculate_bill(units)

    try:
        connection.execute("""
            INSERT INTO bills (
                customer_id, billing_month, units,
                bill_amount, payment_status
            )
            VALUES (?, ?, ?, ?, 'Unpaid')
        """, (customer_id, billing_month, units, amount))

        connection.commit()

    except sqlite3.IntegrityError:
        connection.close()
        flash(
            "A bill already exists for this customer and month.",
            "error"
        )
        return redirect(url_for("admin_dashboard"))

    connection.close()

    flash(
        f"Bill generated successfully: Rs. {amount:.2f} for {billing_month}.",
        "success"
    )
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# MARK A MONTHLY BILL AS PAID
# --------------------------------------------------

@app.route("/pay/<int:bill_id>", methods=["POST"])
@admin_required
def mark_paid(bill_id):
    connection = get_db()

    connection.execute("""
        UPDATE bills
        SET payment_status = 'Paid'
        WHERE id = ?
    """, (bill_id,))

    connection.commit()
    connection.close()

    flash("Monthly bill marked as paid.", "success")
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# DELETE A MONTHLY BILL
# --------------------------------------------------

@app.route("/delete-bill/<int:bill_id>", methods=["POST"])
@admin_required
def delete_bill(bill_id):
    connection = get_db()

    connection.execute("""
        DELETE FROM bills WHERE id = ?
    """, (bill_id,))

    connection.commit()
    connection.close()

    flash("Monthly bill deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# CUSTOMER DASHBOARD
# --------------------------------------------------

@app.route("/customer")
@customer_required
def customer_dashboard():
    username = session["username"]
    connection = get_db()

    customer = connection.execute("""
        SELECT name
        FROM customers
        WHERE username = ?
        ORDER BY id DESC
        LIMIT 1
    """, (username,)).fetchone()

    bills = connection.execute("""
        SELECT
            bills.id,
            bills.billing_month,
            bills.units,
            bills.bill_amount,
            bills.payment_status
        FROM bills
        JOIN customers ON customers.id = bills.customer_id
        WHERE customers.username = ?
        ORDER BY bills.billing_month DESC, bills.id DESC
    """, (username,)).fetchall()

    bills_due = connection.execute("""
        SELECT
            bills.id,
            bills.billing_month,
            bills.units,
            bills.bill_amount,
            bills.payment_status
        FROM bills
        JOIN customers ON customers.id = bills.customer_id
        WHERE customers.username = ?
          AND bills.payment_status != 'Paid'
        ORDER BY bills.billing_month DESC, bills.id DESC
    """, (username,)).fetchall()

    connection.close()

    return render_template(
        "customer.html",
        bills=bills,
        bills_due=bills_due,
        username=username,
        customer_name=customer["name"] if customer else username
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have logged out successfully.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, use_reloader=False)
