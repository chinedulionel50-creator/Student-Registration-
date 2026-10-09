import customtkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import csv
import re
import os
import hashlib
import hmac
from datetime import datetime, date

DB = "students.db"

COURSES = ["Computer Science", "Software Engineering", "Cybersecurity", "Law",
           "Electrical Engineering", "Medicine", "Accounting", "Other"]
LEVELS = ["100", "200", "300", "400", "500"]
GENDERS = ["Male", "Female"]

# ---------- database ----------
def run(sql, params=()):
    conn = sqlite3.connect(DB)
    try:
        with conn:
            conn.execute(sql, params)
    finally:
        conn.close()

def query(sql, params=()):
    conn = sqlite3.connect(DB)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()        

def setup_database():
    run("""CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE
    )""")
    columns = [row[1] for row in query("PRAGMA table_info(students)")]
    for column in ("matric", "course", "phone", "level", "gender", "dob"):
        if column not in columns:
            run(f"ALTER TABLE students ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
    run("""CREATE UNIQUE INDEX IF NOT EXISTS idx_matric
           ON students(matric COLLATE NOCASE) WHERE matric != ''""")
    run("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password TEXT NOT NULL
    )""")
    user_columns = [row[1] for row in query("PRAGMA table_info(users)")]
    if "role" not in user_columns:
        run("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    # make sure there is always at least one admin (the oldest account)
    if query("SELECT 1 FROM users") and not query("SELECT 1 FROM users WHERE role = 'admin'"):
        run("UPDATE users SET role = 'admin' WHERE id = (SELECT MIN(id) FROM users)")

setup_database()

# ---------- passwords and accounts ----------
def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + digest.hex()

def check_password(password, stored):
    salt_hex, digest_hex = stored.split(":")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 100_000)
    return hmac.compare_digest(digest.hex(), digest_hex)

def create_user(username, password, confirm, role="user"):
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if len(password) < 6:
        return "Password must be at least 6 characters."
    if password != confirm:
        return "Passwords do not match."
    if query("SELECT 1 FROM users WHERE username = ?", (username,)):
        return "That username is already taken."
    run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, hash_password(password), role))
    return None

def admin_count():
    return query("SELECT COUNT(*) FROM users WHERE role = 'admin'")[0][0]

# ---------- table colours (follows dark/light mode) ----------
def apply_tree_style():
    dark = tk.get_appearance_mode() == "Dark"
    bg = "#2b2b2b" if dark else "#ffffff"
    fg = "#ffffff" if dark else "#000000"
    head_bg = "#1f538d" if dark else "#3b8ed0"
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg,
                    rowheight=26, borderwidth=0)
    style.map("Treeview", background=[("selected", "#1f6aa5")],
              foreground=[("selected", "#ffffff")])
    style.configure("Treeview.Heading", background=head_bg, foreground="#ffffff", relief="flat")
    style.map("Treeview.Heading", background=[("active", "#144870")])

# ---------- login screen ----------
def login_screen():
    result = {"user": None}
    attempts = {"count": 0}
    first_run = query("SELECT COUNT(*) FROM users")[0][0] == 0
    mode = {"register": first_run}

    win = tk.CTk()
    win.geometry("380x470")
    win.title("Login")
    win.protocol("WM_DELETE_WINDOW", win.quit)

    heading = tk.CTkLabel(win, text="", font=("Arial", 22))
    heading.pack(pady=20)

    username_entry = tk.CTkEntry(win, placeholder_text="Username", width=240)
    username_entry.pack(pady=8)

    password_entry = tk.CTkEntry(win, placeholder_text="Password", show="*", width=240)
    password_entry.pack(pady=8)

    confirm_entry = tk.CTkEntry(win, placeholder_text="Confirm password", show="*", width=240)

    message = tk.CTkLabel(win, text="", wraplength=300)
    message.pack(pady=5)

    action_button = tk.CTkButton(win, text="", command=lambda: attempt())
    action_button.pack(pady=10)

    switch_button = tk.CTkButton(win, text="", fg_color="gray", command=lambda: toggle())
    if not first_run:
        switch_button.pack(pady=5)

    def show_mode():
        for entry in (username_entry, password_entry, confirm_entry):
            entry.delete(0, "end")
        message.configure(text="")
        if mode["register"]:
            heading.configure(text="Create account")
            confirm_entry.pack(after=password_entry, pady=8)
            action_button.configure(text="Create account")
            switch_button.configure(text="Back to login")
        else:
            heading.configure(text="Login")
            confirm_entry.pack_forget()
            action_button.configure(text="Login")
            switch_button.configure(text="Create new account")

    def toggle():
        mode["register"] = not mode["register"]
        show_mode()

    def attempt():
        username = username_entry.get().strip()
        password = password_entry.get()

        if username == "" or password == "":
            message.configure(text="Enter username and password.", text_color="red")
            return

        if mode["register"]:
            role = "admin" if first_run else "user"
            error = create_user(username, password, confirm_entry.get(), role)
            if error:
                message.configure(text=error, text_color="red")
                return
            if first_run:
                result["user"] = username
                win.quit()
            else: 
                mode["register"] = False
                show_mode()
                message.configure(text="Account created. Please log in.", text_color="green")
        else:
            rows = query("SELECT password FROM users WHERE username = ?", (username,))
            if rows and check_password(password, rows[0][0]):
                result["user"] = username
                win.quit()
            else:
                attempts["count"] += 1
                if attempts["count"] >= 3:
                    win.quit()
                else:
                    left = 3 - attempts["count"]
                    message.configure(text=f"Wrong login. {left} attempt(s) left.", text_color="red")

    for entry in (username_entry, password_entry, confirm_entry):
        entry.bind("<Return>", lambda event: attempt())

    show_mode()
    win.mainloop()
    win.destroy()
    return result["user"]

# ---------- main app ----------
def run_app(current_user):
    current_user, role = query("SELECT username, role FROM users WHERE username = ?", (current_user,))[0]
    is_admin = role == "admin"
    state = {"editing_id": None, "logout": False, "sort_col": None, "reverse": False}

    window = tk.CTk()
    window.geometry("900x740")
    window.title("Student Registration")
    window.protocol("WM_DELETE_WINDOW", window.quit)
    apply_tree_style()

    first_frame = tk.CTkFrame(master=window)
    first_frame.pack(fill='x', pady=6, padx=19)

    second_frame = tk.CTkFrame(window)
    second_frame.pack(fill='x', pady=6, padx=19)

    third_frame = tk.CTkFrame(window)
    third_frame.pack(fill='both', expand=True, pady=6, padx=19)

    tk.CTkLabel(first_frame, text="Student Registration", font=("Arial", 22)).pack()

    user_row = tk.CTkFrame(first_frame, fg_color="transparent")
    user_row.pack(pady=4)
    tk.CTkLabel(user_row, text=f"Logged in as: {current_user} ({role})").pack(side="left", padx=10)

    # ---------- form ----------
    def add_entry(row, column, label, placeholder):
        tk.CTkLabel(second_frame, text=label).grid(row=row, column=column * 2, padx=(20, 5), pady=4, sticky="e")
        entry = tk.CTkEntry(second_frame, placeholder_text=placeholder, width=220)
        entry.grid(row=row, column=column * 2 + 1, padx=(5, 20), pady=4)
        entry.bind("<Return>", lambda event: submit())
        return entry

    def add_combo(row, column, label, values, readonly):
        tk.CTkLabel(second_frame, text=label).grid(row=row, column=column * 2, padx=(20, 5), pady=4, sticky="e")
        combo = tk.CTkComboBox(second_frame, values=values, width=220,
                               state="readonly" if readonly else "normal")
        combo.grid(row=row, column=column * 2 + 1, padx=(5, 20), pady=4)
        combo.set("")
        combo.bind("<Return>", lambda event: submit())
        return combo

    name_entry = add_entry(0, 0, "Full Name:", "Enter full name")
    matric_entry = add_entry(1, 0, "Matric No:", "e.g. 2024/1234")
    email_entry = add_entry(2, 0, "Email:", "Enter email")
    phone_entry = add_entry(3, 0, "Phone:", "e.g. 08012345678")

    course_box = add_combo(0, 1, "Course:", COURSES, False)
    level_box = add_combo(1, 1, "Level:", LEVELS, True)
    gender_box = add_combo(2, 1, "Gender:", GENDERS, True)
    dob_entry = add_entry(3, 1, "Birth date:", "YYYY-MM-DD (optional)")

    text_entries = [name_entry, matric_entry, email_entry, phone_entry, dob_entry]
    combo_boxes = [course_box, level_box, gender_box]

    button_row = tk.CTkFrame(second_frame, fg_color="transparent")
    button_row.grid(row=4, column=0, columnspan=4, pady=8)

    # ---------- bottom area ----------
    result_label = tk.CTkLabel(third_frame, text="", wraplength=800)
    result_label.pack(pady=4)

    search_row = tk.CTkFrame(third_frame, fg_color="transparent")
    search_row.pack(pady=4)
    search_entry = tk.CTkEntry(search_row, placeholder_text="Search any field", width=260)
    search_entry.pack(side="left", padx=5)
    search_entry.bind("<Return>", lambda event: refresh())

    # ---------- table ----------
    columns = ("name", "matric", "email", "course", "level", "phone", "gender", "dob")
    headings = {"name": "Name", "matric": "Matric No", "email": "Email", "course": "Course",
                "level": "Level", "phone": "Phone", "gender": "Gender", "dob": "Birth date"}
    widths = {"name": 150, "matric": 95, "email": 200, "course": 130, "level": 55, "phone": 105,
              "gender": 70, "dob": 90}

    tree_frame = tk.CTkFrame(third_frame)
    tree_frame.pack(fill="both", expand=True, padx=10, pady=6)

    tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse",
                        displaycolumns=("name", "matric", "email", "course", "level", "phone"))
    scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    for col in columns:
        tree.heading(col, text=headings[col], command=lambda c=col: sort_by(c))
        tree.column(col, width=widths[col], anchor="w")

    action_row = tk.CTkFrame(third_frame, fg_color="transparent")
    action_row.pack(pady=4)

    count_label = tk.CTkLabel(third_frame, text="")
    count_label.pack(pady=2)

    # ---------- helpers ----------
    def load_records():
        return query("""SELECT id, name, matric, email, course, level, phone, gender, dob
                        FROM students ORDER BY id""")

    def valid_email(email):
        return re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", email) is not None

    def valid_matric(matric):
        return re.match(r"^[A-Za-z0-9/\-]{3,20}$", matric) is not None

    def valid_phone(phone):
        return re.match(r"^\+?\d{7,15}$", phone) is not None

    def parse_dob(text):
        # accepts 2001-08-21 or 21-08-2001, always returns 2001-08-21
        for fmt in ("%Y-%m-%d", "%d-%m-%Y"):
            try:
                parsed = datetime.strptime(text, fmt).date()
            except ValueError:
                continue
            if parsed < date.today():
                return parsed.isoformat()
        return None

    def already_used(field, value):
        ignore = state["editing_id"] if state["editing_id"] is not None else -1
        rows = query(f"SELECT 1 FROM students WHERE {field} = ? COLLATE NOCASE AND id != ?", (value, ignore))
        return len(rows) > 0

    def say(text, color="green"):
        result_label.configure(text=text, text_color=color)

    # ---------- table actions ----------
    def refresh():
        term = search_entry.get().strip().lower()
        records = load_records()
        shown = [r for r in records if term in " ".join(r[1:]).lower()]

        if state["sort_col"] is not None:
            index = columns.index(state["sort_col"]) + 1
            shown.sort(key=lambda r: str(r[index]).lower(), reverse=state["reverse"])

        tree.delete(*tree.get_children())
        for r in shown:
            tree.insert("", "end", iid=str(r[0]), values=r[1:])

        if term:
            count_label.configure(text=f"Showing {len(shown)} of {len(records)} students")
        else:
            count_label.configure(text=f"Total: {len(records)} students")

    def sort_by(col):
        if state["sort_col"] == col:
            state["reverse"] = not state["reverse"]
        else:
            state["sort_col"] = col
            state["reverse"] = False
        refresh()

    def show_all():
        search_entry.delete(0, "end")
        refresh()

    def get_selected():
        selection = tree.selection()
        if not selection:
            say("Click a student in the table first.", "red")
            return None
        student_id = int(selection[0])
        for row in load_records():
            if row[0] == student_id:
                return row
        return None

    # ---------- form actions ----------
    def reset_form():
        state["editing_id"] = None
        for entry in text_entries:
            entry.delete(0, "end")
        for combo in combo_boxes:
            combo.set("")
        submit_button.configure(text="Submit")

    def submit():
        name = name_entry.get().strip()
        matric = matric_entry.get().strip()
        email = email_entry.get().strip()
        phone = phone_entry.get().strip().replace(" ", "")
        dob = dob_entry.get().strip()
        course = course_box.get().strip()
        level = level_box.get().strip()
        gender = gender_box.get().strip()

        def fail(text):
            say(text, "red")

        if name == "":
            return fail("Please enter the full name.")
        if not valid_matric(matric):
            return fail("Enter a valid matric number (letters, numbers, / or -).")
        if not valid_email(email):
            return fail("Please enter a valid email address.")
        if not valid_phone(phone):
            return fail("Enter a valid phone number (7 to 15 digits).")
        if course == "":
            return fail("Please choose or type a course.")
        if level not in LEVELS:
            return fail("Please choose a level.")
        if gender not in GENDERS:
            return fail("Please choose a gender.")
        if dob != "":
            dob = parse_dob(dob)
            if dob is None:
                return fail("Birth date must look like 2004-05-21 or 21-05-2004, and be in the past.")
        if already_used("email", email):
            return fail("This email is already registered.")
        if already_used("matric", matric):
            return fail("This matric number is already registered.")

        try:
            if state["editing_id"] is None:
                run("""INSERT INTO students (name, matric, email, course, level, phone, gender, dob)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (name, matric, email, course, level, phone, gender, dob))
                message = f"Saved: {name} ({matric})"
            else:
                run("""UPDATE students SET name = ?, matric = ?, email = ?, course = ?,
                       level = ?, phone = ?, gender = ?, dob = ? WHERE id = ?""",
                    (name, matric, email, course, level, phone, gender, dob, state["editing_id"]))
                message = f"Updated: {name} ({matric})"
        except sqlite3.IntegrityError:
            return fail("Email or matric number already registered.")

        reset_form()
        say(message)
        refresh()

    def edit_selected():
        row = get_selected()
        if row is None:
            return
        reset_form()
        state["editing_id"] = row[0]
        # row = (id, name, matric, email, course, level, phone, gender, dob)
        for entry, value in zip(text_entries, (row[1], row[2], row[3], row[6], row[8])):
            if value:
                entry.insert(0, value)
        for combo, value in zip(combo_boxes, (row[4], row[5], row[7])):
            combo.set(value)
        submit_button.configure(text="Save changes")
        say("Editing. Change the details, then click Save changes.", "orange")

    def cancel_edit():
        reset_form()
        say("Edit cancelled.", "gray")

    def delete_selected():
        row = get_selected()
        if row is None:
            return
        if messagebox.askyesno("Delete", f"Delete {row[1]}?"):
            run("DELETE FROM students WHERE id = ?", (row[0],))
            reset_form()
            say(f"Deleted: {row[1]}")
            refresh()

    def clear_all():
        if messagebox.askyesno("Clear all", "Delete ALL registrations?"):
            run("DELETE FROM students")
            reset_form()
            search_entry.delete(0, "end")
            say("All registrations cleared.")
            refresh()

    def on_double_click(event):
        if tree.identify_region(event.x, event.y) == "cell":
            edit_selected()

    tree.bind("<Double-1>", on_double_click)

    # ---------- export, backup, restore ----------
    def export_csv():
        records = load_records()
        if not records:
            say("There are no students to export.", "red")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV file", "*.csv")],
            initialfile=f"students_{date.today():%Y%m%d}.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.writer(file)
            writer.writerow([headings[c] for c in columns])
            writer.writerows([r[1:] for r in records])
        say(f"Exported {len(records)} students to {os.path.basename(path)}")

    def backup_database():
        path = filedialog.asksaveasfilename(
            defaultextension=".db", filetypes=[("Database", "*.db")],
            initialfile=f"students_backup_{date.today():%Y%m%d}.db")
        if not path:
            return
        if os.path.abspath(path) == os.path.abspath(DB):
            say("Choose a different file name for the backup.", "red")
            return
        source = sqlite3.connect(DB)
        target = sqlite3.connect(path)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        say(f"Backup saved: {os.path.basename(path)}")

    def looks_like_backup(path):
        try:
            conn = sqlite3.connect(path)
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            finally:
                conn.close()
            return {"students", "users"} <= tables
        except sqlite3.Error:
            return False

    def restore_backup():
        path = filedialog.askopenfilename(
            title="Choose a backup file", filetypes=[("Database", "*.db"), ("All files", "*.*")])
        if not path:
            return
        if os.path.abspath(path) == os.path.abspath(DB):
            say("That is the live database, choose a backup file.", "red")
            return
        if not looks_like_backup(path):
            say("That file is not a valid backup.", "red")
            return
        if not messagebox.askyesno(
                "Restore", "This replaces ALL current data with the backup.\n"
                           "A copy of the current data is saved as before_restore.db.\nContinue?"):
            return
        current = sqlite3.connect(DB)
        safety = sqlite3.connect("before_restore.db")
        try:
            current.backup(safety)
        finally:
            safety.close()
            current.close()
        source = sqlite3.connect(path)
        target = sqlite3.connect(DB)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        setup_database()
        messagebox.showinfo("Restore", "Backup restored. Please log in again.")
        state["logout"] = True
        window.quit()

    # ---------- manage users (admin) ----------
    def manage_users():
        top = tk.CTkToplevel(window)
        top.geometry("460x520")
        top.title("Manage users")
        top.attributes("-topmost", True)

        tk.CTkLabel(top, text="Manage users", font=("Arial", 20)).pack(pady=10)

        users_tree = ttk.Treeview(top, columns=("username", "role"), show="headings",
                                  selectmode="browse", height=8)
        users_tree.heading("username", text="Username")
        users_tree.heading("role", text="Role")
        users_tree.column("username", width=250)
        users_tree.column("role", width=100)
        users_tree.pack(fill="x", padx=15, pady=5)

        msg = tk.CTkLabel(top, text="", wraplength=400)
        msg.pack(pady=4)

        new_password_entry = tk.CTkEntry(top, placeholder_text="New password (for reset)", show="*", width=240)
        new_password_entry.pack(pady=6)

        def note(text, color="green"):
            msg.configure(text=text, text_color=color)

        def load_users():
            users_tree.delete(*users_tree.get_children())
            for user_id, username, user_role in query("SELECT id, username, role FROM users ORDER BY id"):
                users_tree.insert("", "end", iid=str(user_id), values=(username, user_role))

        def selected_user():
            selection = users_tree.selection()
            if not selection:
                note("Select a user first.", "red")
                return None
            rows = query("SELECT id, username, role FROM users WHERE id = ?", (int(selection[0]),))
            return rows[0] if rows else None

        def set_role(new_role):
            user = selected_user()
            if user is None:
                return
            if new_role == "user" and user[2] == "admin":
                if user[1].lower() == current_user.lower():
                    note("You cannot remove your own admin role.", "red")
                    return
                if admin_count() <= 1:
                    note("There must be at least one admin.", "red")
                    return
            run("UPDATE users SET role = ? WHERE id = ?", (new_role, user[0]))
            load_users()
            note(f"{user[1]} is now {new_role}.")

        def reset_password():
            user = selected_user()
            if user is None:
                return
            new_password = new_password_entry.get()
            if len(new_password) < 6:
                note("Type a new password (at least 6 characters) first.", "red")
                return
            run("UPDATE users SET password = ? WHERE id = ?", (hash_password(new_password), user[0]))
            new_password_entry.delete(0, "end")
            note(f"Password reset for {user[1]}.")

        def delete_user():
            user = selected_user()
            if user is None:
                return
            if user[1].lower() == current_user.lower():
                note("You cannot delete your own account.", "red")
                return
            if user[2] == "admin" and admin_count() <= 1:
                note("There must be at least one admin.", "red")
                return
            if messagebox.askyesno("Delete user", f"Delete user {user[1]}?", parent=top):
                run("DELETE FROM users WHERE id = ?", (user[0],))
                load_users()
                note(f"Deleted user {user[1]}.")

        buttons = tk.CTkFrame(top, fg_color="transparent")
        buttons.pack(pady=6)
        tk.CTkButton(buttons, text="Make admin", width=100, command=lambda: set_role("admin")).pack(side="left", padx=4)
        tk.CTkButton(buttons, text="Make user", width=100, command=lambda: set_role("user")).pack(side="left", padx=4)
        more = tk.CTkFrame(top, fg_color="transparent")
        more.pack(pady=6)
        tk.CTkButton(more, text="Reset password", width=120, command=reset_password).pack(side="left", padx=4)
        tk.CTkButton(more, text="Delete user", width=100, fg_color="red", hover_color="#a00",
                     command=delete_user).pack(side="left", padx=4)
        tk.CTkButton(top, text="Close", width=100, fg_color="gray", command=top.destroy).pack(pady=10)

        load_users()
        top.after(150, lambda: (top.lift(), top.focus_force(), top.grab_set()))

    # ---------- account actions ----------
    def logout():
        state["logout"] = True
        window.quit()

    def toggle_theme():
        tk.set_appearance_mode("dark" if theme_switch.get() == 1 else "light")
        apply_tree_style()

    def change_password():
        top = tk.CTkToplevel(window)
        top.geometry("360x420")
        top.title("Change password")
        top.attributes("-topmost", True)

        tk.CTkLabel(top, text="Change password", font=("Arial", 20)).pack(pady=15)
        current_entry = tk.CTkEntry(top, placeholder_text="Current password", show="*", width=240)
        current_entry.pack(pady=8)
        new_entry = tk.CTkEntry(top, placeholder_text="New password", show="*", width=240)
        new_entry.pack(pady=8)
        confirm_entry = tk.CTkEntry(top, placeholder_text="Confirm new password", show="*", width=240)
        confirm_entry.pack(pady=8)
        msg = tk.CTkLabel(top, text="", wraplength=300)
        msg.pack(pady=5)


        def save():
            rows = query("SELECT password FROM users WHERE username = ?", (current_user,))
            current = current_entry.get()
            new = new_entry.get()
            if not rows or not check_password(current, rows[0][0]):
                msg.configure(text="Current password is wrong.", text_color="red")
            elif len(new) < 6:
                msg.configure(text="New password must be at least 6 characters.", text_color="red")
            elif new != confirm_entry.get():
                msg.configure(text="New passwords do not match.", text_color="red")
            elif new == current:
                msg.configure(text="New password must be different.", text_color="red")
            else:
                run("UPDATE users SET password = ? WHERE username = ?", (hash_password(new), current_user))
                top.destroy()
                say("Password changed.")

        tk.CTkButton(top, text="Save password", command=save).pack(pady=15)
        for entry in (current_entry, new_entry, confirm_entry):
            entry.bind("<Return>", lambda event: save())

        top.after(150, lambda: (top.lift(), top.focus_force(), top.grab_set()))

    # ---------- buttons ----------
    tk.CTkButton(user_row, text="Change password", width=130, height=28,
                 command=change_password).pack(side="left", padx=5)
    tk.CTkButton(user_row, text="Logout", width=80, height=28, fg_color="gray",
                 command=logout).pack(side="left", padx=5)
    theme_switch = tk.CTkSwitch(user_row, text="Dark mode", command=toggle_theme)
    theme_switch.pack(side="left", padx=10)
    if tk.get_appearance_mode() == "Dark":
        theme_switch.select()

    submit_button = tk.CTkButton(button_row, text="Submit", command=submit)
    submit_button.pack(side="left", padx=10)
    tk.CTkButton(button_row, text="Cancel edit", fg_color="gray", command=cancel_edit).pack(side="left", padx=10)

    tk.CTkButton(search_row, text="Search", width=80, command=refresh).pack(side="left", padx=5)
    tk.CTkButton(search_row, text="View all", width=80, command=show_all).pack(side="left", padx=5)

    tk.CTkButton(action_row, text="Edit", width=70, command=edit_selected).pack(side="left", padx=4)
    tk.CTkButton(action_row, text="Export CSV", width=95, command=export_csv).pack(side="left", padx=4)
    if is_admin:
        tk.CTkButton(action_row, text="Delete", width=70, command=delete_selected).pack(side="left", padx=4)
        tk.CTkButton(action_row, text="Clear all", width=80, fg_color="red", hover_color="#a00",
                     command=clear_all).pack(side="left", padx=4)
        tk.CTkButton(action_row, text="Backup", width=75, command=backup_database).pack(side="left", padx=4)
        tk.CTkButton(action_row, text="Restore", width=75, command=restore_backup).pack(side="left", padx=4)
        tk.CTkButton(action_row, text="Users", width=70, command=manage_users).pack(side="left", padx=4)

    refresh()
    window.mainloop()
    window.destroy()
    return state["logout"]

# ---------- start ----------
while True:
    user = login_screen()
    if user is None:
        break
    if not run_app(user):
        break