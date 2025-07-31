import os
import sqlite3
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet, InvalidToken
import logging
import traceback
from datetime import datetime

# Constants
TEXTBOX_WIDTH = 30
BUTTON_WIDTH = 20
WINDOW_WIDTH = 550
WINDOW_HEIGHT = 550
PASSWORDS_DIR = "Passwords"
KEYS_DIR = os.path.join(PASSWORDS_DIR, "keys")
IMAGE_PATH = "AngelicSecurity.png"  
IMAGE_SCALE = 0.5  
file_initialized = False

# Ensure directories exist
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(PASSWORDS_DIR, exist_ok=True)

def log_debug_message(message):
    global file_initialized
    debug_file_path = 'Debug_Log.txt'
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

    # Overwrite the file on the first call
    if not file_initialized:
        with open(debug_file_path, 'w') as file:
            file.write("Security Debug Log\n")
        file_initialized = True
    
    # Append messages to the file after it's initialized
    with open(debug_file_path, 'a') as file:
        file.write(f"{timestamp}--{message}\n")

class ECHO_Security:
    def __init__(self, master):
        log_debug_message("DEBUG: Debug File Created")
        log_debug_message("DEBUG: Initializing PasswordManager.")
        self.master = master
        self.master.title("Enhanced Cognitive Helper and Operator")
        self.master.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.master.configure(bg='#082245')
        self.current_user = None
        self.current_key = None
        self.photo = None

        # Define the path for the Passwords folder and database
        self.passwords_dir = os.path.join(os.path.dirname(__file__), 'Passwords')
        self.db_path = os.path.join(self.passwords_dir, 'passwords.db')

        self.initialize_database()
        self.create_login_screen()

    def initialize_database(self):
        log_debug_message("DEBUG: Initializing database.")
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if the users table already exists
            log_debug_message("DEBUG: Checking for 'users' table.")
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone() is None:
                log_debug_message("DEBUG: Creating 'users' table.")
                cursor.execute(''' 
                    CREATE TABLE users (
                        username TEXT PRIMARY KEY,
                        master_password TEXT
                    )
                ''')
                conn.commit()

            # Check if the passwords table already exists
            log_debug_message("DEBUG: Checking for 'passwords' table.")
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'")
            if cursor.fetchone() is None:
                log_debug_message("DEBUG: Creating 'passwords' table.")
                cursor.execute(''' 
                    CREATE TABLE passwords (
                        id INTEGER PRIMARY KEY,
                        username TEXT,
                        service TEXT,
                        password TEXT,
                        service_username TEXT,
                        FOREIGN KEY (username) REFERENCES users(username)
                    )
                ''')
                conn.commit()
            else:
                # Check if service_username column exists
                cursor.execute("PRAGMA table_info(passwords)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'service_username' not in columns:
                    log_debug_message("DEBUG: Adding 'service_username' column to 'passwords' table.")
                    cursor.execute("ALTER TABLE passwords ADD COLUMN service_username TEXT")
                    conn.commit()

            log_debug_message("DEBUG: Database initialized successfully.")
        except sqlite3.Error as e:
            log_debug_message(f"DEBUG: SQLite error: {e}")
            logging.error(f"SQLite error: {e}")
        except Exception as e:
            log_debug_message(f"DEBUG: Unexpected error: {e}")
            logging.error(f"Unexpected error: {e}")
            logging.error(traceback.format_exc())
        finally:
            if conn:
                log_debug_message("DEBUG: Closing database connection.")
                conn.close()

    def load_image(self):
        try:
            log_debug_message(f"DEBUG: Loading image from: {IMAGE_PATH}")
            if os.path.exists(IMAGE_PATH):
                image = Image.open(IMAGE_PATH)
                image = image.resize(
                    (int(image.width * IMAGE_SCALE), int(image.height * IMAGE_SCALE)),
                    Image.LANCZOS
                )
                self.photo = ImageTk.PhotoImage(image)
                log_debug_message("DEBUG: Image loaded and scaled successfully.")
            else:
                log_debug_message(f"DEBUG: Image file not found: {IMAGE_PATH}")
                self.photo = None
        except Exception as e:
            log_debug_message(f"DEBUG: Error loading image: {e}")
            self.photo = None

    def display_image(self):
        if self.photo:
            log_debug_message("DEBUG: Displaying image.")
            tk.Label(self.master, image=self.photo, bg='#082245').pack()

    def create_login_screen(self):
        log_debug_message("DEBUG: Creating login screen.")
        self.clear_screen()
        self.load_image()
        self.display_image()
        tk.Label(self.master, text="Username:", bg='#082245', fg='#FFFFFF').pack(pady=(10, 0))
        self.username_entry = tk.Entry(self.master, width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.username_entry.pack()
        tk.Label(self.master, text="Master Password:", bg='#082245', fg='#FFFFFF').pack()
        self.password_entry = tk.Entry(self.master, show='*', width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.password_entry.pack()
        tk.Button(self.master, text="Log In", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.log_in).pack()
        tk.Button(self.master, text="Sign Up", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=lambda: [log_debug_message("DEBUG: Starting sign-up process."), self.create_sign_up_screen()]).pack()
        tk.Button(self.master, text="Exit", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.master.quit).pack(pady=10)

    def create_sign_up_screen(self):
        log_debug_message("DEBUG: Creating sign-up screen.")
        self.clear_screen()
        self.load_image()
        self.display_image()
        tk.Label(self.master, text="Username:", bg='#082245', fg='#FFFFFF').pack(pady=(10, 0))
        self.username_entry = tk.Entry(self.master, width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.username_entry.pack()
        
        # Password entry
        tk.Label(self.master, text="Master Password:", bg='#082245', fg='#FFFFFF').pack()
        self.password_entry = tk.Entry(self.master, show='*', width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.password_entry.pack()
        
        # Confirm password entry
        tk.Label(self.master, text="Confirm Password:", bg='#082245', fg='#FFFFFF').pack()
        self.confirm_password_entry = tk.Entry(self.master, show='*', width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.confirm_password_entry.pack()
        
        # Confirm and Back buttons
        tk.Button(self.master, text="Confirm", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.sign_up).pack()
        tk.Button(self.master, text="Back", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_login_screen).pack(pady=10) 

    def create_main_screen(self):
        log_debug_message("Creating main screen.")
        self.clear_screen()
        self.load_image()  # Load the image for main screen
        self.display_image()  # Display the image
        log_debug_message("Main screen UI elements setup in progress.")
        
        tk.Button(self.master, text="Add Password", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_add_password_screen).pack()
        tk.Button(self.master, text="View Passwords", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.view_passwords).pack()
        tk.Button(self.master, text="Settings", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_settings_screen).pack()
        tk.Button(self.master, text="Exit", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.master.quit).pack()
        
        log_debug_message("Main screen created successfully.")

    def create_add_password_screen(self):
        log_debug_message("Creating add password screen.")
        self.clear_screen()
        log_debug_message("Cleared screen for add password screen.")
        
        # Load and display the logo
        self.load_image()
        self.display_image()
        tk.Label(self.master, text="Service:", bg='#082245', fg='#FFFFFF').pack(pady=10)
        self.service_entry = tk.Entry(self.master, width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.service_entry.pack()
        tk.Label(self.master, text="Service Username:", bg='#082245', fg='#FFFFFF').pack(pady=10)
        self.username_entry_add = tk.Entry(self.master, width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.username_entry_add.pack()
        tk.Label(self.master, text="Service Password:", bg='#082245', fg='#FFFFFF').pack()
        self.password_entry_add = tk.Entry(self.master, show='*', width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.password_entry_add.pack()
        tk.Button(self.master, text="Save", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.save_password).pack()
        tk.Button(self.master, text="Back", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_main_screen).pack(pady=10)
        
        log_debug_message("Add password screen created successfully.")

    def create_settings_screen(self):
        log_debug_message("Creating settings screen.")
        self.clear_screen()
        self.load_image()  # Load the image for settings screen
        self.display_image()  # Display the image
        
        log_debug_message("Settings screen UI elements setup in progress.")
        tk.Button(self.master, text="Change Password", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_change_master_password_screen).pack()
        tk.Button(self.master, text="Log Out", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_login_screen).pack()
        tk.Button(self.master, text="Delete Account", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_delete_account_screen).pack() 
        tk.Button(self.master, text="Exit", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.master.quit).pack()
        tk.Button(self.master, text="Back", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_main_screen).pack(pady=10)
        
        log_debug_message("Settings screen created successfully.")

    def create_edit_entry_screen(self, record_id):
        log_debug_message(f"DEBUG: Editing entry with ID {record_id}")
        self.clear_screen()

        # Fetch the entry data from the database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT service, service_username, password FROM passwords WHERE id = ?", (record_id,))
        entry = cursor.fetchone()
        conn.close()

        if not entry:
            messagebox.showerror("Error", "Entry not found.")
            return

        service, service_username, encrypted_password = entry
        fernet = Fernet(self.current_key)
        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()

        # Populate fields with current entry data
        tk.Label(self.master, text="Edit Service:", bg='#082245', fg='#FFFFFF').pack(pady=10)
        self.service_entry = tk.Entry(self.master, width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.service_entry.insert(0, service)
        self.service_entry.pack()

        tk.Label(self.master, text="Edit Service Username:", bg='#082245', fg='#FFFFFF').pack(pady=10)
        self.username_entry_add = tk.Entry(self.master, width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.username_entry_add.insert(0, service_username)
        self.username_entry_add.pack()

        tk.Label(self.master, text="Edit Service Password:", bg='#082245', fg='#FFFFFF').pack()
        self.password_entry_add = tk.Entry(self.master, width=TEXTBOX_WIDTH, bg='#1C2B44', fg='#FFFFFF')
        self.password_entry_add.insert(0, decrypted_password)
        self.password_entry_add.pack()

        # Update and Back buttons
        tk.Button(self.master, text="Update", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', 
                command=lambda: self.update_entry(record_id)).pack()
        tk.Button(self.master, text="Back", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', 
                command=self.view_passwords).pack(pady=10)

    def create_change_master_password_screen(self):
        self.clear_screen()

        # Load and display the logo
        self.load_image()
        self.display_image()

        # Current Master Password
        tk.Label(self.master, text="Current Master Password:", bg="#082245", fg="#FFFFFF").pack(pady=(5, 0))
        current_password_entry = tk.Entry(self.master, show="*", width=30, bg="#1C2B44", fg="#FFFFFF")
        current_password_entry.pack(pady=5)

        # New Master Password
        tk.Label(self.master, text="New Master Password:", bg="#082245", fg="#FFFFFF").pack(pady=(10, 0))
        new_password_entry = tk.Entry(self.master, show="*", width=30, bg="#1C2B44", fg="#FFFFFF")
        new_password_entry.pack(pady=5)

        # Confirm New Master Password
        tk.Label(self.master, text="Confirm New Master Password:", bg="#082245", fg="#FFFFFF").pack(pady=(10, 0))
        confirm_password_entry = tk.Entry(self.master, show="*", width=30, bg="#1C2B44", fg="#FFFFFF")
        confirm_password_entry.pack(pady=5)

        # Submit Button
        tk.Button(
            self.master,
            text="Submit",
            width=BUTTON_WIDTH,
            bg="#0A3A70",
            fg="#FFFFFF",
            command=lambda: self.change_master_password(
                current_password_entry.get(),
                new_password_entry.get(),
                confirm_password_entry.get(),
            ),
        ).pack(pady=(15, 5))

        # Back Button
        tk.Button(
            self.master,
            text="Back",
            width=BUTTON_WIDTH,
            bg="#0A3A70",
            fg="#FFFFFF",
            command=self.create_settings_screen,
        ).pack(pady=(5, 10))  # Adjusted padding to keep it visible

    def create_delete_account_screen(self):
        log_debug_message("Creating delete account screen.")
        self.clear_screen()

        # Load and display the logo
        self.load_image()
        self.display_image()

        # Master Password Field
        tk.Label(self.master, text="Master Password:", bg="#082245", fg="#FFFFFF").pack(pady=(5, 0))
        master_password_entry = tk.Entry(self.master, show="*", width=TEXTBOX_WIDTH, bg="#1C2B44", fg="#FFFFFF")
        master_password_entry.pack()

        # Confirm Master Password Field
        tk.Label(self.master, text="Confirm Master Password:", bg="#082245", fg="#FFFFFF").pack(pady=(10, 0))
        confirm_password_entry = tk.Entry(self.master, show="*", width=TEXTBOX_WIDTH, bg="#1C2B44", fg="#FFFFFF")
        confirm_password_entry.pack()

        # Buttons
        tk.Button(
            self.master,
            text="Delete",
            width=BUTTON_WIDTH,
            bg="#D9534F",
            fg="#FFFFFF",
            command=lambda: self.delete_account(master_password_entry.get(), confirm_password_entry.get()),
        ).pack(pady=(15, 5))

        tk.Button(
            self.master,
            text="Back",
            width=BUTTON_WIDTH,
            bg="#0A3A70",
            fg="#FFFFFF",
            command=self.create_settings_screen,
        ).pack(pady=(5, 10))

    def update_entry(self, record_id):
        new_service = self.service_entry.get().strip()
        new_service_username = self.username_entry_add.get().strip()
        new_password = self.password_entry_add.get()

        if new_service and new_service_username and new_password:
            try:
                fernet = Fernet(self.current_key)
                encrypted_password = fernet.encrypt(new_password.encode()).decode()

                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE passwords 
                    SET service = ?, service_username = ?, password = ? 
                    WHERE id = ?""",
                    (new_service, new_service_username, encrypted_password, record_id)
                )
                conn.commit()
                conn.close()
                
                log_debug_message(f"DEBUG: Entry ID {record_id} updated successfully.")
                messagebox.showinfo("Success", "Password updated successfully.")
                self.view_passwords()
            except Exception as e:
                log_debug_message(f"DEBUG: Error updating entry ID {record_id}: {e}")
                logging.error(f"Error updating entry: {e}")
                messagebox.showerror("Error", "Failed to update password.")

    def sign_up(self):
        username = self.username_entry.get().strip().capitalize()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if password != confirm_password:
            log_debug_message("DEBUG: Passwords do not match.")
            messagebox.showerror("Sign-Up Error", "Passwords do not match.")
            return

        key = Fernet.generate_key()  # Generate a key for encryption
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode()).decode()

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if the user already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                log_debug_message(f"DEBUG: User {username} already exists.")
                messagebox.showerror("Sign-Up Error", "User already exists.")
                return

            # Insert user into the database
            cursor.execute("INSERT INTO users (username, master_password) VALUES (?, ?)", (username, encrypted_password))
            conn.commit()

            # Store the key for password encryption
            key_path = os.path.join(KEYS_DIR, f"{username}.key")
            with open(key_path, 'wb') as key_file:
                key_file.write(key)

            log_debug_message(f"DEBUG: User {username} signed up successfully.")
            messagebox.showinfo("Sign-Up Success", "User signed up successfully.")
            self.create_login_screen()

        except sqlite3.Error as e:
            log_debug_message(f"DEBUG: SQLite error during sign-up: {e}")
            logging.error(f"SQLite error: {e}")
        except Exception as e:
            log_debug_message(f"DEBUG: Unexpected error during sign-up: {e}")
            logging.error(f"Unexpected error: {e}")
            logging.error(traceback.format_exc())
        finally:
            if conn:
                log_debug_message("DEBUG: Closing database connection.")
                conn.close()

    def log_in(self):
        log_debug_message("DEBUG: Attempting to log in.")
        username = self.username_entry.get().strip().capitalize()
        password = self.password_entry.get()

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if the user exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                encrypted_password = user[1]
                key_path = os.path.join(KEYS_DIR, f"{username}.key")

                # Check if key file exists
                if not os.path.exists(key_path):
                    log_debug_message(f"DEBUG: Key file for {username} does not exist.")
                    messagebox.showerror("Login Error", "Key file not found.")
                    return

                # Decrypt the stored password using the Fernet key
                with open(key_path, 'rb') as key_file:
                    key = key_file.read()

                fernet = Fernet(key)
                decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()

                # Validate the password
                if password == decrypted_password:
                    self.current_user = username
                    self.current_key = key
                    log_debug_message(f"DEBUG: User {username} logged in successfully.")
                    messagebox.showinfo("Login Success", f"Welcome, {username}!")
                    self.create_main_screen()
                else:
                    log_debug_message("DEBUG: Incorrect password.")
                    messagebox.showerror("Login Error", "Incorrect password.")
            else:
                log_debug_message(f"DEBUG: User {username} not found.")
                messagebox.showerror("Login Error", "User not found.")

        except sqlite3.Error as e:
            log_debug_message(f"DEBUG: SQLite error during login: {e}")
            logging.error(f"SQLite error: {e}")
        except Exception as e:
            log_debug_message(f"DEBUG: Unexpected error during login: {e}")
            logging.error(f"Unexpected error: {e}")
            logging.error(traceback.format_exc())
        finally:
            if conn:
                log_debug_message("DEBUG: Closing database connection.")
                conn.close()

    def view_passwords(self):
        log_debug_message("Starting to view passwords.")
        self.clear_screen()
        log_debug_message("Screen cleared for viewing passwords.")
        
        tk.Label(self.master, text="Your Saved Passwords", bg='#082245', fg='#FFFFFF').pack(pady=(10, 0))

        self.passwords_frame = tk.Frame(self.master, bg='#082245')
        self.passwords_frame.pack(expand=True, fill=tk.BOTH)

        self.load_passwords()  # Load and display the passwords
        
        tk.Button(self.master, text="Back", width=BUTTON_WIDTH, bg='#0A3A70', fg='#FFFFFF', command=self.create_main_screen).pack(pady=10)
        log_debug_message("Back button added to password view screen.")

    def load_passwords(self):
        try:
            # Log database path and current user for debugging
            log_debug_message(f"DEBUG: Database path: {self.db_path}")
            log_debug_message(f"DEBUG: Current user: {self.current_user}")
            
            # Connect to the database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Fetch passwords for the current user
            query = "SELECT id, service, service_username, password FROM passwords WHERE username = ?"
            cursor.execute(query, (self.current_user,))
            results = cursor.fetchall()
            conn.close()

            log_debug_message(f"DEBUG: Number of records fetched: {len(results)}")

            if not results:
                log_debug_message("DEBUG: No passwords found for the current user.")
                messagebox.showinfo("No Passwords", "You don't have any saved passwords.")
                return

            fernet = Fernet(self.current_key)
            log_debug_message("DEBUG: Fernet key initialized successfully.")

            for record_id, service, service_username, encrypted_password in results:
                try:
                    # Attempt to decrypt the password
                    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                except InvalidToken:
                    log_debug_message(f"DEBUG: Failed to decrypt password for service: {service}")
                    continue  # Skip this entry if decryption fails

                # Create a frame for each entry
                entry_frame = tk.Frame(self.passwords_frame, bg='#1C2B44')
                entry_frame.pack(fill=tk.X, pady=2)

                # Mouse hover effects
                entry_frame.bind("<Enter>", lambda e, frame=entry_frame: frame.config(bg='#3E5C77'))
                entry_frame.bind("<Leave>", lambda e, frame=entry_frame: frame.config(bg='#1C2B44'))

                # Display text
                display_text = f"Service: {service}\nUsername: {service_username}\nPassword: {decrypted_password}"
                entry_label = tk.Label(entry_frame, text=display_text, bg='#1C2B44', fg='#FFFFFF', anchor="w", justify="left")
                entry_label.pack(fill=tk.X, padx=10, pady=5)

                # Set up click to open edit screen
                entry_frame.bind("<Button-1>", lambda e, record_id=record_id: self.create_edit_entry_screen(record_id))
                entry_label.bind("<Button-1>", lambda e, record_id=record_id: self.create_edit_entry_screen(record_id))

        except sqlite3.OperationalError as e:
            # Log and handle SQLite-related errors
            log_debug_message(f"DEBUG: SQLite error: {e}")
            logging.error(f"SQLite error: {e}")
            messagebox.showerror("Database Error", "There was a problem accessing the database.")
        except InvalidToken as e:
            # Handle decryption errors specifically
            log_debug_message("DEBUG: Invalid encryption key detected.")
            logging.error(f"Encryption error: {e}")
            messagebox.showerror("Decryption Error", "Failed to decrypt stored passwords.")
        except Exception as e:
            # Catch-all for unexpected errors
            log_debug_message(f"DEBUG: Unexpected error: {e}")
            logging.error(f"Error loading passwords: {e}")
            logging.error(traceback.format_exc())
            messagebox.showerror("Error", "Failed to load passwords.")

    def save_password(self):
        log_debug_message("DEBUG: Saving password...")
        service = self.service_entry.get().strip()
        service_username = self.username_entry_add.get().strip()  # This is the service-specific username
        password = self.password_entry_add.get()

        if service and service_username and password:
            try:
                log_debug_message(f"DEBUG: Encrypting password for service: {service}")
                fernet = Fernet(self.current_key)
                encrypted_password = fernet.encrypt(password.encode()).decode()

                log_debug_message(f"DEBUG: Connecting to database: {self.db_path}")
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                log_debug_message(f"DEBUG: Inserting password into database for user: {self.current_user}")
                cursor.execute("INSERT INTO passwords (username, service, service_username, password) VALUES (?, ?, ?, ?)",
                               (self.current_user, service, service_username, encrypted_password))
                conn.commit()
                conn.close()
                log_debug_message("DEBUG: Password saved successfully.")

                messagebox.showinfo("Success", "Password saved successfully.")
                self.service_entry.delete(0, tk.END)
                self.username_entry_add.delete(0, tk.END)
                self.password_entry_add.delete(0, tk.END)
            except Exception as e:
                logging.error(f"Error saving password: {e}")
                log_debug_message(f"DEBUG: Error saving password: {e}")
                messagebox.showerror("Error", "Failed to save password.")

    def change_master_password(self, current_password, new_password, confirm_password):
        log_debug_message("DEBUG: Change password option selected.")

        try:
            # Step 1: Verify Current Master Password
            log_debug_message("DEBUG: Verifying current master password.")
            conn = sqlite3.connect(self.db_path)
            conn.isolation_level = "EXCLUSIVE"  # Enable transaction support
            cursor = conn.cursor()
            
            # Fetch the stored encrypted master password
            cursor.execute("SELECT master_password FROM users WHERE username = ?", (self.current_user,))
            result = cursor.fetchone()
            if not result:
                messagebox.showerror("Error", "User not found.")
                return
            
            encrypted_master_password = result[0]

            # Load the user's key to decrypt the current master password
            key_path = os.path.join(KEYS_DIR, f"{self.current_user}.key")
            if not os.path.exists(key_path):
                messagebox.showerror("Error", "Encryption key file not found.")
                return

            with open(key_path, "rb") as key_file:
                current_key = key_file.read()
            fernet = Fernet(current_key)

            try:
                decrypted_master_password = fernet.decrypt(encrypted_master_password.encode()).decode()
            except InvalidToken:
                messagebox.showerror("Error", "Failed to decrypt master password. Key mismatch or corrupted data.")
                return

            # Verify the entered current password
            if current_password != decrypted_master_password:
                messagebox.showerror("Error", "Current master password is incorrect.")
                return

            # Step 2: Validate New Password Inputs
            log_debug_message("DEBUG: Validating new password inputs.")
            if not new_password or not confirm_password:
                messagebox.showerror("Error", "New password fields cannot be empty.")
                return

            if new_password != confirm_password:
                messagebox.showerror("Error", "New passwords do not match.")
                return

            # Step 3: Generate New Encryption Key
            log_debug_message("DEBUG: Generating new encryption key.")
            new_key = Fernet.generate_key()
            new_fernet = Fernet(new_key)

            # Encrypt the new master password
            encrypted_new_password = new_fernet.encrypt(new_password.encode()).decode()

            # Step 4: Re-encrypt Stored Passwords
            log_debug_message("DEBUG: Re-encrypting passwords.")
            cursor.execute("SELECT id, password FROM passwords WHERE username = ?", (self.current_user,))
            passwords = cursor.fetchall()

            for record_id, encrypted_password in passwords:
                try:
                    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                    re_encrypted_password = new_fernet.encrypt(decrypted_password.encode()).decode()
                    cursor.execute(
                        "UPDATE passwords SET password = ? WHERE id = ?", 
                        (re_encrypted_password, record_id)
                    )
                except InvalidToken:
                    log_debug_message(f"DEBUG: Failed to decrypt password for record ID {record_id}. Skipping.")
                    continue

            # Step 5: Update the Master Password and Save the New Key
            log_debug_message("DEBUG: Updating master password and saving new encryption key.")
            cursor.execute(
                "UPDATE users SET master_password = ? WHERE username = ?", 
                (encrypted_new_password, self.current_user)
            )
            
            with open(key_path, "wb") as key_file:
                key_file.write(new_key)

            # Commit changes
            conn.commit()
            log_debug_message("DEBUG: Master password changed successfully.")
            messagebox.showinfo("Success", "Master password changed successfully!")

        except sqlite3.Error as e:
            conn.rollback()  # Roll back any changes
            log_debug_message(f"DEBUG: SQLite error during password change: {e}")
            messagebox.showerror("Error", "An error occurred while accessing the database.")
        except Exception as e:
            log_debug_message(f"DEBUG: Unexpected error during password change: {e}")
            messagebox.showerror("Error", "An unexpected error occurred.")
        finally:
            if conn:
                log_debug_message("DEBUG: Closing database connection.")
                conn.close()

    def delete_account(self, master_password, confirm_password):
        log_debug_message("DEBUG: Delete account option selected.")

        if master_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # Confirmation messagebox
        confirm = messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete your account? This action cannot be undone.")
        if not confirm:
            log_debug_message("DEBUG: User canceled account deletion.")
            return

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Step 1: Verify the Master Password
            log_debug_message("DEBUG: Verifying master password.")
            cursor.execute("SELECT master_password FROM users WHERE username = ?", (self.current_user,))
            result = cursor.fetchone()
            if not result:
                messagebox.showerror("Error", "User not found.")
                return

            encrypted_master_password = result[0]
            key_path = os.path.join(KEYS_DIR, f"{self.current_user}.key")
            if not os.path.exists(key_path):
                messagebox.showerror("Error", "Encryption key file not found.")
                return

            with open(key_path, "rb") as key_file:
                current_key = key_file.read()
            fernet = Fernet(current_key)

            try:
                decrypted_master_password = fernet.decrypt(encrypted_master_password.encode()).decode()
            except InvalidToken:
                messagebox.showerror("Error", "Incorrect master password.")
                return

            if master_password != decrypted_master_password:
                messagebox.showerror("Error", "Incorrect master password.")
                return

            # Step 2: Delete the User's Data
            log_debug_message("DEBUG: Deleting user data.")
            cursor.execute("DELETE FROM passwords WHERE username = ?", (self.current_user,))
            cursor.execute("DELETE FROM users WHERE username = ?", (self.current_user,))
            conn.commit()

            # Step 3: Delete the User's Key File
            log_debug_message("DEBUG: Deleting user's key file.")
            if os.path.exists(key_path):
                os.remove(key_path)

            # Step 4: Notify the User and Log Out
            log_debug_message(f"DEBUG: Account for user {self.current_user} deleted successfully.")
            messagebox.showinfo("Success", "Account deleted successfully!")
            self.current_user = None
            self.create_login_screen()

        except sqlite3.Error as e:
            conn.rollback()  # Roll back changes on failure
            log_debug_message(f"DEBUG: SQLite error during account deletion: {e}")
            messagebox.showerror("Error", "An error occurred while accessing the database.")
        except Exception as e:
            log_debug_message(f"DEBUG: Unexpected error during account deletion: {e}")
            messagebox.showerror("Error", "An unexpected error occurred.")
        finally:
            if conn:
                log_debug_message("DEBUG: Closing database connection.")
                conn.close()

    def clear_screen(self):
        log_debug_message("Clearing the screen of all widgets.")
        for widget in self.master.winfo_children():
            widget.destroy()
        log_debug_message("Screen cleared.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ECHO_Security(root)
    root.mainloop()