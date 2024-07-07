import sqlite3
import os
import bcrypt
from cryptography.fernet import Fernet

# Absolute path to the database
absolute_path = "/Users/pranavkapoor/password_manager.db"
print("Database path:", absolute_path)

# Function to create tables if they don't exist
def ensure_tables_exist():
    connection = sqlite3.connect(absolute_path)
    cursor = connection.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        password_id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        website TEXT NOT NULL,
        encrypted_password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
    ''')
    connection.commit()
    connection.close()

# Function to hash a password
def hash_password(password):
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password with the generated salt
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

# Function to check if a provided password matches the stored hash
def check_password(hashed_password, password):
    # Check if the provided password matches the hashed password
    return bcrypt.checkpw(password.encode(), hashed_password)

# Function to create a new user
def create_user(username, password):
    hashed_password = hash_password(password)
    connection = sqlite3.connect(absolute_path)
    cursor = connection.cursor()
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
    connection.commit()
    connection.close()

# Function to authenticate a user
def authenticate_user(username, password):
    connection = sqlite3.connect(absolute_path)
    cursor = connection.cursor()
    cursor.execute("SELECT user_id, password_hash FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    connection.close()
    if result:
        user_id, stored_hash = result
        if check_password(stored_hash.encode('utf-8'), password):
            return True, user_id
    return False, None

# Function to create a password entry
def create_password_entry(user_id, website, password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    connection = sqlite3.connect(absolute_path)
    cursor = connection.cursor()
    cursor.execute("INSERT INTO passwords (user_id, website, encrypted_password) VALUES (?, ?, ?)", (user_id, website, encrypted_password.decode()))
    connection.commit()
    connection.close()

# Function to read password entries
def read_password_entries(user_id, key):
    connection = sqlite3.connect(absolute_path)
    cursor = connection.cursor()
    cursor.execute("SELECT password_id, website, encrypted_password FROM passwords WHERE user_id=?", (user_id,))
    entries = cursor.fetchall()
    connection.close()
    cipher_suite = Fernet(key)
    decrypted_entries = [(pid, website, cipher_suite.decrypt(encrypted_password.encode()).decode()) for pid, website, encrypted_password in entries]
    return decrypted_entries

# Function to update a password entry
def update_password_entry(password_id, new_password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(new_password.encode())
    connection = sqlite3.connect(absolute_path)
    cursor = connection.cursor()
    cursor.execute("UPDATE passwords SET encrypted_password=? WHERE password_id=?", (encrypted_password.decode(), password_id))
    connection.commit()
    connection.close()

# Function to delete a password entry
def delete_password_entry(password_id):
    connection = sqlite3.connect(absolute_path)
    cursor = connection.cursor()
    cursor.execute("DELETE FROM passwords WHERE password_id=?", (password_id,))
    connection.commit()
    connection.close()

# Main script
if __name__ == "__main__":
    try:
        # Ensure tables exist
        ensure_tables_exist()

        # Create a new user
        create_user('user1', 'mysecretpassword')

        # Authenticate the user
        authenticated, user_id = authenticate_user('user1', 'mysecretpassword')
        if authenticated:
            print("User authenticated successfully.")

            # Generate a key for encryption
            key = Fernet.generate_key()

            # Create a password entry
            website = 'example.com'
            password = 'mypassword'
            create_password_entry(user_id, website, password, key)

            # Read password entries
            entries = read_password_entries(user_id, key)
            for pid, website, decrypted_password in entries:
                print(f"Password ID: {pid}, Website: {website}, Password: {decrypted_password}")

            # Update a password entry
            new_password = 'newpassword'
            password_id = entries[0][0]  # Using the first password entry ID for update
            update_password_entry(password_id, new_password, key)

            # Delete a password entry
            delete_password_entry(password_id)
        else:
            print("Authentication failed.")
    except sqlite3.Error as error:
        print("SQLite error:", error)
    except Exception as error:
        print("Error:", error)
