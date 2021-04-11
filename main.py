from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os
import random
from tkinter import *
from tkinter import messagebox as messagebox
from hashlib import sha512
import sqlite3
chunks = 32 * 1024
admin_password_hash = ""

def encrypt(key, filename):
    out_file_name = os.path.basename(filename)
    out_file_name = "encrypted-" + out_file_name.split("-")[-1]
    file_size = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)
    encryptor = AES.new(key, AES.MODE_CFB, IV)
    with open(filename, "rb") as f_input:
        with open(out_file_name, "wb") as f_output:
            f_output.write(file_size.encode("utf-8"))
            f_output.write(IV)
            while True:
                chunk = f_input.read(chunks)
                if len(chunk) == 0:
                    break
                if len(chunk) % 16 != 0:
                    chunk += b" " * (16 - (len(chunk) % 16))
                f_output.write(encryptor.encrypt(chunk))


def decrypt(key, filename):
    out_file_name = "decrypted-" + filename.split("-")[-1]
    with open(filename, "rb") as f_input:
        filesize = int(f_input.read(16))
        IV = f_input.read(16)
        decryptor = AES.new(key, AES.MODE_CFB, IV)
        with open(out_file_name, "wb") as f_output:
            while True:
                chunk = f_input.read(chunks)
                if len(chunk) == 0:
                    break
                f_output.write(decryptor.decrypt(chunk))
                f_output.truncate(filesize)


def get_key(password):
    hashing = SHA256.new(password.encode("utf-8"))
    return hashing.digest()


def create_password():
    x = ["q", "w", "e", "r", "t", "z", "u", "i", "o", "p", "a", "s", "d", "f", "g", "h", 'j', 'k', 'l', 'y', 'x', 'c',
         'v', 'b', 'n', 'm', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'ß', '!', '§', '$', '%', '&', '/', '(',
         ')', '=', '?', 'Q', 'W', 'E', 'R', 'P', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Y', 'X', 'C', 'V', 'B',
         'N', 'M']

    password = ""
    for word in range(20):
        password += random.choice(x)
    password_entry.delete(0, END)
    password_entry.insert(0, password)


def check_password():
    global pw
    global admin_password_hash
    try:
        pw = input_entry.get()
        decrypt(get_key(sha512(input_entry.get().encode('utf-8')).hexdigest()), "encrypted-Passwords.db")
        connection = sqlite3.connect("decrypted-Passwords.db")  # open connection
        cursor = connection.cursor()  # create cursor
        cursor.execute("SELECT * FROM admin")
        admin_password_hash_list = cursor.fetchall()
        for hash in admin_password_hash_list[0]:
            admin_password_hash = hash
        connection.commit()  # commit data
        connection.close()
    except:
        return
    if sha512(input_entry.get().encode('utf-8')).hexdigest() == admin_password_hash:
        open_manager()
        input_entry.delete(0, END)
    else:
        input_entry.delete(0, END)
        return


def open_manager():
    global passwords
    global add_Login
    global delete_entry
    passwords = Toplevel()
    passwords.title("Password Manager")
    passwords.geometry("400x600")
    read_logins()
    add_logins()
    delete_label = Label(passwords, text="Delete Login with ID ")
    delete_label.grid(row=5, column=0, padx=5, pady=(50, 0), sticky="w")
    delete_entry = Entry(passwords, width=30)
    delete_entry.grid(row=5, column=1, padx=5, pady=(50, 0), sticky="w", columnspan=3)
    delete_one_login_button = Button(passwords, text="delete", command=delete_one_login)
    delete_one_login_button.grid(row=5, column=2, padx=(90, 5), pady=(50, 0), sticky="w")
    delete_all_logins_button = Button(passwords, text="Delete all Logins", command=warning)
    delete_all_logins_button.grid(row=6, column=0, padx=5, pady=(50, 0), sticky="w")


def refresh_manager():
    passwords.destroy()
    open_manager()


def add_logins():
    global login_entry
    global login_label
    global email_entry
    global email_label
    global password_entry
    global password_label
    global submit_button
    login_label = Label(passwords, text="Login")
    login_label.grid(row=1, column=0, padx=5, pady=(50, 0), sticky="w", columnspan=3)
    login_entry = Entry(passwords, width=30)
    login_entry.grid(row=1, column=1, padx=5, pady=(50, 0), sticky="w", columnspan=3)
    email_label = Label(passwords, text="Email")
    email_label.grid(row=2, column=0, padx=5, pady=5, sticky="w", columnspan=3)
    email_entry = Entry(passwords, width=30)
    email_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w", columnspan=3)
    password_label = Label(passwords, text="Password")
    password_label.grid(row=3, column=0, padx=5, pady=5, sticky="w", columnspan=3)
    password_entry = Entry(passwords, width=30, show="*")
    password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w", columnspan=3)
    create_password_button = Button(passwords, text="random", command=create_password)
    create_password_button.grid(row=3, column=2, padx=(90, 0), pady=5, sticky="w", columnspan=3)
    submit_button = Button(passwords, text="Submit", width=15, command=submit_logins)
    submit_button.grid(row=4, column=1, padx=5, pady=5, sticky="w")


def submit_logins():
    connection = sqlite3.connect("decrypted-Passwords.db")  # open connection
    cursor = connection.cursor()  # create cursor
    cursor.execute("INSERT INTO passwords VALUES (:login_entry, :email_entry, :password_entry)",
                   {
                       "login_entry": login_entry.get(),
                       "email_entry": email_entry.get(),
                       "password_entry": password_entry.get()
                   })
    connection.commit()  # commit data
    connection.close()  # close connection
    login_entry.delete(0, END)
    email_entry.delete(0, END)
    password_entry.delete(0, END)
    read_logins()


def read_logins():
    connection = sqlite3.connect("decrypted-Passwords.db")  # open connection
    cursor = connection.cursor()  # create cursor
    cursor.execute("SELECT *, oid FROM passwords")
    records = cursor.fetchall()
    # print(records)
    print_id = ""
    print_logins = ""
    print_emails = ""
    print_passwords = ""
    for record in records:
        print_id += str(record[3]) + "\n"
        print_logins += str(record[0] + "\n")
        print_emails += str(record[1] + "\n")
        print_passwords += str(record[2] + "\n")

    id_label = Label(passwords, text="ID\n" + print_id, justify=LEFT)
    id_label.grid(row=0, column=0, sticky="w", padx=0)
    logins_label = Label(passwords, text="Logins\n" + print_logins, justify=LEFT)
    logins_label.grid(row=0, column=1, sticky="w", padx=5)
    emails_label = Label(passwords, text="Emails\n" + print_emails, justify=LEFT, width=30)
    emails_label.grid(row=0, column=2, sticky="w", padx=0)
    passwords_label = Label(passwords, text="Passwords\n" + print_passwords, justify=LEFT)
    passwords_label.grid(row=0, column=3, sticky="w", padx=0)

    connection.commit()  # commit data
    connection.close()  # close connection


def delete_one_login():
    connection = sqlite3.connect("decrypted-Passwords.db")  # open connection
    cursor = connection.cursor()  # create cursor
    cursor.execute("DELETE FROM passwords WHERE oid = " + delete_entry.get())
    delete_entry.delete(0, END)
    connection.commit()  # commit data
    connection.close()  # close connection
    refresh_manager()


def delete_all_logins():
    connection = sqlite3.connect("decrypted-Passwords.db")  # open connection
    cursor = connection.cursor()  # create cursor
    cursor.execute("DROP TABLE passwords")
    cursor.execute("""CREATE TABLE passwords (
        login text,
        email text,
        password text
    )""")
    connection.commit()  # commit data
    connection.close()  # close connection
    refresh_manager()


def warning():
    response = messagebox.askquestion("Warning", "This is the last confirmation\nAre you sure to delete all passwords?")
    if response == "yes":
        delete_all_logins()
    else:
        return


def new_admin_password():
    connection = sqlite3.connect("decrypted-Passwords.db")  # open connection
    cursor = connection.cursor()  # create cursor
    cursor.execute("INSERT INTO admin VALUES (:input_entry)",
                   {
                       "input_entry": sha512(input_entry.get().encode('utf-8')).hexdigest()
                   })
    connection.commit()  # commit data
    connection.close()  # close connection


# Database
#connection = sqlite3.connect("Passwords.db")  # open connection
#cursor = connection.cursor()  # create cursor


# Create the tables
#cursor.execute("""CREATE TABLE passwords (
#    login text,
#    email text,
#   password text
# )""")

#Create the tables
#cursor.execute("""CREATE TABLE admin (
#    password text
#)""")

#connection.commit()  # commit data
#connection.close()

# Window


login = Tk()
login.geometry("400x250")
login.title("Login")

input_entry = Entry(login, width=30, show="*")
input_entry.grid(padx=5, pady=5, sticky="w")
enter_password_button = Button(login, text="Enter Password", command=check_password)
enter_password_button.grid(padx=5, sticky="w")

login.mainloop()
if sha512(pw.encode('utf-8')).hexdigest() == admin_password_hash:
    os.remove("encrypted-Passwords.db")
    encrypt(get_key(admin_password_hash), "decrypted-Passwords.db")
os.remove("decrypted-Passwords.db")
