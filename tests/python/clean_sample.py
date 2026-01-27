from flask import Flask, request
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

@app.route("/")
def home():
    name = request.args.get("name", "")
    return f"<h1>Welcome {name}</h1>"

@app.route("/user")
def user():
    username = request.args.get("username")
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return str(result)

if __name__ == "__main__":
    app.run()
