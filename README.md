from flask import Flask, request, jsonify, session 
import sqlite3 
import bcrypt 

app = Flask(__name__) 
app.secret_key = 'supersecretkey'  # Note: Use a more secure key in production 

DATABASE = 'users.db' 

# Initialize the database 
def init_db(): 
    with sqlite3.connect(DATABASE) as conn: 
        cursor = conn.cursor() 
        cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                           username TEXT UNIQUE, 
                           password TEXT)''') 
        conn.commit() 

init_db() 

@app.route('/register', methods=['POST']) 
def register(): 
    username = request.form['username'] 
    password = request.form['password'] 
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) 

    with sqlite3.connect(DATABASE) as conn: 
        cursor = conn.cursor() 
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                       (username, hashed_pw)) 
        conn.commit() 

    return jsonify({'message': 'User registered successfully'}), 201 

@app.route('/login', methods=['POST']) 
def login(): 
    username = request.form['username'] 
    password = request.form['password'] 

    with sqlite3.connect(DATABASE) as conn: 
        cursor = conn.cursor() 
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,)) 
        result = cursor.fetchone() 

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0]): 
            session['user'] = username 
            return jsonify({'message': 'Login successful'}), 200 
        else: 
            return jsonify({'message': 'Invalid credentials'}), 401 

@app.route('/logout', methods=['POST']) 
def logout(): 
    session.pop('user', None) 
    return jsonify({'message': 'Logout successful'}), 200 

if __name__ == '__main__': 
    app.run(debug=True) 
