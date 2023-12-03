import hashlib
import re
import subprocess

from flask import Flask, render_template, request, redirect, url_for, session, g, abort, send_file, flash
import sqlite3
import os

from werkzeug.utils import secure_filename

#exec(open('db_maker.py').read())

app = Flask(__name__)
DATABASE = 'database.db'

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'database.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if len(password) < 8 or not re.match(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)', password):
            flash('Пароль должен быть не менее 8 символов и включать цифры, заглавные и строчные буквы, а также специальные символы.')
            return redirect(url_for('register'))

        sha256 = hashlib.sha256()
        data = username + password
        sha256.update(data.encode('utf-8'))
        secret = sha256.hexdigest()

        db = get_db()
        db.execute('INSERT INTO users (username, password, role, secret) VALUES (?, ?, ?, ?)',
                   (username, password, 'user', secret))
        db.commit()
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        db = get_db()
        user = db.execute(query, (username, password)).fetchone()

        if user:
            session['username'] = user[1]
            return redirect(url_for('user_profile', username=user[1]))
        else:
            flash('Invalid credentials, please try again.')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/user/<username>')
def user_profile(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    if current_user != username:
        abort(403)

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if user:
        return render_template('user_profile.html', user=user)
    else:
        abort(404)


@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ""
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')

        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip_address):
            result = subprocess.run(['ping', '-c', '4', ip_address], capture_output=True, text=True).stdout
        else:
            result = "Неверный формат IP адреса."

    return render_template('ping.html', result=result)


@app.route('/loadImage')
def load_image():
    filename = request.args.get('filename')
    if filename:
        secure_name = secure_filename(filename)

        filepath = os.path.join(app.root_path, 'static', 'images', secure_name)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            return send_file(filepath)
        else:
            return 'Файл не найден', 404
    else:
        return 'Файл не найден', 404


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/set_status', methods=['POST'])
def set_status():
    if 'username' not in session:
        return redirect(url_for('login'))

    status = request.form.get('status', '')
    username = session['username']

    db = get_db()
    db.execute('UPDATE users SET status = ? WHERE username = ?', (status, username))
    db.commit()

    return redirect(url_for('user_profile', username=username))


@app.route('/')
def index():
    category = request.args.get('category')
    db = get_db()

    if category:
        query = "SELECT * FROM animals WHERE category = ?"
        images = db.execute(query, (category,)).fetchall()
    else:
        images = db.execute('SELECT * FROM animals LIMIT 4').fetchall()

    return render_template('index.html', images=images, selected_category=category)


if __name__ == '__main__':
    app.run()
