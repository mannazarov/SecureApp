import sqlite3

# Создание новой базы данных SQLite
conn = sqlite3.connect('database.db')

# Удаление существующих таблиц для чистой установки
conn.execute('DROP TABLE IF EXISTS users')
conn.execute('DROP TABLE IF EXISTS animals')

# Создание таблицы пользователей
conn.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT,
    status TEXT,
    secret TEXT
);
''')

# Добавление пользователей
users = [
    ('admin', '1223', 'admin', 'cool status', 'c92c0babdc764d8674bcea14a55d867d'),
    ('user1', '3241', 'user', 'cool status', 'ef39fbf69170b58787ce4e574db9d842'),
    ('user2', '5232', 'user', 'cool status', '3ab1faad513e753501264a716622ba06'),
    ('user3', '5133', 'user', 'cool status', '3ab1faad513e753501264a716622ba06'),
    ('user4', '5554', 'user', 'cool status', '3ab1faad513e753501264a716622ba06'),
]

conn.executemany('INSERT INTO users (username, password, role, status, secret) VALUES (?, ?, ?, ?, ?)', users)

# Создание таблицы животных
conn.execute('''
CREATE TABLE animals (
    animal_id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    image_path TEXT NOT NULL,
    description TEXT
);
''')

# Добавление животных
animals = [
    ('cat', 'cat1', 'cat1.jpg', 'cat description1'),
    ('cat', 'cat2', 'cat2.jpg', 'cat description2'),
    ('cat', 'cat3', 'cat3.jpg', 'cat description3'),
    ('cat', 'cat4', 'cat4.jpg', 'cat description4'),
    ('dog', 'dog1', 'dog1.jpg', 'dog description1'),
    ('dog', 'dog2', 'dog2.jpg', 'dog description2'),
    ('dog', 'dog3', 'dog3.jpg', 'dog description3'),
    ('dog', 'dog4', 'dog4.jpg', 'dog description4'),
    ('rabbit', 'rabbit1', 'rabbit1.jpg', 'rabbit description1'),
    ('rabbit', 'rabbit2', 'rabbit2.jpg', 'rabbit description2'),
    ('rabbit', 'rabbit3', 'rabbit3.jpg', 'rabbit description3'),
    ('rabbit', 'rabbit4', 'rabbit4.jpg', 'rabbit description4'),
    ('hamster', 'hamster1', 'hamster1.jpg', 'hamster description1'),
    ('hamster', 'hamster2', 'hamster2.jpg', 'hamster description2'),
    ('hamster', 'hamster3', 'hamster3.jpg', 'hamster description3'),
    ('hamster', 'hamster4', 'hamster4.jpg', 'hamster description4'),
]

conn.executemany('INSERT INTO animals (category, name, image_path, description) VALUES (?, ?, ?, ?)', animals)

# Сохранение изменений и закрытие соединения с базой данных
conn.commit()
conn.close()

