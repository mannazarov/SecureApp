### Инструкция по сборке и запуску приложения
> В этом разделе нужно описать пререквизиты и примеры запуска
#### Пререквизиты:
python
pip
flask
#### Пример запуска:
1) Переходим в директорию `VulnerableApp/App`.
2) Запускаем `main.py`. `python3 main.py`
3) Копируем `http://127.0.0.1:5000` и вставляем в браузер.

### Комментарии к исправлениям
> Основные идеи исправлений для реализованных уязвимостей нужно описать в этом разделе.  
> Будет большим плюсом, если:
> - Исправления оформлены в виде отдельных коммитов
> - В этом разделе имеется рассуждение/обоснование надёжности внесённых исправлений

### a. XSS
#### Причина уязвимости
Использование фильтра safe в шаблонах Jinja2 указывает на то, что HTML не должен экранироваться. Это означает, что если статус пользователя содержит HTML или JavaScript код, он будет отображаться как есть в браузере. Злоумышленник может использовать это, вставив вредоносные скрипты в свой статус, которые затем будут выполнены в браузере любого пользователя, просматривающего их профиль.

#### Как исправить
Для устранения этой уязвимости следует удалить фильтр safe, чтобы убедиться, что любой HTML или JavaScript в статусе будет должным образом экранирован и не выполнен браузером. Исправленная строка в шаблоне `user_profile.html` будет выглядеть так:

```
{% block content %}
    <h1>Welcome, {{ user[1] }}!</h1>
    <p>Role: {{ user[3] }}</p>
    <p>Secret: {{ user[-1] }}</p>
    <p>Status: {{ user[4] }}</p>
    <!-- Форма для изменения статуса -->
    <form method="POST" action="{{ url_for('set_status') }}">
        <input type="text" name="status" placeholder="Set your status">
        <button type="submit">Update Status</button>
    </form>
{% endblock %}
```

### b. IDOR
#### Причина Уязвимости
Уязвимость проявляется в функции user_profile, которая позволяет просматривать информацию о пользователях:
```
@app.route('/user/<username>')
def user_profile(username):
    if 'username' in session:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            return render_template('user_profile.html', user=user)
        else:
            abort(404)
    return redirect(url_for('login'))
```
Здесь проверяется только то, что пользователь вошел в систему ('username' in session), но не проверяется, соответствует ли запрашиваемый профиль текущему пользователю сессии. Это позволяет любому аутентифицированному пользователю просматривать или изменять информацию других пользователей, просто изменив имя пользователя в URL.

#### Как исправить
Чтобы устранить эту уязвимость, необходимо добавить проверку, что текущий пользователь сессии имеет право на доступ к запрашиваемому профилю. Вот как можно изменить код:

```
@app.route('/user/<username>')
def user_profile(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    if current_user != username:
        abort(403)  # Запрет доступа, если пользователь пытается получить доступ к чужому профилю

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if user:
        return render_template('user_profile.html', user=user)
    else:
        abort(404)

```
В этой версии сначала проверяется, аутентифицирован ли пользователь. Затем мы сравниваем имя пользователя в сессии с запрашиваемым именем пользователя. Если они не совпадают, доступ запрещается. Это гарантирует, что пользователи могут взаимодействовать только со своим собственным профилем, предотвращая несанкционированный доступ к данным других пользователей.

### c. SQLI

#### Уязвимость SQLi в функции login
#### Причина уязвимости:
Уязвимость находится в функции login, где пользовательский ввод (имя пользователя и пароль) используется напрямую в SQL запросе без предварительной обработки или использования параметризованных запросов:

```
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Уязвимый SQL запрос, который проверяет и имя пользователя, и пароль
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        db = get_db()
        user = db.execute(query).fetchone()

 ...
```

#### Как исправить:
Следует использовать параметризованные запросы для предотвращения SQL инъекций. Параметризованные запросы гарантируют, что переданные данные обрабатываются строго как данные, а не как часть SQL команды. Исправленный код:

```
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        db = get_db()
        user = db.execute(query, (username, password)).fetchone()

        ...

```


#### Уязвимость SQLi в функции index
#### Причина уязвимости:
Эта уязвимость находится в функции index, где категория выбирается из параметра запроса и вставляется напрямую в SQL запрос:
```
@app.route('/')
def index():
    category = request.args.get('category')
    db = get_db()

    if category:
        query = f"SELECT * FROM animals WHERE category = '{category}'"
        images = db.execute(query).fetchall()
        ...

```

#### Как исправить:
Следует также использовать параметризованные запросы для защиты от SQL инъекций. 
```
@app.route('/')
def index():
    category = request.args.get('category')
    db = get_db()

    if category:
        query = "SELECT * FROM animals WHERE category = ?"
        images = db.execute(query, (category,)).fetchall()
        ...

```

### d. OS command injection

#### Причина уязвимости:
Уязвимость возникает из-за того, что пользовательский ввод напрямую включается в команду, которая затем выполняется на сервере. 
```
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ""
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')

        # Уязвимое место: выполнение команды ping с пользовательским вводом
        result = os.popen(f'ping -c 4 {ip_address}').read()

    return render_template('ping.html', result=result)
```

Здесь ip_address берется напрямую из формы и вставляется в команду ping, которая выполняется на сервере. Если злоумышленник введет что-то вроде 127.0.0.1; malicious_command, то malicious_command также будет выполнена на сервере.

#### Как исправить:
Для предотвращения уязвимости OS Command Injection необходимо избегать прямого использования пользовательского ввода в системных командах. Вот несколько способов исправить эту уязвимость:

**Использование безопасных функций**: Вместо os.popen, стоит использовать более безопасные функции, такие как subprocess.run, которые позволяют более точно контролировать выполнение команд и их аргументы.

**Валидация входных данных**: Прежде чем использовать пользовательский ввод, убедитесь, что он соответствует ожидаемому формату (например, является действительным IP-адресом).


```
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
```

### e. Path Traversal
#### Причина уязвимости:
Уязвимость проявляется в функции load_image, которая используется для загрузки изображений:
```
@app.route('/loadImage')
def load_image():
    filename = request.args.get('filename')
    if filename:
        filepath = './static/images/' + filename
        return send_file(filepath)
    else:
        return 'Файл не найден', 404
```
Пользовательский ввод (имя файла) напрямую конкатенируется с базовым путем к папке с изображениями. Если злоумышленник подставит в имя файла относительные пути (например, `../`), он сможет получить доступ к файлам, которые находятся за пределами директории `./static/images/`.

#### Как исправить:
**Ограничение доступа к файлам**: Прежде всего, надо убедиться, что путь к файлу ограничивает доступ только к предназначенной папке с изображениями.

**Валидация входных данных**: Следует проверить, что имя файла не содержит недопустимых символов, таких как `../`, которые могут указывать на попытку path traversal.

**Использование безопасных функций**: Стоит использовать функции, предоставляемые фреймворком, для безопасного объединения путей.


```
import os
from werkzeug.utils import secure_filename

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

```

В этом коде `secure_filename` из `Werkzeug` используется для очистки имени файла, а `os.path.join` для безопасного создания полного пути к файлу. Также добавлена проверка существования файла и его типа, чтобы предотвратить отправку несуществующих или недопустимых файлов.

### f.  Brute force

...

### Дополнительные комментарии
> Опциональный раздел

...

