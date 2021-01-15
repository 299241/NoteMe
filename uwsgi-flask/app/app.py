import os, redis, uuid, hashlib, math
from time import sleep
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.sql import exists
from flask_wtf.csrf import CSRFProtect

from passlib.hash import bcrypt
from Crypto.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

SESSION_SECRET_KEY = "SESSION_SECRET_KEY"
USER_ID = "user_id"
LOGIN_ATTEMPTS = "login_attempts"
LOGIN_BLOCKED = "login_blocked"
TOKEN_EXPIRATION_TIME = 180

path = os.getcwd()
UPLOAD_FOLDER = os.path.join(path, 'app/uploads')

if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

app = Flask(__name__, static_url_path="")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///NoteMe.db'

csrf = CSRFProtect(app)

db = SQLAlchemy(app)
db_redis = redis.Redis(host="redis-db", port=6379, decode_responses=True)

app.secret_key = os.environ.get(SESSION_SECRET_KEY)
app.permanent_session_lifetime = TOKEN_EXPIRATION_TIME


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(128), primary_key=True)
    email = db.Column(db.String(128), unique=True)
    password = db.Column(db.String(128))
    first_name = db.Column(db.String(128))
    last_name = db.Column(db.String(128))
    active = db.Column(db.Integer)
    login_logs = relationship("LoginLog")
    notes = relationship("Note")
    shared_notes = relationship("SharedNote")

class LoginLog(db.Model):
    __tablename__ = "login_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey("users.id"))
    ip = db.Column(db.String(15))
    date = db.Column(db.String(26))

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.String(48), primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey("users.id")) 
    note_title = db.Column(db.String(128))
    note_desc = db.Column(db.String(1024))
    note_type = db.Column(db.String(12))
    note_salt = db.Column(db.String(128))
    note_iv = db.Column(db.String(128))
    shared_notes = db.relationship("SharedNote")
    files = db.relationship("File")

class UserAuthToken(db.Model):
    __tablename__ = "user_auth_tokens"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey("users.id")) 
    token = db.Column(db.String(48))

class SharedNote(db.Model):
    __tablename__ = "shared_notes"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey("users.id"))
    note_id = db.Column(db.String, db.ForeignKey("notes.id"))

class File(db.Model):
    __tablename__ = "files"
    id = db.Column(db.String(48), primary_key=True)
    note_id = db.Column(db.String, db.ForeignKey("notes.id"))
    filename = db.Column(db.String(512))
    

def authorization_required(fun):
    @wraps(fun)
    def authorization_decorator(*args, **kwds):
        if USER_ID not in session:
            return redirect(url_for("login"))

        return fun(*args, **kwds)

    return authorization_decorator


def valid_input(value):
    if "SELECT" in value:
        return False
    if "--\'" in value:
        return False
    if "\'--" in value:
        return False
    if "--" in value:
        return False
    if "innerHTML" in value:
        return False
    
    return value


def entropy(d):
   stat={}
   for c in d:
       m=c
       if m in stat:
           stat[m] +=1
       else:
           stat[m]=1
   H=0.0
   for i in stat.keys():
       pi=stat[i]/len(d)
       H -=pi*math.log2(pi)
   return H


def logs_sort(v):
    return v.id


@app.after_request
def after_request_func(response):
    response.headers['Content-Security-Policy']= "default-src \'self\' \'unsafe-inline\' w3.org';font-src \'self\' fonts.gstatic.com fontawesome.com;style-src \'self\' fonts.googleapis.com *.fontawesome.com \'unsafe-inline\' ;script-src \'self\' cdnjs.cloudflare.com;object-src \'self\';img-src \'self\' w3.org "
    return response


@app.route("/", methods=["GET"])
@authorization_required
def home():
    user_id = session[USER_ID]
    login_logs = LoginLog.query.filter(LoginLog.user_id == user_id).all()
    login_logs.sort(key=logs_sort, reverse=True)
    user_first_name = User.query.filter(User.id == user_id).first().first_name
    user_last_name = User.query.filter(User.id == user_id).first().last_name
    email = User.query.filter(User.id == user_id).first().email

    user_emails = [user.email for user in User.query.all()]
    user_emails.remove(email)

    return render_template("dashboard.html", alert_type=request.args.get("alert_type"), alert_msg=request.args.get("alert_msg"),
        login_logs=login_logs, user_emails=user_emails, user_first_name=user_first_name, user_last_name = user_last_name)


@app.route("/login", methods=["GET", "POST"])
def login():
    if USER_ID in session:
        return redirect(url_for("home"))
    
    if request.method == "GET":
        session_expired = request.args.get("session_expired")
        if session_expired:
            alert_type = "danger"
            alert_msg = "Twoja sesja wygasła. Zaloguj się ponownie, aby kontynuować."
            return render_template("login.html", alert_type=alert_type, alert_msg=alert_msg)
        else:
            return render_template("login.html", alert_type=request.args.get("alert_type"), alert_msg=request.args.get("alert_msg"))
    else:
        user_id = hashlib.sha3_512(request.form["email"].encode("utf-8")).hexdigest()
        password = request.form["password"]

        user_ip = str(request.environ['REMOTE_ADDR'])
        user_blocked_time = db_redis.hget(LOGIN_BLOCKED + user_id, user_ip)

        if user_blocked_time != None:
            if datetime.strptime(user_blocked_time, "%d/%m/%Y %H:%M:%S") > datetime.now():
                alert_type = "danger"
                alert_msg = "Przekroczono liczbę prób logowania. Konto zostało tymczasowo zablokowane."
                return render_template("login.html", alert_type=alert_type, alert_msg=alert_msg)
            else:
                db_redis.hdel(LOGIN_ATTEMPTS + user_id, user_ip)
                db_redis.hdel(LOGIN_BLOCKED + user_id, user_ip)
 
        if db_redis.hget(LOGIN_ATTEMPTS + user_id, user_ip) == None:
            login_attempts = 0
        else:
            login_attempts = int(db_redis.hget(LOGIN_ATTEMPTS + user_id, user_ip))

        sleep(2 + 2 * login_attempts)
            
        if (db.session.query(User.query.filter(User.id == user_id).exists()).scalar()):
            if (User.query.filter(User.id == user_id).first().active == 0):
                alert_type = "danger"
                alert_msg = "Twoje konto nie zostało jeszcze aktywowane. Link nie dotarł? Kliknij "
                alert_link = "https://localhost/token/resend/" + user_id
                return render_template("login.html", alert_type=alert_type, alert_msg=alert_msg, alert_link=alert_link)

            if (bcrypt.verify(password, User.query.filter(User.id == user_id).first().password)):
                if user_id == hashlib.sha3_512("admin@note.me".encode("utf-8")).hexdigest():
                    app.logger.debug((datetime.now() + timedelta(hours=1)).strftime("%d/%m/%Y %H:%M:%S") + " | Próba logowania na konto typu honypots z adresu IP: " + user_ip)
                    abort(403)

                session[USER_ID] = user_id
                session.permanent = True

                if (db.session.query(LoginLog.query.filter(LoginLog.ip == user_ip).exists()).scalar()) == False:
                    app.logger.debug((datetime.now() + timedelta(hours=1)).strftime("%d/%m/%Y %H:%M:%S") + " | Nowa próba dostępu do konta z adresu IP: " + user_ip)

                login_log = LoginLog(user_id=user_id, ip=user_ip, date=(datetime.now() + timedelta(hours=1)).strftime("%d/%m/%Y %H:%M:%S"))
                db.session.add(login_log)
                db.session.commit()
                
                response = make_response(redirect(url_for('home')))
                return response
            else:
                db_redis.hset(LOGIN_ATTEMPTS + user_id, user_ip, login_attempts + 1)
                if (login_attempts + 1) == 5:
                    db_redis.hset(LOGIN_BLOCKED + user_id, user_ip, (datetime.now() + timedelta(minutes=5)).strftime("%d/%m/%Y %H:%M:%S"))
                alert_type = "danger"
                alert_msg = "Nieprawidłowy adres e-mail lub/i hasło."
                return render_template("login.html", alert_type=alert_type, alert_msg=alert_msg)
        else:
            db_redis.hset(LOGIN_ATTEMPTS + user_id, user_ip, login_attempts + 1)
            if (login_attempts + 1) == 5:
                db_redis.hset(LOGIN_BLOCKED + user_id, user_ip, (datetime.now() + timedelta(minutes=5)).strftime("%d/%m/%Y %H:%M:%S"))
            alert_type = "danger"
            alert_msg = "Nieprawidłowy adres e-mail lub/i hasło."
            return render_template("login.html", alert_type=alert_type, alert_msg=alert_msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    if USER_ID in session:
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("register.html", alert_type=request.args.get("alert_type"), alert_msg=request.args.get("alert_msg"))
    
    else:
        first_name = valid_input(request.form["first-name"])
        last_name = valid_input(request.form["last-name"])
        email = valid_input(request.form["email"])
        password = valid_input(request.form["password"])

        if (first_name and last_name and email and password):
            user_id = hashlib.sha3_512(request.form["email"].encode("utf-8")).hexdigest()

            if(db.session.query(User.query.filter(User.id == user_id).exists()).scalar()):
                if (User.query.filter(User.id == user_id).first().active == 0):
                    alert_type = "danger"
                    alert_msg = "Twoje konto nie zostało jeszcze aktywowane. Link nie dotarł? Kliknij "
                    alert_link = "https://localhost/token/resend/" + user_id
                    return render_template("login.html", alert_type=alert_type, alert_msg=alert_msg, alert_link=alert_link)
                
                alert_type = "danger"
                alert_msg = "Nie można utworzyć konta dla podanego adresu e-mail."
                return render_template("register.html", alert_type=alert_type, alert_msg=alert_msg)
            else:
                if len(password) < 8:
                    alert_type = "danger"
                    alert_msg = "Zbyt krótkie hasło. Musi mieć conajmniej 8 znaków."
                    return render_template("register.html", alert_type=alert_type, alert_msg=alert_msg)
                if entropy(password) < 2:
                    alert_type = "danger"
                    alert_msg = "Zbyt słabe hasło. Użyj np. małych i wielkich liter, cyfry oraz znaki specjalne."
                    return render_template("register.html", alert_type=alert_type, alert_msg=alert_msg)
                
                password_hash = bcrypt.hash(password)
                new_user = User(id=user_id, email=email, password=password_hash, first_name=first_name, last_name=last_name, active=0)
                db.session.add(new_user)
                db.session.commit()

                token = str(uuid.uuid4())
                user_auth_token = UserAuthToken(user_id=user_id, token=token)
                db.session.add(user_auth_token)
                db.session.commit()
                app.logger.debug((datetime.now() + timedelta(hours=1)).strftime("%d/%m/%Y %H:%M:%S") + " | Link aktywacyjny: https://localhost/token/" + token)

                alert_type = "success"
                alert_msg = "Rejestracja przebiegła pomyślnie. Użyj linku z maila, aby aktywować konto."
                return render_template("register.html", alert_type=alert_type, alert_msg=alert_msg)

        else:
            alert_type = "danger"
            alert_msg = "Wprowadzone dane zawierają zabronione elementy."
            return render_template("register.html", alert_type=alert_type, alert_msg=alert_msg)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if USER_ID in session:
        return redirect(url_for("home"))
    
    if request.method == "GET":
        return render_template("forgot-password.html")
    else:
        email = valid_input(request.form["email"])
        if email:
            if (db.session.query(User.query.filter(User.email == email).exists()).scalar()):
                user_id = hashlib.sha3_512(email.encode("utf-8")).hexdigest()
                token = str(uuid.uuid4())
                user_auth_token = UserAuthToken(user_id=user_id, token=token)
                db.session.add(user_auth_token)
                db.session.commit()
                app.logger.debug((datetime.now() + timedelta(hours=1)).strftime("%d/%m/%Y %H:%M:%S") + " | Link do resetu hasła: https://localhost/token/" + token)
            else:
                abort(401)
        else:
            abort(401)


@app.route("/notes", methods=["GET"])
@authorization_required
def notes():
    user_id = session[USER_ID]
    user_first_name = User.query.filter(User.id == user_id).first().first_name
    user_last_name = User.query.filter(User.id == user_id).first().last_name
    notes = Note.query.filter(Note.user_id == user_id).all()
    files = File.query.all()
    notes_1 = []
    notes_2 = []
    notes_3 = []

    l = len(notes)
    c = 0
    while c < l:
        if c % 3 == 1:
            note = notes[c]
            notes_2.append(notes[c])
        elif c % 3 == 2:
            notes_3.append(notes[c])
        else:
            notes_1.append(notes[c])
        c = c + 1

    return render_template("notes.html", alert_type=request.args.get("alert_type"), alert_msg=request.args.get("alert_msg"),
        notes_1=notes_1, notes_2=notes_2, notes_3=notes_3, files=files, user_first_name=user_first_name, user_last_name = user_last_name)

@app.route("/notes/files/<id>", methods=["GET"])
@authorization_required
def notes_files(id):
    file = File.query.filter(File.id == id).first()
    file_ext = os.path.splitext(file.filename)[1]
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.id + file_ext)

    return send_file(filepath, attachment_filename=file.id + file_ext)


@app.route("/secret-note", methods=["POST"])
@authorization_required
def secret_note():
    user_id = session[USER_ID]
    user_first_name = User.query.filter(User.id == user_id).first().first_name
    user_last_name = User.query.filter(User.id == user_id).first().last_name
    files = File.query.all()

    note_id = valid_input(request.form["note-id"])
    note_secret_pass = valid_input(request.form["secret-password"])

    if (note_id and note_secret_pass):
        note = Note.query.filter(Note.id == note_id).first()

        try:
            key = PBKDF2(note_secret_pass.encode("utf-8"), note.note_salt)
            iv = b64decode(note.note_iv)
            encrypted = b64decode(note.note_desc)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            note_desc = str(decrypted)
            
            return render_template("secret-note.html", alert_type=request.args.get("alert_type"), note_title=note.note_title, note_desc=note_desc,
                files=files, user_first_name=user_first_name, user_last_name = user_last_name)

        except:
            abort(401)

    else:
        alert_type = "danger"
        alert_msg = "Wprowadzone hasło zawiera zabronione elementy."
        response = make_response(redirect(url_for("notes", alert_type=alert_type, alert_msg=alert_msg)))
        return response


@app.route("/shared-with-me", methods=["GET"])
@authorization_required
def shared_with_me():
    user_id = session[USER_ID]
    user_first_name = User.query.filter(User.id == user_id).first().first_name
    user_last_name = User.query.filter(User.id == user_id).first().last_name
    files = File.query.all()
    notes_ids = [note.note_id for note in SharedNote.query.filter(SharedNote.user_id == user_id).all()]
    notes = []
    
    for note_id in notes_ids:
        notes.append(Note.query.filter(Note.id == note_id).first())

    notes_1 = []
    notes_2 = []
    notes_3 = []

    l = len(notes)
    c = 0
    while c < l:
        if c % 3 == 1:
            notes_2.append(notes[c])
        elif c % 3 == 2:
            notes_3.append(notes[c])
        else:
            notes_1.append(notes[c])
        c = c + 1


    return render_template("shared-with-me.html", notes_1=notes_1, notes_2=notes_2, notes_3=notes_3,
        files=files, user_first_name=user_first_name, user_last_name = user_last_name)


@app.route("/public-notes", methods=["GET"])
@authorization_required
def public_notes():
    user_id = session[USER_ID]
    user_first_name = User.query.filter(User.id == user_id).first().first_name
    user_last_name = User.query.filter(User.id == user_id).first().last_name
    files = File.query.all()
    notes = Note.query.filter(Note.note_type == "public-note").all()
    notes_1 = []
    notes_2 = []
    notes_3 = []

    l = len(notes)
    c = 0
    while c < l:
        if c % 3 == 1:
            notes_2.append(notes[c])
        elif c % 3 == 2:
            notes_3.append(notes[c])
        else:
            notes_1.append(notes[c])
        c = c + 1


    return render_template("public-notes.html", notes_1=notes_1, notes_2=notes_2, notes_3=notes_3,
        files=files, user_first_name=user_first_name, user_last_name = user_last_name)


@app.route("/logout", methods=["GET"])
@authorization_required
def logout():
    alert_type = "success"
    alert_msg = "Nastąpiło wylogowanie z serwisu."
    session.clear()
    response = make_response(redirect(url_for("login", alert_type=alert_type, alert_msg=alert_msg)))
    return response


@app.route("/add-note", methods=["POST"])
@authorization_required
def add_note():
    note_title = valid_input(request.form["title"])
    note_desc = valid_input(request.form["description"])
    note_type = valid_input(request.form["type"])
    note_secret_pass = valid_input(request.form["secret-password"])
    shared_with = request.form.getlist("shared-with")

    if (note_title and note_desc and note_type):
        id = str(uuid.uuid4())
        user_id = session[USER_ID]

        if (note_type == "private-note" or note_type == "public-note"):
            new_note = Note(id=id, user_id=user_id, note_title=note_title, note_desc=note_desc, note_type=note_type)
            db.session.add(new_note)
            db.session.commit()
        elif (note_type == "encrypt-note"):
            note_salt = get_random_bytes(16)
            note_data = note_desc.encode("utf-8")
            key = PBKDF2(note_secret_pass.encode("utf-8"), note_salt)
            cipher = AES.new(key, AES.MODE_CBC)
            encrypted_bytes = cipher.encrypt(pad(note_data, AES.block_size))
            note_iv = b64encode(cipher.iv).decode('utf-8')
            encrypted = b64encode(encrypted_bytes).decode('utf-8')

            new_note = Note(id=id, user_id=user_id, note_title=note_title, note_desc=encrypted, note_type=note_type, note_salt=note_salt, note_iv=note_iv)
            db.session.add(new_note)
            db.session.commit()
        elif (note_type == "shared-note"):
            new_note = Note(id=id, user_id=user_id, note_title=note_title, note_desc=note_desc, note_type=note_type)
            db.session.add(new_note)
            db.session.commit()

            for user in shared_with:
                user_hash = hashlib.sha3_512(user.encode("utf-8")).hexdigest()
                new_shared_note = SharedNote(user_id=user_hash, note_id=id)
                db.session.add(new_shared_note)
            db.session.commit()

        if "files[]" in request.files:
            files = request.files.getlist("files[]")
            for file in files:
                if file:
                    file_id = str(uuid.uuid4())

                    file_ext = os.path.splitext(file.filename)[1]
                    file.save(os.path.join(app.config["UPLOAD_FOLDER"], file_id + file_ext))

                    new_file = File(id=file_id, note_id=id, filename=file.filename)
                    db.session.add(new_file)
                    db.session.commit()
            
        alert_type = "success"
        alert_msg = "Pomyślnie dodano nową notatkę."
        response = make_response(redirect(url_for("notes", alert_type=alert_type, alert_msg=alert_msg)))
        return response

    else:
        alert_type = "danger"
        alert_msg = "Wprowadzone dane zawierają zabronione elementy lub są niepoprawne."
        response = make_response(redirect(url_for("home", alert_type=alert_type, alert_msg=alert_msg)))
        return response


@app.route("/token/<token>", methods=["GET"])
def token_auth(token):
    if USER_ID in session:
        return redirect(url_for("home"))

    auth_status = (db.session.query(UserAuthToken.query.filter(UserAuthToken.token == token).exists()).scalar())

    if auth_status:
        user_id = UserAuthToken.query.filter(UserAuthToken.token == token).first().user_id
        active = User.query.filter(User.id == user_id).first().active
        if active == 0:
            user = User.query.filter(User.id == user_id).first()
            user.active = 1
            db.session.commit()

            token_to_del = UserAuthToken.query.filter(UserAuthToken.token == token).first()
            db.session.delete(token_to_del)
            db.session.commit()

            alert_type = "success"
            alert_msg = "Twoje konto zostało aktywowane."
            response = make_response(redirect(url_for("login", alert_type=alert_type, alert_msg=alert_msg)))
            return response
        else:
            app.logger.debug("TODO!")
    else:
        alert_type = "danger"
        alert_msg = "Ten link jest niepoprawny lub wygasł."
        response = make_response(redirect(url_for("register", alert_type=alert_type, alert_msg=alert_msg)))
        return response


@app.route("/token/resend/<user_id>", methods=["GET"])
def token_resend(user_id):
    if USER_ID in session:
        return redirect(url_for("home"))

    user_exists = (db.session.query(User.query.filter(User.id == user_id).exists()).scalar())

    if user_exists:
        token_exists = (db.session.query(UserAuthToken.query.filter(UserAuthToken.user_id == user_id).exists()).scalar())
        
        if token_exists:
            token = UserAuthToken.query.filter(UserAuthToken.user_id == user_id).first().token
            app.logger.debug((datetime.now() + timedelta(hours=1)).strftime("%d/%m/%Y %H:%M:%S") + " | Link aktywacyjny: https://localhost/token/" + token)

            alert_type = "success"
            alert_msg = "Wysłano ponownie link aktywacyjny."
            response = make_response(redirect(url_for('register', alert_type=alert_type, alert_msg=alert_msg)))
            return response
        else:
            abort(401)
    else:
        abort(401)


@app.errorhandler(400)
def bad_request(error):
    return render_template("400.html", error=error)


@app.errorhandler(401)
def page_unauthorized(error):
    return render_template("401.html", error=error)

@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html", error=error)

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html", error=error)

