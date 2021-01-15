import sqlite3
conn = sqlite3.connect("NoteMe.db")
cursor = conn.cursor()

varchar(128) NOT NULL UNIQUE, password varchar(128) NOT NULL, first_name varchar(128) NOT NULL, last_name varchar(128) NOT NULL, active integer NOT NULL)")

cursor.execute("CREATE TABLE login_logs(id integer NOT NULL PRIMARY KEY AUTOINCREMENT, user_id varchar(128) NOT NULL, ip archer(15) NOT NULL, date varchar(26) NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id))")

cursor.execute("CREATE TABLE notes(id varchar(48) NOT NULL PRIMARY KEY, user_id varchar(128) NOT NULL, note_title varchar(128) NOT NULL, note_desc varchar(1024), note_type varchar(12) NOT NULL, note_salt varchar(128), note_iv varchar(128), FOREIGN KEY(user_id) REFERENCES users(id))")

cursor.execute("CREATE TABLE user_auth_tokens(id integer NOT NULL PRIMARY KEY AUTOINCREMENT, user_id varchar(128) NOT NULL, token varchar(48) NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id))")

