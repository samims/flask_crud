from flask import Flask, render_template, flash, url_for, redirect, session, logging, request
#from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# config MySQL

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Dingdong'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MySQL

mysql = MySQL(app)

#Articles = Articles()


# home


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/articles')
def articles():
    # create cursor
    cur = mysql.connection.cursor()

    # Get Articles

    result = cur.execute("Select * from articles")
    articles = cur.fetchall()
    if result > 0:
        return render_template("articles.html", articles=articles)
    else:
        msg = "No articles Found"
        return render_template('articles.html', msg=msg)
    cur.close()


@app.route('/article/<string:id>/')
def article(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * from articles WHERE id = %s",[id])
    article = cur.fetchone()
    cur.close()

    return render_template('article.html', article=article)


# RegisterForm class
class RegisterForm(Form):
    name = StringField('Name', [validators.length(min=1, max=50)])
    username = StringField('Username', [validators.length(min=4, max=25)])
    email = StringField('Email', [validators.length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')


# Registration


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # create cursor
        cur = mysql.connection.cursor()

        cur.execute(
            "INSERT INTO users(name,email,username,password) VALUES (%s, %s, %s, %s)",
            (name, email, username, password)
        )

        mysql.connection.commit()
        cur.close()

        flash('You are now registered', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # form fill up
        username = request.form['username']
        password_candidate = request.form['password']

        # create cursor
        cur = mysql.connection.cursor()

        # create user by user name
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # check password is true or not
            if sha256_crypt.verify(password_candidate, password):
                # app.logger.info('Password Matched')
                # passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are Logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Login'
                # app.logger.info('Please enter correct password')
                return render_template('login.html', error=error)
            cur.close()
        else:
            error = 'Username Not found'
            return render_template('login.html', error=error)
    return render_template('login.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))

    return wrap


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged Out', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@is_logged_in
def dashboard():
    # create cursor
    cur = mysql.connection.cursor()

    # Get Articles

    result = cur.execute("Select * from articles")
    articles = cur.fetchall()
    if result >0:
        return render_template("dashboard.html", articles=articles)
    else:
        msg = "No articles Found"
        return render_template('dashboard.html', msg=msg)
    cur.close()


# Article form class
class ArticleForm(Form):
    title = StringField('Title', [validators.length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])


# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # create cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO articles(title, body,author) VALUES(%s, %s, %s)", (title, body, session['username']))

        # commit
        mysql.connection.commit()

        # close connection
        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
