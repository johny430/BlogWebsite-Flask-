from flask_login import login_user, login_required, logout_user, current_user, LoginManager, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from flask import Flask, render_template, request, url_for, redirect,  session, request, flash,g
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = '12313123123qwdqwcxascqasd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)

class User (db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_articles = db.relationship('Article', backref='user', lazy=True)
    user_comments = db.relationship('Comments', backref='user', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.id

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(30),nullable=False)
    text = db.Column(db.Text,nullable=False)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    article_comments = db.relationship('Comments', backref='article', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.id

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text,nullable=False)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_username = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.id

@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def index():
    a = current_user.get_id()
    articles = Article.query.order_by(Article.date).all()
    return render_template('index.html', articles=articles,user=a)

@app.route('/allarticles')
def allarticles():
    a = current_user.get_id()
    articles = Article.query.order_by(Article.date).all()
    return render_template('allarticles.html', articles=articles, user=a)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    a = current_user.get_id()
    if not a == None:
        flash('Вы уже вошли')
        return redirect(url_for('createarticle'))
    elif request.method == 'POST':
        login = request.form.get('username')
        password = request.form.get('password')
        if login and password:
            user = User.query.filter_by(login=login).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                flash('Вы успешно вошли!')
                return redirect(url_for('index'))
            else:
                flash('Неверно введен логин или пароль!')
                return render_template('singin.html', user=a)
        else:
            flash('Введите логин и пароль')
            return render_template('singin.html', user=a)

    else:
        return render_template('singin.html', user=a)

@app.route('/register', methods=['GET', 'POST'])
def register():
    a = current_user.get_id()
    if not a == None:
        flash('Вы уже вошли')
        return redirect(url_for('createarticle'))
    elif request.method == 'POST':
        login = request.form.get('username')
        password = request.form.get('password')
        print(password + login)
        user = User.query.filter_by(login=login).first()
        if not user == None:
            flash('Никнейм занят!Выберите другой!')
            return render_template('register.html', user=a)
        if login == "" or password == "":
            flash('Введите логин и пароль!')
            return render_template('register.html', user=a)
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация прошла успешно!Теперь ввойдите в аккаунт!')
            return redirect(url_for('login_page'))
    else:
        return render_template('register.html', user=a)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('Вы вышли из аккаунта!')
    return redirect(url_for('index'))

@app.route('/article/<int:id>/delete')
@login_required
def delete(id):
    articl = Article.query.filter_by(id=id).first()
    a = current_user.get_id()
    if articl == None:
        flash('Такой статьи не существует!')
        return redirect(url_for('createarticle'))
    else:
        if int(articl.user_id) == int(a):
            try:
                db.session.delete(articl)
                db.session.commit()
                flash('Удалено успешно!')
                return redirect(url_for('createarticle'))
            except:
                flash('Что-то пошло не так!')
                return redirect(url_for('createarticle'))
        else:
            flash('Это не ваша статья!')
            return redirect(url_for('createarticle'))

@app.route('/comment/<int:id>/delete')
@login_required
def deletecomment(id):
    articl = Comments.query.filter_by(id=id).first()
    a = current_user.get_id()
    if articl == None:
        flash('Такого комментария не существует!')
        return redirect(url_for('createarticle'))
    else:
        if int(articl.user_id) == int(a):
            try:
                db.session.delete(articl)
                db.session.commit()
                flash('Удалено успешно!')
                return redirect(url_for('createarticle'))
            except:
                flash('Что-то пошло не так!')
                return redirect(url_for('createarticle'))
        else:
            flash('Это не ваша комментарий!')
            return redirect(url_for('createarticle'))

@app.route('/article/<int:id>/change',methods=['GET', 'POST'])
@login_required
def change(id):
    articl = Article.query.filter_by(id=id).first()
    a = current_user.get_id()
    if articl == None:
        flash('Такой статьи не существует!')
        return redirect(url_for('createarticle'))
    else:
        if int(articl.user_id) == int(a):
            if request.method == 'POST':
                articl.title = request.form.get('title')
                articl.text = request.form.get('text')
                try:
                    db.session.commit()
                    flash('Изменено успешно!')
                    return redirect(url_for('createarticle'))
                except:
                    flash('Что-то пошло не так!')
                    return redirect(url_for('createarticle'))
            else:
                return render_template('changearticle.html', articles=articl)
        else:
            flash('Это не ваша статья!')
            return redirect(url_for('createarticle'))

@app.route('/comment/<int:id>/change',methods=['GET', 'POST'])
@login_required
def changecomment(id):
    articl = Comments.query.filter_by(id=id).first()
    a = current_user.get_id()
    if articl == None:
        flash('Такого комментария не существует!')
        return redirect(url_for('createarticle'))
    else:
        if int(articl.user_id) == int(a):
            if request.method == 'POST':
                articl.text = request.form.get('text')
                try:
                    db.session.commit()
                    flash('Изменено успешно!')
                    return redirect(url_for('createarticle'))
                except:
                    flash('Что-то пошло не так!')
                    return redirect(url_for('createarticle'))
            else:
                return render_template('changearticle2.html', articles=articl)
        else:
            flash('Это не ваш комментарий!')
            return redirect(url_for('createarticle'))

@app.route('/createarticle', methods=['GET', 'POST'])
@login_required
def createarticle():
    a = current_user.get_id()
    us_art = Article.query.filter_by(user_id=a).all()
    us_com = Comments.query.filter_by(user_id=a).all()
    if request.method == 'POST':
        title = request.form.get('title')
        text = request.form.get('text')
        print(title)
        article = Article(title=title, text=text, user_id=a)
        db.session.add(article)
        db.session.commit()
        flash('Статья создана успешно!')
        return redirect(url_for('createarticle'))
    else:
        return render_template ('createarticle.html', articles=us_art, comments=us_com)

@app.route('/article/<int:id>', methods=['GET', 'POST'])
def article(id):
    a = current_user.get_id()
    user = User.query.filter_by(id=a).first()
    art_com = Comments.query.filter_by(article_id=id).all()
    articles = Article.query.filter_by(id=id).first()
    if articles == None:
        return render_template('articlenone.html')
    else:
        author = User.query.filter_by(id=articles.user_id).first()

        if request.method == 'POST':
            text = request.form.get('text')
            comment = Comments(text=text, user_id=a,article_id=id,user_username=user.login)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('article', id=id))
        else:
            return render_template('article.html',articles=articles,comments=art_com,author=author,user=user)

@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response

@app.after_request
def add_header(response):
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response

if __name__ == '__main__':
    app.run(debug=1)