from pony import orm
from datetime import datetime
import feedparser
from flask import Flask, render_template, request, redirect, url_for, flash
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

db = orm.Database()
db.bind('sqlite', 'fbdb.sqlite', create_db=True)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'TcAnhkN0z4F2loeqVA8IHw6Hw5iU10n1bgxcigeZdk27sMRm8oGlrw5EUENgd8vo'
bootstrap = Bootstrap(app)
moment = Moment(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Feed(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    articles = orm.Set('Article')
    categories = orm.Set('Category')
    title = orm.Required(str)
    url = orm.Required(str, unique=True)
    etag = orm.Optional(str)
    modified = orm.Optional(str)

class Article(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    feed = orm.Required('Feed')
    author = orm.Optional('Author')
    title = orm.Required(str)
    url = orm.Required(str, unique=True)
    read = orm.Optional(bool, default=False)
    published = orm.Required(datetime)
    summary = orm.Optional(str)

class Category(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    title = orm.Required(str, unique=True)
    feeds = orm.Set('Feed')

class Author(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    name = orm.Required(str, unique=True)
    articles = orm.Set('Article')

class User(UserMixin, db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    username = orm.Required(str, unique=True)
    password_hash = orm.Required(str, unique=True)

db.generate_mapping(create_tables=True)

@orm.db_session
def add_category(title):
    exists = Category.get(title=title)
    if exists:
        return exists.id
    else:
        new_category = Category(title=title)
        orm.commit()
        return new_category.id

@orm.db_session
def add_author(name):
    exists=Author.get(name=name)
    if exists:
        return exists.id
    else:
        new_author = Author(name=name)
        orm.commit()
        return new_author.id

@orm.db_session
def fetch_feed(id):
    feed = Feed[id]
    p = feedparser.parse(feed.url, etag=feed.etag, modified=feed.modified)
    feed.etag = p.etag if 'etag' in p else ''
    feed.modified = p.modified if 'modified' in p else ''
    for e in p.entries if 'entries' in p else []:
        author = Author[add_author(e.author.title())] if 'author' in e and e.author else Author[add_author('None')]
        title = e.title if 'title' in e else ''
        url = e.link if 'link' in e else feed.url
        published = datetime(*e.published_parsed[:6]) if 'published_parsed' in e else datetime.utcnow()
        summary = strip_summary(e.summary) if 'summary' in e else ''
        a = Article.get(url=url)
        if a:
            if a.published != published:
                a.feed = feed
                a.author = author
                a.title = title
                a.published = published
                a.summary = summary
        else:
            new_article = Article(feed=feed, author=author, title=title, url=url, published=published, summary=summary)

def strip_summary(summary):
    soup = BeautifulSoup(summary, 'html.parser')
    text = soup.find_all(text=True)
    stripped = ''.join(list(filter(visible, text)))
    return stripped[:300] + '...' if stripped else ''

def visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta']:
        return False
    elif isinstance(element, Comment):
        return False
    return True

@login_manager.user_loader
@orm.db_session
def load_user(user_id):
    return User.get(id=user_id)

@orm.db_session
def add_user(username, password):
    exists=User.get()
    if exists:
        return False
    else:
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash)
        orm.commit()
        return new_user

@app.context_processor
@orm.db_session
def nav_variables():
    feeds = list(Feed.select())
    uncategorized = list(Feed.select(lambda u: not u.categories))
    categories = list(Category.select())
    users = list(User.select())
    username = users[0].username if users else ''
    return dict(nav_feeds=feeds, nav_uncategorized=uncategorized, nav_categories=categories, username=username)

@app.route('/register', methods=['GET', 'POST'])
@orm.db_session
def register():
    next = get_redirect_target()
    if len(list(User.select())) > 0:
        return redirect(next)
    else:
        if request.method == 'POST':
            if not request.values['username'] or not request.values['password']:
                flash('Username and Password are both required')
            else:
                new_user = add_user(request.values['username'], request.values['password'])
                if new_user:
                    flash('New user {} successfully registered'.format(new_user.username))
                    remember = 'remember_me' in request.values
                    login_user(new_user, remember=remember)
                    flash('Login Successful!')
                    return redirect(url_for('settings'))
                else:
                    flash('Warning: failed to register user')

        return render_template('register.html', next=next)

@app.route('/login', methods=['GET', 'POST'])
@orm.db_session
def login():
    next = get_redirect_target()
    if len(list(User.select())) == 0:
        return redirect(url_for('register', next=next))
    else:
        if request.method == 'POST':
            if not request.values['username'] or not request.values['password']:
                flash('Username and Password are both required')
            else:
                user = User.get(username=request.values['username'])
                password = request.values['password']
                if user and password and check_password_hash(user.password_hash, password):
                    remember = 'remember_me' in request.values
                    login_user(user, remember=remember)
                    flash('Login Successful!')
                else:
                    flash('Incorrect Username or Password')

            return redirect(next)

        return render_template('login.html', next=next)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(get_redirect_target())

@app.route('/edit_user', methods=['POST'])
@orm.db_session
@login_required
def edit_user():
    next = get_redirect_target()
    if 'username' in request.values:
        user = list(User.select())[0]
        user.username = request.values['username']
    elif 'password' in request.values:
        user = list(User.select())[0]
        user.password_hash = generate_password_hash(request.values['password'])
    elif 'delete' in request.values:
        logout_user()
        for user in User.select():
            user.delete()
        for category in Category.select():
            category.delete()
        for article in Article.select():
            article.delete()
        for feed in Feed.select():
            feed.delete()

    return redirect(next)

@app.route('/settings')
@orm.db_session
@login_required
def settings():
    return render_template('settings.html')

@app.route('/')
@orm.db_session
@login_required
def display():
    try:
        if not 'entity' in request.values:
            articles = list(Article.select().order_by(orm.desc(Article.published)))
            return render_template('display.html', type='all_feeds', articles=articles)
        elif request.values['entity'] == 'category' and 'id' not in request.values:
            articles = list(orm.select(a for a in Article if not a.feed.categories).order_by(orm.desc(Article.published)))
            return render_template('display.html', type='uncategorized', articles=articles)
        elif valid_entity() and request.values['entity'] == 'category':
            category = Category[request.values['id']]
            articles = list(orm.select(a for a in Article if a.feed in category.feeds).order_by(orm.desc(Article.published)))
            return render_template('display.html', type='category', category=category, articles=articles)
        elif valid_entity() and request.values['entity'] == 'feed':
            feed = Feed[request.values['id']]
            articles = list(orm.select(a for a in Article if a.feed is feed).order_by(orm.desc(Article.published)))
            return render_template('display.html', type='feed', feed=feed, articles=articles)
    except orm.ObjectNotFound:
        missing_entitiy()

    if not valid_entity():
        flash('Warning: Invalid Feed/Category')

    return redirect(get_redirect_target())

@app.route('/add', methods=['POST'])
@orm.db_session
@login_required
def add_entity():
    if request.values['entity'] == 'feed' and request.values['url']:
        url = request.values['url']
        if not Feed.get(url=url):
            p = feedparser.parse(url)
            title = p.feed.title if 'title' in p.feed else url
            new_feed = Feed(title=title, url=url)
            [new_feed.categories.add(Category[c]) for c in list(request.values.getlist('category'))]
    elif request.values['entity'] == 'category' and request.values['category']:
        title = request.values['category']
        if not Category.get(title=title):
            new_category = Category(title=title)
            [new_category.feeds.add(Feed[f]) for f in list(request.values.getlist('feed'))]

    return redirect(url_for('settings'))

@app.route('/del')
@orm.db_session
@login_required
def del_entity():
    if valid_entity():
        try:
            if request.values['entity'] == 'feed':
                Feed[request.values['id']].delete()
            elif request.values['entity'] == 'category':
                Category[request.values['id']].delete()
            flash('Sucess!')
        except orm.ObjectNotFound:
            missing_entitiy()

    return redirect(url_for('settings'))

@app.route('/edit', methods=['POST', 'GET'])
@orm.db_session
@login_required
def edit_entity():
    if not valid_entity():
        flash('Warning: Invalid Edit Parameter(s)')
    try:
        if request.method == 'GET':
            if request.values['entity'] == 'feed':
                feed=Feed[request.values['id']]
                other_categories = list(orm.select(c for c in Category if c not in feed.categories))
                return render_template('edit.html', feed=feed, other_categories=other_categories)

            elif request.values['entity'] == 'category':
                category = Category[request.values['id']]
                other_feeds = list(orm.select(f for f in Feed if f not in category.feeds))
                return render_template('edit.html', category=category, other_feeds=other_feeds)

        elif request.method =='POST':
            if request.values['submit'] == 'delete':
                return redirect(url_for('del_entity', entity=request.values['entity'], id=request.values['id']))

            elif request.values['submit'] == 'save' and request.values['entity'] == 'feed':
                feed = Feed[request.values['id']]
                feed.title = request.values['title']
                feed.url = request.values['url']
                feed.categories.clear()
                [feed.categories.add(Category[c]) for c in list(request.values.getlist('category'))]
                flash('Success!')

            elif request.values['submit'] == 'save' and request.values['entity'] == 'category':
                category = Category[request.values['id']]
                category.title = request.values['title']
                category.feeds.clear()
                [category.feeds.add(Feed[f]) for f in list(request.values.getlist('feed'))]
                flash('Success')

            else:
                flash('Warning: Improper Edit Submission')

    except orm.ObjectNotFound:
        missing_entitiy()

    return redirect(url_for('settings'))

@app.route('/fetch')
@orm.db_session
@login_required
def fetch_entity():
    try:
        if not 'entity' in request.values:
            for feed_id in orm.select(f.id for f in Feed):
                fetch_feed(feed_id)
        elif request.values['entity'] == 'category' and 'id' not in request.values:
            for feed in orm.select(f for f in Feed if not f.categories):
                fetch_feed(feed.id)
        elif valid_entity() and request.values['entity'] == 'category':
            for feed in Category[request.values['id']].feeds:
                fetch_feed(feed.id)
        elif valid_entity() and request.values['entity'] == 'feed':
            fetch_feed(request.values['id'])
        else:
            flash('Warning: Failed Fetch')

    except orm.ObjectNotFound:
        missing_entitiy()

    return redirect(get_redirect_target())

@app.errorhandler(404)
@orm.db_session
def page_not_found(e):
    print(e)
    return render_template('error.html'), 404

@app.errorhandler(500)
@orm.db_session
def internal_server_error(e):
    print(e)
    return render_template('error.html'), 500

def is_safe_url(target):
    ref_url = urlparse(url_for('display', _external=True))
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def get_redirect_target(default='display'):
    for target in request.values.get('next'), request.referrer, url_for(default):
        if not target:
            continue
        if is_safe_url(target):
            return target

def missing_entitiy():
    try:
        flash('Warning: Could not find {} with id {}'.format(request.values['entity'], request.values['id']))
    except (KeyError):
        flash('Warning: Invalid Request Type')

def valid_entity():
    try:
        return int(request.values['id']) >= 0 and request.values['entity'] in ['feed', 'category']
    except (ValueError, KeyError):
        return False
