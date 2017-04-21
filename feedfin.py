from pony import orm
from datetime import datetime, timedelta
import feedparser
from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment, Doctype
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from concurrent.futures import ProcessPoolExecutor, as_completed
import listparser
from email.utils import format_datetime
from lxml import etree
import requests
import uuid
import os
import certifi

db = orm.Database()
db.bind('sqlite', 'fbdb.sqlite', create_db=True)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'TcAnhkN0z4F2loeqVA8IHw6Hw5iU10n1bgxcigeZdk27sMRm8oGlrw5EUENgd8vo'
bootstrap = Bootstrap(app)
moment = Moment(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
cert_location = certifi.where()

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
    author = orm.Optional(str)
    title = orm.Required(str)
    url = orm.Required(str, unique=True)
    read = orm.Optional(bool, default=False)
    published = orm.Required(datetime)
    summary = orm.Optional(str)
    image = orm.Optional(str)

    def before_delete(self):
        if self.image:
            os.remove(os.path.abspath('static/' + self.image))


class Category(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    title = orm.Required(str, unique=True)
    feeds = orm.Set('Feed')

class User(UserMixin, db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    username = orm.Required(str, unique=True)
    password_hash = orm.Required(str, unique=True)
    page_length = orm.Required(int, default=50)

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

def fetch_feed(url, feed_id, etag='', modified=''):
    parsed = feedparser.parse(url, etag=etag, modified=modified)
    return {
        'id': feed_id,
        'etag': parsed.etag if 'etag' in parsed else '',
        'modified': parsed.modified if 'modified' in parsed else '',
        'entries': parsed.entries if 'entries' in parsed else []
    }


def parse_entry(entry, feed_id, url, published):
    author = entry['author'].title() if 'author' in entry else ''
    title = entry.title if 'title' in entry else ''
    summary = strip_summary(entry.summary) if 'summary' in entry else ''
    image = find_image(entry)

    return {
        'id': feed_id,
        'author': author,
        'title': title,
        'url': url,
        'published': published,
        'summary': summary,
        'image': image
    }


def strip_summary(summary):
    soup = BeautifulSoup(summary, 'lxml')
    text = soup.find_all(text=True)
    stripped = ' '.join(list(filter(visible, text)))
    if len(stripped) > 300:
        return stripped[:300] + '...'
    elif stripped:
        return stripped
    else:
        return ''


def visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta']:
        return False
    elif isinstance(element, (Comment, Doctype)):
        return False
    elif element.string == '\n':
        return False
    elif 'href' in element.parent.attrs and bad_url(element.parent['href']):
        return False
    return True


def bad_url(url):
    sites = ['projectwonderful.com']
    for site in sites:
        if site in url:
            return True
    return False


def find_image(entry):
    image = ''
    if 'media_content' in entry and 'url' in entry['media_content'][0]:
        image = entry['media_content'][0]['url']
    else:
        if 'content' in entry and 'value' in entry['content'][0]:
            image = parse_image(entry['content'][0]['value'])
        if not image and 'summary' in entry:
            image = parse_image(entry['summary'])

    if image:
        parts = urlparse(image)
        if allowed_file_name(parts.path):
            if not parts.netloc:
                parent = urlparse(entry['link'])
                parent_url = parent.scheme + '://' + parent.netloc
                image = urljoin(parent_url, parts.path)

            r = requests.get(image, verify=cert_location)
            if allowed_file_type(r.headers.get('content-type')):
                file_id = str(uuid.uuid4())
                file_ext = urlparse(image).path.rsplit('.', 1)[1]
                file_name = 'img/' + file_id + '.' + file_ext
                with open(os.path.abspath('static/' + file_name), 'wb') as f:
                    f.write(r.content)
                return file_name

    return ''


def parse_image(html):
    soup = BeautifulSoup(html, 'lxml')
    images = soup.find_all('img')
    for image in images:
        if ((
                image.find_parent('div')
                and 'class' in image.find_parent('div').attrs
                and 'feedflare' in image.find_parent('div')['class']
        ) or (
            'src' in image.attrs
            and bad_url(image['src'])
        )):
            continue
        elif 'src' in image.attrs:
            return image['src']

    return ''



@login_manager.user_loader
@orm.db_session
def load_user(user_id):
    return User.get(id=user_id)

@orm.db_session
def add_user(username, password):
    exists = User.get()
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
    feeds = list(Feed.select().order_by(Feed.title))
    uncategorized = list(Feed.select(lambda u: not u.categories).order_by(Feed.title))
    categories = list(Category.select().order_by(Category.title))
    return dict(nav_feeds=feeds, nav_uncategorized=uncategorized, nav_categories=categories)

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
    elif 'page_length' in request.values:
        user = list(User.select())[0]
        user.page_length = int(request.values['page_length'])
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
    users = list(User.select())
    user = users[0] if users else ''
    return render_template('settings.html', user=user)

@app.route('/')
@orm.db_session
@login_required
def display():
    try:
        page_length = list(u.page_length for u in User.select())[0]
        entity, id, page_number = parse_entity()
        if entity == 'feed' and id == -1:
            articles = list(Article.select().order_by(orm.desc(Article.published)).page(page_number, pagesize=page_length))
            page_title = 'Everything'
        elif entity == 'feed' and id > -1:
            feed = Feed[id]
            articles = list(orm.select(a for a in Article if a.feed is feed).order_by(orm.desc(Article.published)).page(page_number, pagesize=page_length))
            page_title = feed.title
        elif entity == 'category' and id == -1:
            articles = list(orm.select(a for a in Article if not a.feed.categories).order_by(orm.desc(Article.published)).page(page_number, pagesize=page_length))
            page_title = 'Uncategorized'
        elif entity == 'category' and id > -1:
            category = Category[id]
            articles = list(orm.select(a for a in Article if a.feed in category.feeds).order_by(orm.desc(Article.published)).page(page_number, pagesize=page_length))
            page_title = category.title
        return render_template('display.html', articles=articles, page=page_number, page_title=page_title, entity=entity, id=id)
    except orm.ObjectNotFound:
        missing_entitiy()
    except ValueError:
        flash('Warning: Invalid Request')

    if not valid_entity():
        flash('Warning: Invalid Feed/Category')

    return redirect(get_redirect_target())


@app.route('/opml', methods=['POST'])
@orm.db_session
@login_required
def opml():
    if 'action' in request.values and request.values['action'] in ['import', 'export']:
        if request.values['action'] == 'import':
            import_file = request.files.get('file')
            if not import_file or import_file.filename == '':
                flash('Warning: No File Selected')
            else:
                feed_list = listparser.parse(import_file)
                for feed in feed_list['feeds']:
                    url = feed['url']
                    if not Feed.get(url=url):
                        if 'title' in feed and feed['title']:
                            title = feed['title']
                        else:
                            p = feedparser.parse(url)
                            title = p.feed.title if 'title' in p.feed else url
                        new_feed = Feed(title=title, url=url)
                        for category_list in feed['categories']:
                            for title in category_list:
                                if title:
                                    category = Category.get(title=title)
                                    if not category:
                                        category = Category(title=title)
                                    new_feed.categories.add(category)
                flash('Feeds Imported!')
        elif request.values['action'] == 'export':
            opml = etree.Element('opml', version='2.0')
            head = etree.SubElement(opml, 'head')
            head_elements = {
                'title': 'feedfin OPML export',
                'dateCreated': format_datetime(datetime.utcnow()),
                'docs': 'http://dev.opml.org/spec2.html'
            }
            for element, text in head_elements.items():
                new_element = etree.SubElement(head, element)
                new_element.text = text
            body = etree.SubElement(opml, 'body')
            for feed in Feed.select():
                new_element = etree.SubElement(body, 'outline',
                    type='rss',
                    text=feed.title,
                    xmlUrl=feed.url,
                    category=','.join([category.title for category in feed.categories])
                )
            opml_bytes = etree.tostring(opml, encoding='UTF-8', xml_declaration=True)
            response = make_response(opml_bytes.decode('utf-8'))
            response.headers['Content-Disposition'] = 'attachment; filename=feedfin.opml'
            return response

    else:
        flash('Warning: Invalid Request')

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


@app.route('/del_all', methods=['POST', 'GET'])
@orm.db_session
@login_required
def del_all():
    if request.method == 'GET':
        del_feed = 'entity' not in request.values or (
            'entity' in request.values and request.values['entity'] == 'feed')
        del_category = 'entity' not in request.values or (
            'entity' in request.values and request.values['entity'] == 'category')

        if del_feed:
            for feed in Feed.select():
                feed.delete()
            flash('Deleted All Feeds')
        if del_category:
            for category in Category.select():
                category.delete()
            flash('Deleted All Categories')
    elif request.method == 'POST':
        if 'prune' in request.values:
            try:
                prune = int(request.values['prune'])
                if prune >= 0:
                    cutoff = datetime.utcnow() - timedelta(days=prune)
                    articles = orm.select(a for a in Article if a.published < cutoff)
                    for article in articles:
                        article.delete()
                    flash('Deleted All Articles Older Than {} Days'.format(prune))
                else:
                    flash('Warning: You Must Specify 0 or More Days to Keep')
            except ValueError:
                flash('Warning: Invalid Number of Days')
        else:
            flash('Warning: You Must Specify the Number of Days to Keep')

    return redirect(get_redirect_target())


@app.route('/edit', methods=['POST', 'GET'])
@orm.db_session
@login_required
def edit_entity():
    if 'id' in request.values and int(request.values['id']) == -1:
        return redirect(url_for('settings'))
    next = get_redirect_target()
    if not valid_entity():
        flash('Warning: Invalid Edit Parameter(s)')
    else:
        try:
            if request.method == 'GET':
                if request.values['entity'] == 'feed':
                    feed=Feed[request.values['id']]
                    other_categories = list(orm.select(c for c in Category if c not in feed.categories))
                    return render_template('edit.html', feed=feed, other_categories=other_categories, next=next)

                elif request.values['entity'] == 'category':
                    category = Category[request.values['id']]
                    other_feeds = list(orm.select(f for f in Feed if f not in category.feeds))
                    return render_template('edit.html', category=category, other_feeds=other_feeds, next=next)

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

    return redirect(next)


@app.route('/fetch')
@orm.db_session
@login_required
def fetch_entity():
    try:
        entity, id, page_number = parse_entity()
        if entity == 'feed' and id == -1:
            feeds = list(Feed.select())
        elif entity == 'feed' and id > -1:
            feeds = [Feed[id]]
        elif entity == 'category' and id == -1:
            feeds = list(orm.select(f for f in Feed if not f.categories))
        elif entity == 'category' and id > -1:
            feeds = list(Category[id].feeds)
        else:
            feeds = []
            flash('Warning: Failed Fetch')

        with ProcessPoolExecutor() as executor:
            fetched = []
            for feed in feeds:
                fetched.append(executor.submit(fetch_feed, feed.url, feed.id))

            parsed = []
            for fetch in as_completed(fetched):
                results = fetch.result()
                feed = Feed[results['id']]
                if ((results['modified']
                     and feed.modified == results['modified'])
                        or (results['etag']
                            and feed.etag == results['etag'])):
                    continue
                else:
                    feed.modified = results['modified']
                    feed.etag = results['etag']
                    for entry in results['entries']:
                        if 'link' not in entry:
                            continue
                        url = entry['link']

                        if 'published_parsed' in entry:
                            published = datetime(*entry.published_parsed[:6])
                        else:
                            published = datetime.utcnow()

                        article = Article.get(url=url)
                        if article and article.published == published:
                            continue
                        else:
                            if article:
                                article.delete()
                            parsed.append(
                                executor.submit(
                                    parse_entry, entry, results['id'], url,
                                    published
                                )
                            )

            for entry in as_completed(parsed):
                art = entry.result()
                new_article = Article(
                    feed=Feed[art['id']],
                    author=art['author'],
                    title=art['title'],
                    url=art['url'],
                    published=art['published'],
                    summary=art['summary'],
                    image=art['image']
                )
                orm.commit()


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

def parse_entity():
    entity = request.values['entity'] if 'entity' in request.values and request.values['entity'] in ['feed', 'category'] else 'feed'
    id = int(request.values['id']) if 'id' in request.values and int(request.values['id']) >= -1 else -1
    page_number = abs(int(request.values['page'])) if 'page' in request.values else 1
    return entity, id, page_number


def allowed_file_name(filename):
    allowed_extensions = ['png', 'jpg', 'jpeg', 'gif']

    return '.' in filename and filename.rsplit('.', 1)[1] in allowed_extensions


def allowed_file_type(filetype):
    allowed_mimetypes = ['image/png', 'image/jpeg', 'image/gif']

    return filetype and filetype in allowed_mimetypes
