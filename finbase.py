from pony import orm
from datetime import datetime
import feedparser
from flask import Flask, render_template, request, redirect, url_for, flash
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment
from flask_bootstrap import Bootstrap
from flask_moment import Moment

db = orm.Database()
#orm.sql_debug(True)
db.bind('sqlite', 'fbdb.sqlite', create_db=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'TcAnhkN0z4F2loeqVA8IHw6Hw5iU10n1bgxcigeZdk27sMRm8oGlrw5EUENgd8vo'
bootstrap = Bootstrap(app)
moment = Moment(app)

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
        author = Author[add_author(e.author)] if 'author' in e and e.author else Author[add_author('None')]
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

@app.context_processor
@orm.db_session
def nav_variables():
    feeds = list(Feed.select())
    uncategorized = list(Feed.select(lambda u: not u.categories))
    categories = list(Category.select())
    return dict(nav_feeds=feeds, nav_uncategorized=uncategorized, nav_categories=categories)

@app.route('/settings')
@orm.db_session
def settings():
    return render_template('settings.html')

@app.route('/')
@orm.db_session
def display():
    if not valid_entity():
        flash('Warning: Invalid Feed/Category')
    else:
        try:
            if not 'entity' in request.args:
                articles = list(Article.select().order_by(orm.desc(Article.published)))
                return render_template('display.html', type='all_feeds', articles=articles)
            elif request.args['entity'] == 'category' and 'id' not in request.args:
                articles = list(orm.select(a for a in Article if not a.feed.categories).order_by(orm.desc(Article.published)))
                return render_template('display.html', type='uncategorized', articles=articles)
            elif valid_entity() and request.args['entity'] == 'category':
                category = Category[request.args['id']]
                articles = list(orm.select(a for a in Article if a.feed in category.feeds).order_by(orm.desc(Article.published)))
                return render_template('display.html', type='category', category=category, articles=articles)
            elif valid_entity() and request.args['entity'] == 'feed':
                feed = Feed[request.args['id']]
                articles = list(orm.select(a for a in Article if a.feed is feed).order_by(orm.desc(Article.published)))
                return render_template('display.html', type='feed', feed=feed, articles=articles)
        except orm.ObjectNotFound:
            missing_entitiy()

    return redirect(redirect_referrer())

@app.route('/add', methods=['POST'])
@orm.db_session
def add_entity():
    if request.form['entity'] == 'feed' and request.form['url']:
        url = request.form['url']
        if not Feed.get(url=url):
            p = feedparser.parse(url)
            title = p.feed.title if 'title' in p.feed else url
            new_feed = Feed(title=title, url=url)
    elif request.form['entity'] == 'category' and request.form['category']:
        title = request.form['category']
        if not Category.get(title=title):
            new_category = Category(title=title)

    return redirect(url_for('settings'))

@app.route('/del')
@orm.db_session
def del_entity():
    if valid_entity():
        try:
            if request.args['entity'] == 'feed':
                Feed[request.args['id']].delete()
            elif request.args['entity'] == 'category':
                Category[request.args['id']].delete()
            flash('Sucess!')
        except orm.ObjectNotFound:
            missing_entitiy()

    return redirect(url_for('settings'))

@app.route('/edit', methods=['POST', 'GET'])
@orm.db_session
def edit_entity():
    if not valid_entity():
        flash('Warning: Invalid Edit Parameter(s)')
    try:
        if request.method == 'GET':
            if request.args['entity'] == 'feed':
                feed=Feed[request.args['id']]
                other_categories = list(orm.select(c for c in Category if c not in feed.categories))
                return render_template('edit.html', feed=feed, other_categories=other_categories)

            elif request.args['entity'] == 'category':
                category = Category[request.args['id']]
                other_feeds = list(orm.select(f for f in Feed if f not in category.feeds))
                return render_template('edit.html', category=category, other_feeds=other_feeds)

        elif request.method =='POST':
            if request.form['submit'] == 'delete':
                return redirect(url_for('del_entity', entity=request.form['entity'], id=request.form['id']))

            elif request.form['submit'] == 'save' and request.form['entity'] == 'feed':
                feed = Feed[request.form['id']]
                feed.title = request.form['title']
                feed.url = request.form['url']
                feed.categories.clear()
                [feed.categories.add(Category[c]) for c in list(request.form.getlist('category'))]
                flash('Success!')

            elif request.form['submit'] == 'save' and request.form['entity'] == 'category':
                category = Category[request.form['id']]
                category.title = request.form['title']
                category.feeds.clear()
                [category.feeds.add(Feed[f]) for f in list(request.form.getlist('feed'))]
                flash('Success')

            else:
                flash('Warning: Improper Edit Submission')

    except orm.ObjectNotFound:
        missing_entitiy()

    return redirect(url_for('settings'))

@app.route('/fetch')
@orm.db_session
def fetch_entity():
    try:
        if not 'entity' in request.args:
            for feed_id in orm.select(f.id for f in Feed):
                fetch_feed(feed_id)
        elif request.args['entity'] == 'category' and 'id' not in request.args:
            for feed in orm.select(f for f in Feed if not f.categories):
                fetch_feed(feed.id)
        elif valid_entity() and request.args['entity'] == 'category':
            for feed in Category[request.args['id']].feeds:
                fetch_feed(feed.id)
        elif valid_entity() and request.args['entity'] == 'feed':
            fetch_feed(request.args['id'])
        else:
            flash('Warning: Failed Fetch')

    except orm.ObjectNotFound:
        missing_entitiy()

    return redirect(redirect_referrer())

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

def missing_entitiy():
    try:
        method_mux = {'GET': request.args, 'POST': request.form}
        rq = method_mux[request.method]
        flash('Warning: Could not find {} with id {}'.format(rq['entity'], rq['id']))
    except (KeyError):
        flash('Warning: Invalid Request Type')


def redirect_referrer(default='display'):
    if urlparse(url_for(default, _external=True)).netloc == urlparse(request.referrer).netloc:
        return request.referrer
    else:
        return url_for(default)

def valid_entity():
    try:
        method_mux = {'GET': request.args, 'POST': request.form}
        rq = method_mux[request.method]
        return int(rq['id']) >= 0 and rq['entity'] in ['feed', 'category']
    except (ValueError, KeyError):
        return False
