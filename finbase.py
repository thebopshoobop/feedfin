from pony import orm
from datetime import datetime
import feedparser
from flask import Flask, render_template, request, redirect, url_for
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment

db = orm.Database()
#orm.sql_debug(True)
db.bind('sqlite', 'fbdb.sqlite', create_db=True)

app = Flask(__name__)

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

@app.template_filter('datetime')
def format_datetime(value, format='full'):
    formats = {'full': '%m/%d/%Y %I:%M%p', 'date': '%m/%d/%Y', 'time': '%I:%M%p'}
    return value.strftime(formats[format])

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
def all_feeds():
    articles = list(Article.select().order_by(orm.desc(Article.published)))
    return render_template('all_feeds.html', articles=articles)

@app.route('/feed/<int:id>')
@orm.db_session
def feed(id):
    try:
        feed = Feed[id]
        articles = list(orm.select(a for a in Article if a.feed is feed).order_by(orm.desc(Article.published)))
        return render_template('feed.html', feed=feed, articles=articles)
    except orm.ObjectNotFound:
        return render_template('missing.html', entity='Feed', id=id)

@app.route('/add_feed', methods=['POST'])
@orm.db_session
def add_feed():
    if request.form['url']:
        url = request.form['url']
        new_feed = Feed.get(url=url)
        if not new_feed:
            p = feedparser.parse(url)
            title = p.feed.title if 'title' in p.feed else url
            new_feed = Feed(title=title, url=url)

    return redirect(redirect_referrer())

@app.route('/del_feed/<int:id>')
@orm.db_session
def del_feed(id):
    try:
        Feed[id].delete()
        return redirect(redirect_referrer())
    except orm.ObjectNotFound:
        return render_template('missing.html', entity='Feed', id=id)

@app.route('/edit_feed/<int:id>', methods=['GET', 'POST'])
@orm.db_session
def edit_feed(id):
    try:
        feed = Feed[id]
        if request.method == 'POST' and request.form['submit'] == 'Save':
            feed.title = request.form['title']
            feed.url = request.form['url']
            old = set(c.id for c in feed.categories)
            new = set(request.form.getlist('category'))
            if  new != old:
                feed.categories.clear()
                [feed.categories.add(Category[c]) for c in new]
            return redirect(url_for('settings'))

        elif request.method == 'POST' and request.form['submit'] == 'Delete':
            return redirect(url_for('del_feed', id=id))

        other_categories = list(orm.select(c for c in Category if c not in feed.categories))
        return render_template('edit_feed.html', feed=feed, other_categories=other_categories)

    except orm.ObjectNotFound:
        return render_template('missing.html', entity='Feed', id=id)

@app.route('/category')
@app.route('/category/<int:id>')
@orm.db_session
def category(id=-1):
    if id < 0:
        articles = list(orm.select(a for a in Article if not a.feed.categories).order_by(orm.desc(Article.published)))
        return render_template('category.html', articles=articles)
    try:
        category = Category[id]
        articles = list(orm.select(a for a in Article if a.feed in category.feeds).order_by(orm.desc(Article.published)))
        return render_template('category.html', category=category, articles=articles)
    except orm.ObjectNotFound:
        return render_template('missing.html', entity='Category', id=id)

@app.route('/add_category', methods=['POST'])
@orm.db_session
def add_category():
    if request.form['category']:
        title = request.form['category']
        new_category = Category.get(title=title)
        if not new_category:
            new_category = Category(title=title)

    return redirect(redirect_referrer())


@app.route('/del_category/<int:id>')
@orm.db_session
def del_category(id):
    try:
        Category[id].delete()
        return redirect(redirect_referrer())
    except orm.ObjectNotFound:
        return render_template('missing.html', entity='Category', id=id)

@app.route('/edit_category/<int:id>', methods=['GET', 'POST'])
@orm.db_session
def edit_category(id):
    try:
        category = Category[id]
        if request.method == 'POST' and request.form['submit'] == 'Save':
            category.title = request.form['title']
            old = set(f.id for f in category.feeds)
            new = set(request.form.getlist('feed'))
            if  new != old:
                category.feeds.clear()
                [category.feeds.add(Feed[f]) for f in new]
            return redirect(url_for('settings'))

        elif request.method == 'POST' and request.form['submit'] == 'Delete':
            return redirect(url_for('del_category', id=id))

        other_feeds = list(orm.select(f for f in Feed if f not in category.feeds))
        return render_template('edit_category.html', category=category, other_feeds=other_feeds)
    except orm.ObjectNotFound:
        return render_template('missing.html', entity='Category', id=id)

@app.route('/fetch/<int:id>')
@orm.db_session
def fetch(id):
    try:
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
        return redirect(url_for('feed', id=id))
    except orm.ObjectNotFound:
        return render_template('missing.html', entity='Feed', id=id)

@app.route('/fetch_all')
@orm.db_session
def fetch_all():
    for feed_id in orm.select(f.id for f in Feed):
        fetch(feed_id)
    return redirect(redirect_referrer())

@app.route('/fetch_category')
@app.route('/fetch_category/<int:id>')
@orm.db_session
def fetch_category(id=-1):
    if id < 0:
        feeds = orm.select(f for f in Feed if not f.categories)
        for feed in feeds:
            fetch(feed.id)
        return redirect(url_for('category'))
    else:
        try:
            category = Category[id]
            for feed in category.feeds:
                fetch(feed.id)
            return redirect(url_for('category', id=id))
        except orm.ObjectNotFound:
            return render_template('missing.html', entity='Category', id=id)

def redirect_referrer(default='all_feeds'):
    if urlparse(url_for(default, _external=True)).netloc == urlparse(request.referrer).netloc:
        return request.referrer
    else:
        return url_for(default)

def strip_summary(summary):
    soup = BeautifulSoup(summary, 'html.parser')
    text = soup.find_all(text=True)
    return ' '.join(list(filter(visible, text)))[:300] + '...'

def visible(element):
    if element.parent.name in ['style', 'script', '[document]', 'head', 'title', 'meta']:
        return False
    elif isinstance(element, Comment):
        return False
    return True
