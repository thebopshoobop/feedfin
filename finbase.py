from pony import orm
from datetime import datetime
import feedparser
from flask import Flask
from flask import render_template

db = orm.Database()
orm.sql_debug(True)
db.bind('sqlite', 'fbdb.sqlite', create_db=True)

app = Flask(__name__)

class Feed(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    articles = orm.Set('Article')
    categories = orm.Set('Category')
    title = orm.Required(str)
    url = orm.Required(str, unique=True)
    etag = orm.Required(str)
    modified = orm.Required(str)

class Article(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    feed = orm.Required('Feed')
    author = orm.Required('Author')
    tags = orm.Set('Tag')
    title = orm.Required(str)
    url = orm.Required(str, unique=True)
    read = orm.Required(bool, default=False)
    published = orm.Required(datetime)
    summary = orm.Required(str)

class Category(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    title = orm.Required(str, unique=True)
    feeds = orm.Optional('Feed')

class Tag(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    label = orm.Required(str, unique=True)
    articles = orm.Set('Article')

class Author(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    name = orm.Required(str, unique=True)
    articles = orm.Set('Article')

db.generate_mapping(create_tables=True)

@orm.db_session
def fetch_all_feeds():
    for feed_id in orm.select(f.id for f in Feed):
        fetch_feed(feed_id)

@orm.db_session
def fetch_feed(id):
    feed = Feed[id]
    p = feedparser.parse(feed.url, etag=feed.etag, modified=feed.modified)
    feed.etag = p.etag if 'etag' in p else ''
    feed.modified = p.modified if 'modified' in p else ''
    for e in p.entries if 'entries' in p else []:
        author = Author[add_author(e.author)] if 'author' in e and e.author else Author[add_author('none')]
        tags = [Tag[add_tag(t.term)] for t in e.tags] if 'tags' in e else Tag[add_tag('none')]
        title = e.title if 'title' in e else ''
        url = e.link if 'link' in e else feed.url
        published = datetime(*e.published_parsed[:6]) if 'published_parsed' in e else datetime.utcnow()
        summary = e.summary if 'summary' in e else ''
        a = Article.get(url=url)
        if a:
            if a.published != published:
                a.feed = feed
                a.author = author
                a.tags = tags
                a.title = title
                a.published = published
                a.summary = summary
        else:
            new_article = Article(feed=feed, author=author, tags=tags, title=title, url=url, published=published, summary=summary)

def add_feed(url, title=''):
    if not title:
        p = feedparser.parse(url)
        title = p.feed.title if 'title' in p.feed else url
    with orm.db_session:
        exists = Feed.get(url=url)
        if exists:
            return exists.id
        else:
            new_feed = Feed(title=title, url=url)
            orm.commit()
            return new_feed.id

@orm.db_session
def del_feed(id):
    Feed[id].delete()

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
def del_category(id):
    Category[id].delete()

@orm.db_session
def add_tag(label):
    exists = Tag.get(label=label)
    if exists:
        return exists.id
    else:
        new_tag = Tag(label=label)
        orm.commit()
        return new_tag.id

@orm.db_session
def del_tag(id):
    Tag[id].delete()

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
def del_author(id):
    Author[id].delete()

@app.route('/feeds')
@orm.db_session
def feeds():
    feeds = orm.select(f for f in Feed)[:]
    return render_template('feeds.html', feeds=feeds)

@app.route('/feed/<int:id>')
@orm.db_session
def feed(id):
    try:
        feed = Feed[id]
        return render_template('feed.html', feed=feed)
    except orm.ObjectNotFound:
        return render_template('missing.html', entity='Feed', id=id)
