from pony import orm
from datetime import datetime
import feedparser

db = orm.Database()

class Feed(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    articles = orm.Set('Article')
    categories = orm.Set('Category')
    title = orm.Required(str)
    url = orm.Required(str)
    etag = orm.Optional(str)
    modified = orm.Optional(str)


class Article(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    feed = orm.Required('Feed')
    authors = orm.Set('Author')
    tags = orm.Set('Tag')
    title = orm.Required(str)
    url = orm.Required(str)
    read = orm.Required(bool, default=False)
    published = orm.Optional(datetime)
    summary = orm.Optional(str)

class Category(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    title = orm.Required(str, unique=True)
    feeds = orm.Set('Feed')

class Tag(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    label = orm.Required(str, unique=True)
    articles = orm.Set('Article')

class Author(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    name = orm.Required(str, unique=True)
    articles = orm.Set('Article')

def setup():
    orm.sql_debug(True)
    db.bind('sqlite', 'fbdb.sqlite', create_db=True)
    db.generate_mapping(create_tables=True)

def add_feed(url, title=''):
    if not title:
        p = feedparser.parse(url)
        title = p.feed.title if 'title' in p.feed else url

    with orm.db_session:
        new_feed = Feed(title=title, url=url)
        return new_feed.id

def add_category(title):
    with orm.db_session:
        new_category = Category(title=title)
        return new_category.id
