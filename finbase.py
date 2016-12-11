from pony import orm
from datetime import datetime
import feedparser

db = orm.Database()

class Feed(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    title = orm.Required(str)
    url = orm.Required(str)
    updated = orm.Optional(datetime)
    queried = orm.Optional(datetime)
    articles = orm.Set('Article')
    categories = orm.Set('Category')

class Article(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    feed = orm.Required('Feed')
    title = orm.Required(str)
    url = orm.Required(str)
    published = orm.Optional(datetime)
    updated = orm.Optional(datetime)
    read = orm.Optional(bool)

class Category(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    title = orm.Required(str, unique=True)
    feeds = orm.Set('Feed')

def setup():
    orm.sql_debug(True)
    db.bind('sqlite', 'fbdb.sqlite', create_db=True)
    db.generate_mapping(create_tables=True)

@orm.db_session
def add_feed(url, title='', categories=None):
    if not title:
        p = feedparser.parse(url)
        if 'title' in p.feed:
            title = p.feed.title
        else:
            title = url

    if categories:
        new_feed = Feed(title=title, url=url, categories=categories)
    else:
        new_feed = Feed(title=title, url=url)

    return new_feed

@orm.db_session
def add_category(title, feeds=None):
    if feeds:
        new_category = Category(title=title, feeds=feeds)
    else:
        new_category = Category(title=title)

    return new_category
