from pony import orm
from datetime import datetime
import feedparser

db = orm.Database()

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
    authors = orm.Set('Author')
    tags = orm.Set('Tag')
    title = orm.Required(str)
    url = orm.Required(str, unique=True)
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


@orm.db_session
def add_feed(url):
    exists = Feed.get(url=url)
    if exists:
        return exists.id
    else:
        new_feed = Feed(title=title, url=url)
        commit()
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
        commit()
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
        commit()
        return new_tag.id

@orm.db_session
def del_tag(id):
    Tag[id].delete()

@orm.db_session
def add_author(name):
    exists=Author.get(name)
    if exists:
        return exists.id
    else:
        new_author = Author(name=name)
        commit()
        return new_author.id

@orm.db_session
def del_author(id):
    Author[id].delete()
