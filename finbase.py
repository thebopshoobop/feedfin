from pony import orm
from datetime import datetime

db = orm.Database()

class Feed(db.Entity):
    id = orm.PrimaryKey(int, auto=True)
    title = orm.Required(str, unique=True)
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
    title = orm.Required(str)
    feeds = orm.Set('Feed')

def setup():
    orm.sql_debug(True)
    db.bind('sqlite', 'fbdb.sqlite', create_db=True)
    db.generate_mapping(create_tables=True)
