# feedfin
feedfin is a simple feed agregator that I'm building in [Python 3](https://www.python.org/) with [Flask](http://flask.pocoo.org/), [Pony](https://ponyorm.com/), and [Bootstrap](http://getbootstrap.com/). It still needs tons of work, but it's at least minimally functional... Give it a spin?

### Installing
Nothing much to it:
1. Clone the repo
    `$ git clone https://github.com/thebopshoobop/feedfin.git`
2. Initialize and source a virtualenv
    `$ cd feedfin`
    `$ virtualenv -p python3 venv`
    `$ source venv/bin/activate`
3. Install dependencies
    `$ (venv) pip install -r requirements.txt`

### Running
Easy peasy.

* You can just run it locally for testing and whatnot:
`$ (venv) export FLASK_APP=feedfin.py`
`$ (venv) flask run`
* Or you can install the included example feedfin.service systemd unit file (making any necessary edits) and fire it up as a daemon. I'd suggest putting it behind a reverse proxy like [nginx](https://www.nginx.com/resources/admin-guide/reverse-proxy/).

When you run it for the first time it will automatically create an empty database in the current directory. When you load up the site in your browser it will redirect you to the register view, where you can punch in some credentials. After that, hit up the settings to add some feeds and categories. At this time feedfin only has support for a single user, is horribly ineffecient at downloading and parsing new articles, and doesn't even implement paging. But hey, it fetches your feeds!
