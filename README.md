# feedfin
feedfin is a simple feed agregator that I'm building in [Python 3](https://www.python.org/) with [Flask](http://flask.pocoo.org/), [Pony](https://ponyorm.com/), and [Bootstrap](http://getbootstrap.com/). It still needs tons of work, but it's at least minimally functional... Give it a spin?

### Installing
<<<<<<< HEAD
###### Clone the repo
```
$ git clone https://github.com/thebopshoobop/feedfin.git
```
###### Initialize and source a virtualenv
```
$ cd feedfin
$ virtualenv -p python3 venv
$ source venv/bin/activate
```
###### Install dependencies
```
$ (venv) pip install -r requirements.txt
```
=======
Nothing much to it:
1. Clone the repo
```
$ git clone https://github.com/thebopshoobop/feedfin.git
```
2. Initialize and source a virtualenv
```
 $ cd feedfin
 $ virtualenv -p python3 venv
 $ source venv/bin/activate
```
3. Install dependencies
```
 $ (venv) pip install -r requirements.txt
 ```
>>>>>>> 06d60a71062431bf7cf3b51537aac5723fa6e7bd

### Running

<<<<<<< HEAD
###### You can just run it locally for testing and whatnot:
=======
* You can just run it locally for testing and whatnot:
>>>>>>> 06d60a71062431bf7cf3b51537aac5723fa6e7bd
```
$ (venv) export FLASK_APP=feedfin.py
$ (venv) flask run
```
<<<<<<< HEAD
###### Or you can run it as a daemon:
Install the included example feedfin.service systemd unit file (after making any necessary edits) somewhere sensible like `/etc/systemd/system/`, and fire it up. I'd suggest putting it behind a reverse proxy like [nginx](https://www.nginx.com/resources/admin-guide/reverse-proxy/).


### Notes
When you run it for the first time feedfin will automatically create an empty database in its directory. When you load up the site in your browser it will redirect you to the register view, where you can punch in some credentials. After that, hit up the settings to add some feeds and categories. Now hit the refresh button from any display screen for some sweet, sweet feed goodness! At this time feedfin only has support for a single user, is horribly ineffecient at downloading and parsing new articles, and doesn't even implement paging. But hey, it fetches your feeds!
=======
* Or you can install the included example feedfin.service systemd unit file (making any necessary edits) and fire it up as a daemon. I'd suggest putting it behind a reverse proxy like [nginx](https://www.nginx.com/resources/admin-guide/reverse-proxy/).

When you run it for the first time it will automatically create an empty database in its directory. When you load up the site in your browser it will redirect you to the register view, where you can punch in some credentials. After that, hit up the settings to add some feeds and categories. At this time feedfin only has support for a single user, is horribly ineffecient at downloading and parsing new articles, and doesn't even implement paging. But hey, it fetches your feeds!
>>>>>>> 06d60a71062431bf7cf3b51537aac5723fa6e7bd
