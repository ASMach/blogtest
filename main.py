#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from string import letters

import re
import os
import random
import hashlib
import hmac

import webapp2
import jinja2

import logging

from google.appengine.ext import db

from jinja2 import Environment

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, article):
    response.out.write('<b>' + article.subject + '</b><br>')
    response.out.write(article.content)

# Blog code including data structure

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Article(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author_id = db.IntegerProperty()
    liking_users = db.ListProperty(int, required = True) #List of users who have liked an article by user_id

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')

        return render_str("post.html", p = self, u = User, user = user)

class Comment(db.Model):
    author_id = db.IntegerProperty(required = True)
    body = db.StringProperty(required = True)
    article = db.ReferenceProperty(Article, collection_name='comments')

    def post(self):
        body = self.request.get('body')

class BlogFront(Handler):
    def get(self):
        articles = db.GqlQuery("SELECT * FROM Article ORDER BY created DESC LIMIT 10")
        self.render('front.html', articles = articles)

    def post(self, article_id):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        liking_users = self.request.get('liking_users')

        if subject and content:
            uid = int(self.read_secure_cookie('user_id')) # For identifying who wrote an article
            a = article_id.get() # Retrieve the article to update by its ID
            a.subject = subject # Update its subject
            a.content = content # Update its content
            # a.liking_users = liking_users # Update liking users
            a.put() # Actually save the new data
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error = "We need both a subject and an article body!"
            # TODO: Show error message on page

class PostPage(Handler):
    def get(self, article_id):
        key = db.Key.from_path('Article', int(article_id), parent=blog_key())
        article = db.get(key)

        if not article:
            self.error(404)
            return

        self.render("permalink.html", article = article)

    def post(self, article_id):
        if not self.user:
            self.redirect('/blog')

        key = db.Key.from_path('Article', int(article_id), parent=blog_key())

        subject = self.request.get('subject')
        content = self.request.get('content')
        # liking_users = self.request.get('liking_users')

        if subject and content:
            uid = int(self.read_secure_cookie('user_id')) # For identifying who wrote an article
            a = article_id.get() # Retrieve the article to update by its ID
            a.subject = subject # Update its subject
            a.content = content # Update its content
            # a.liking_users = liking_users # Update liking users
            a.put() # Actually save the new data
            self.write(json.dumps(({'redirect_url': '/blog/' + blog_id}))) # Prepare to redirect

            # Old redirect
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error = "We need both a subject and an article body!"
            self.render("post.html", subject=subject, content=content, error=error)

class EditPost(Handler):
    def get(self, article_id):
        if self.user:
            self.render("editpost.html")
        else:
            self.redirect("/blog/login")

    def post(self, article_id):
        if not self.user:
            self.redirect('/blog')

        key = db.Key.from_path('Article', int(article_id), parent=blog_key())

        subject = self.request.get('subject')
        content = self.request.get('content')
        # liking_users = self.request.get('liking_users')

        if subject and content:
            uid = int(self.read_secure_cookie('user_id')) # For identifying who wrote an article
            a = article_id.get() # Retrieve the article to update by its ID
            a.subject = subject # Update its subject
            a.content = content # Update its content
            # a.liking_users = liking_users # Update liking users
            a.put() # Actually save the new data
            self.write(json.dumps(({'redirect_url': '/blog/' + blog_id}))) # Prepare to redirect

            # Old redirect
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error = "We need both a subject and an article body!"
            self.render("post.html", subject=subject, content=content, error=error)

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/blog/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        #liking_users = self.request.get('liking_users')

        if subject and content:
            uid = int(self.read_secure_cookie('user_id')) # For identifying who wrote an article
            a = Article(parent = blog_key(), subject = subject, content = content, author_id = uid)#, liking_users = liking_users) # TODO: Diagnose invalid value being passed in
            a.put()
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error = "We need both a subject and an article body!"
            self.render("newpost.html", subject=subject, content=content, error=error)

# user stuff

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Signup(Handler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')

class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')

class MainPage(Handler):
    def render_front(self, subject="", content="", error=""):
        articles = db.GqlQuery("SELECT * FROM Article ORDER BY created DESC")

        self.render("front.html", subject=subject, content=content, error = error, articles = articles)

    def get(self):
        self.render_front()

app = webapp2.WSGIApplication([
    ('/', MainPage), ('/blog/?', BlogFront), ('/blog/([0-9]+)', PostPage), ('/blog/edit/', EditPost), ('/blog/newpost', NewPost), ('/blog/signup', Register), ('/blog/login', Login), ('/blog/logout', Logout), ('/blog/welcome', Welcome),
], debug=True)
