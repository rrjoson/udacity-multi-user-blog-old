import os
import re
import random
from string import letters
import hmac
import hashlib

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

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

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

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
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/')

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    likes = db.IntegerProperty(default = 0)
    user_id = db.IntegerProperty(required = True)

    def render(self, current_user_id):
        key = db.Key.from_path('User', int(self.user_id), parent=users_key())
        user = db.get(key)

        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self, current_user_id = current_user_id, author = user.name  )

    @classmethod
    def by_id(cls, uid):
        return Post.get_by_id(uid, parent = blog_key())
        
class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where ancestor is :1 order by created desc limit 10", key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, comments = comments)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.write("You don't have permission to access this page")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, user_id = self.user.key().id())
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)



###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):

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

    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

# Registration system

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, password, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + password + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name, 
                    pw_hash = pw_hash, 
                    email = email)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def login(cls, username, password):
        u = User.by_name(username)
        if u and valid_pw(username, password, u.pw_hash):
            return u

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)

        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error = msg)
        else: 
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Login(BlogHandler):
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
            msg = 'Invalid Username or Password'
            self.render('login-form.html', error = msg)

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

class Delete(BlogHandler):
    def get(self, post_id, post_user_id):
        if self.user and self.user.key().id() == int(post_user_id): 
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.delete()

            self.redirect('/blog')

        else:
            self.write("You don't have permission to delete this post")

class EditPost(BlogHandler):
    def get(self, post_id, post_user_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)


        if self.user and self.user.key().id() == post.user_id:
            self.render('editpost.html', subject = post.subject, content = post.content)
        else: 
            self.write("You cannot edit this post becuase you are not the one who wrote this post.")

    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            post.subject = subject
            post.content = content

            post.put()

            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class LikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key) 

        if self.user and self.user.key().id() == post.user_id:
            self.write("You cannot like your own post")
        elif not self.user:
            self.write("You don't have permission to like this post.")
        else:
            l = Like.all().filter('user_id =', self.user.key().id()).filter('post_id =', post.key().id()).get()
            
            if l:
                self.redirect('/blog/')
            else: 
                like = Like(parent = key, user_id = self.user.key().id(), post_id = post.key().id())  
                post.likes += 1

                like.put()
                post.put()

                self.redirect('/blog/')

class UnlikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key) 

        if self.user and self.user.key().id() == post.user_id:
            self.write("You cannot dislike your own post")
        elif not self.user:
            self.write("You don't have permission to unlike this post.")
        else:
            l = Like.all().filter('user_id =', self.user.key().id()).filter('post_id =', post.key().id()).get()

            if l:
                l.delete()
                post.likes -= 1
                post.put()

                self.redirect('/blog/')
            else:
                self.redirect('/blog/') 



class Like(db.Model):
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.IntegerProperty(required = True)
    post_id = db.IntegerProperty(required = True)

class Comment(db.Model):
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.IntegerProperty(required = True)

class AddComment(BlogHandler):
    def get(self, post_id, user_id):
        self.render("addcomment.html")

    def post(self, post_id, user_id):
        content = self.request.get('content')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        c = Comment(parent = key, user_id = int(user_id), content = content)
        c.put()

        self.redirect('/blog/' + post_id)

class DeleteComment(BlogHandler):
    def get(self, post_id, post_user_id, comment_id):

        if self.user and self.user.key().id() == int(post_user_id):
            postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
            comment = db.get(key)
            comment.delete()

            self.redirect('/blog/' + post_id)

        else:
            self.write("You don't have permission to delete this comment.")


class EditComment(BlogHandler):
    def get(self, post_id, post_user_id, comment_id):
        if self.user and self.user.key().id() == int(post_user_id):
            postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
            comment = db.get(key)

            self.render('editcomment.html', content = comment.content)

        else:
            self.write("You don't have permission to delete this comment.")


    def post(self, post_id, post_user_id, comment_id):
        content = self.request.get('content')

        postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
        comment = db.get(key)

        comment.content = content
        comment.put()

        self.redirect('/blog/' + post_id)






app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/logout', Logout),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/delete/([0-9]+)/([0-9]+)', Delete),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/blog/([0-9]+)/unlike', UnlikePost),
                               ('/blog/([0-9]+)/([0-9]+)/addcomment', AddComment),
                               ('/blog/([0-9]+)/([0-9]+)/([0-9]+)/deletecomment', DeleteComment),
                               ('/blog/([0-9]+)/([0-9]+)/([0-9]+)/editcomment', EditComment)

                               ],
                              debug=True)
