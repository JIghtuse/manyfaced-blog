"""Multi-user blog"""

import webapp2
from google.appengine.ext import ndb
from handler import Handler


class Post(ndb.Model):
    """Models post in a blog with title, content, and creation date"""
    title = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    creation_date = ndb.DateTimeProperty(auto_now_add=True)

    def render(self):
        return Handler.render_template("post.html", post=self)


class HomePage(Handler):
    """Displays blog home page with posts"""
    def get(self):
        posts = Post.query().order(-Post.creation_date).fetch(limit=10)
        self.render("main_page.html", posts=posts)


class NewPostPage(Handler):
    """Displays form to submit new posts"""
    def render_page(self, **kw):
        self.render("new_post.html", **kw)

    def get(self):
        self.render_page()

    def post(self):
        title = self.request.get('title')
        content = self.request.get('content')
        params = dict(title=title, content=content)

        if content and title:
            # Creating a post
            post = Post(content=content, title=title)
            post.put()

            # Redirecting to post permalink page
            post_id = post.key.id()
            self.redirect("/blog/" + str(post_id))
        else:
            # Showing errors
            if not title:
                params['post_title_error'] = "Post title cannot be empty"
            if not content:
                params['post_content_error'] = "Post content cannot be empty"
            self.render_page(**params)


class PostPermalinkPage(Handler):
    """Displays a single blog post"""
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        if not post:
            self.error(404)
        else:
            self.render("post_permalink.html", post=post)


app = webapp2.WSGIApplication([
    ('/', HomePage),
    ('/blog/?', HomePage),
    ('/blog/newpost', NewPostPage),
    ('/blog/(\d+)', PostPermalinkPage)
], debug=True)
