from google.appengine.ext import ndb
from blog_handler import BlogHandler


class Post(ndb.Model):
    """Models post in a blog with title, content, and creation date"""
    title = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    creation_date = ndb.DateTimeProperty(auto_now_add=True)

    def render(self):
        return BlogHandler.render_template("post.html", post=self)
