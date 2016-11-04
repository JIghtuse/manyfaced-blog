from google.appengine.ext import ndb
from blog_handler import BlogHandler
from user import User


class Post(ndb.Model):
    """Models post in a blog with title, content, and creation date"""
    title = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    creation_date = ndb.DateTimeProperty(auto_now_add=True)
    author = ndb.KeyProperty(kind=User, required=True)

    def render(self, permalink=False):
        author = User.get_by_id(self.author.id())
        return BlogHandler.render_template("post.html", post=self,
                                           author=author.name,
                                           permalink=permalink)
