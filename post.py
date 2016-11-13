from google.appengine.ext import ndb
from blog_handler import BlogHandler
from user import User


class Post(ndb.Model):
    """
    Models post in a blog
    with title, content, creation date, author, and score"""
    title = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    creation_date = ndb.DateTimeProperty(auto_now_add=True)
    author = ndb.KeyProperty(kind=User, required=True)
    score = ndb.IntegerProperty(default=0)

    def render(self, permalink=False):
        author = User.get_by_id(self.author.id())
        return BlogHandler.render_template("post.html", post=self,
                                           author=author.name,
                                           permalink=permalink)

    def make_vote(self, user_key, like=False, dislike=False):
        vote = Vote.query().filter(Vote.post == self.key,
                                   Vote.user == user_key).get()
        if vote is None:
            vote = Vote(user=user_key, post=self.key,
                        like=like, dislike=dislike)
        else:
            vote.like = like
            vote.dislike = dislike
        vote.put()

    def recalculate_score(self):
        votes = Vote.query(Vote.post == self.key)
        likes = votes.filter(Vote.like == True).count()
        dislikes = votes.filter(Vote.dislike == True).count()
        self.score = likes - dislikes
        self.put()

    def like(self, user_key):
        self.make_vote(user_key, like=True)
        self.recalculate_score()

    def dislike(self, user_key):
        self.make_vote(user_key, dislike=True)
        self.recalculate_score()

    def get_comments(self):
        return Comment.query(Comment.post == self.key).order(Comment.creation_date)


class Vote(ndb.Model):
    """Models vote for a blog post"""
    user = ndb.KeyProperty(kind=User, required=True)
    post = ndb.KeyProperty(kind=Post, required=True)
    like = ndb.BooleanProperty(default=False, required=True, indexed=True)
    dislike = ndb.BooleanProperty(default=False, required=True, indexed=True)

    def __repr__(self):
        return "Vote({}, {}, {}, {})".format(self.user, self.post,
                                             self.like, self.dislike)


class Comment(ndb.Model):
    """Models comment for a blog post"""
    user = ndb.KeyProperty(kind=User, required=True)
    post = ndb.KeyProperty(kind=Post, required=True)
    content = ndb.TextProperty(required=True)
    creation_date = ndb.DateTimeProperty(auto_now_add=True)
