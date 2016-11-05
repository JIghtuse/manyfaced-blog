from google.appengine.ext import ndb
from user import User
from post import Post


class Vote(ndb.Model):
    """Models post in a blog with title, content, and creation date"""
    user = ndb.KeyProperty(kind=User, required=True)
    post = ndb.KeyProperty(kind=Post, required=True)
    like = ndb.BooleanProperty(default=False, required=True, indexed=True)
    dislike = ndb.BooleanProperty(default=False, required=True, indexed=True)

    @classmethod
    def like_post(cls, post_key, user_key):
        vote = Vote.query().filter(Vote.post == post_key,
                                   Vote.user == user_key).get()
        if vote:
            vote.like = True
            vote.dislike = False
        else:
            vote = cls(user=user_key, post=post_key, like=True, dislike=False)
        vote.put()

    @classmethod
    def dislike_post(cls, post_key, user_key):
        vote = Vote.query().filter(Vote.post == post_key,
                                   Vote.user == user_key).get()
        if vote:
            vote.like = False
            vote.dislike = True
        else:
            vote = cls(user=user_key, post=post_key, like=False, dislike=True)
        vote.put()

    @classmethod
    def score(self, post_key):
        likes = Vote.query(Vote.post == post_key,
                           Vote.like == True).count()
        dislikes = Vote.query(Vote.post == post_key,
                              Vote.dislike == True).count()

        return likes - dislikes
