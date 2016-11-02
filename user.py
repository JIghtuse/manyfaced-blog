from google.appengine.ext import ndb
from password import make_password_hash, valid_password


class User(ndb.Model):
    """Models blog user"""
    name = ndb.StringProperty(required=True)
    password_hash = ndb.StringProperty(required=True)
    salt = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_name(cls, name):
        return cls.query(User.name == name).get()

    @classmethod
    def register(cls, name, password, email=None):
        password_hash, salt = make_password_hash(name, password)
        return User(name=name,
                    password_hash=password_hash, salt=salt,
                    email=email)

    @classmethod
    def login(cls, name, password):
        user = cls.by_name(name)
        if user and valid_password(name, password, user.password_hash,
                                   user.salt):
            return user
