import hashlib
import random
import string


def make_salt(length=32):
    return ''.join(random.sample(string.ascii_letters, length))


def make_password_hash(name, password, salt=None):
    if salt is None:
        salt = make_salt()
    message = name + password + salt
    h = hashlib.sha256(message.encode())
    return h.hexdigest(), salt


def valid_password(name, password, h, salt):
    return make_password_hash(name, password, salt)[0] == h
