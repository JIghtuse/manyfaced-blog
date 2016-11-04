#!/usr/bin/env python3

import hmac
import logging
from secret import SECRET

SEPARATOR = '|'


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return s + SEPARATOR + hash_str(s)


def check_secure_val(sh):
    s, hash_value = sh.split(SEPARATOR)
    if hash_str(s) == hash_value:
        return s
    else:
        logging.warning("Something wrong with value or hash: " + sh)


def make_cookie(name, value):
    cookie_value = make_secure_val(value)
    return "{name}={value}; Path=/".format(name=name, value=cookie_value)


def check_cookie(value):
    return value and check_secure_val(value)
