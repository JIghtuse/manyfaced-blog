import webapp2
from handler import Handler
from cookie import make_cookie, check_cookie
from user import User


class BlogHandler(Handler):
    COOKIE_USER_ID = 'user_id'

    def render(self, template_filename, **kw):
        kw['user'] = self.user
        Handler.render(self, template_filename, **kw)

    def set_secure_cookie(self, name, value):
        cookie = make_cookie(name, value)
        self.response.headers.add_header('Set-Cookie', cookie)

    def read_secure_cookie(self, name):
        cookie_value = self.request.cookies.get(name)
        return check_cookie(cookie_value)

    def login(self, user):
        self.set_secure_cookie(BlogHandler.COOKIE_USER_ID, str(user.key.id()))

    def logout(self):
        self.set_secure_cookie(BlogHandler.COOKIE_USER_ID, '')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie(BlogHandler.COOKIE_USER_ID)
        self.user = uid and User.get_by_id(int(uid))
