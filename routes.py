import webapp2
from handlers import HomePage, NewPostPage, PostPermalinkPage
from handlers import WelcomePage, SignupPage, LoginPage, LogoutHandler

COMMON_ROUTES = [
    webapp2.Route('/', HomePage, name="home"),
    webapp2.Route('/blog', HomePage, name="home"),
    webapp2.Route('/blog/', HomePage, name="home"),
    webapp2.Route('/blog/<post_id:\d+>', PostPermalinkPage, name="permalink"),
    webapp2.Route('/blog/newpost', NewPostPage, name="newpost"),
    webapp2.Route('/blog/welcome', WelcomePage, name="welcome"),
    webapp2.Route('/blog/signup', SignupPage, name="signup"),
    webapp2.Route('/blog/login', LoginPage, name="login"),
    webapp2.Route('/blog/logout', LogoutHandler, name="logout"),
]
