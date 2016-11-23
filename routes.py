import webapp2
from handlers import HomePage, NewPostPage, PostPermalinkPage
from handlers import WelcomePage, SignupPage, LoginPage, LogoutHandler
from handlers import PostEditPage, NewCommentPage, CreditsPage, EditCommentPage

COMMON_ROUTES = [
    webapp2.Route('/', HomePage, name="home"),
    webapp2.Route('/blog', HomePage, name="home"),
    webapp2.Route('/blog/', HomePage, name="home"),
    webapp2.Route('/blog/<post_id:\d+>', PostPermalinkPage, name="permalink"),
    webapp2.Route('/blog/newpost', NewPostPage, name="newpost"),
    webapp2.Route('/blog/<post_id:\d+>/newcomment', NewCommentPage,
                  name="newcomment"),
    webapp2.Route('/blog/welcome', WelcomePage, name="welcome"),
    webapp2.Route('/blog/signup', SignupPage, name="signup"),
    webapp2.Route('/blog/login', LoginPage, name="login"),
    webapp2.Route('/blog/logout', LogoutHandler, name="logout"),
    webapp2.Route('/blog/edit/<post_id:\d+>', PostEditPage, name="post_edit"),
    webapp2.Route('/blog/edit/comment/<comment_id:\d+>', EditCommentPage,
                  name="comment_edit"),
    webapp2.Route('/credits', CreditsPage, name="credits"),
]
