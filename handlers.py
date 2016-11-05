import logging
import re
from blog_handler import BlogHandler, BlogRegisteredOnlyHandler
from post import Post
from user import User


class HomePage(BlogHandler):
    """Displays blog home page with posts"""
    def get(self):
        posts = Post.query().order(-Post.creation_date).fetch(limit=10)
        self.render("main_page.html", posts=posts)


class NewPostPage(BlogRegisteredOnlyHandler):
    """Displays form to submit new posts"""
    def render_page(self, **kw):
        self.render("new_post.html", **kw)

    def get(self):
        self.render_page()

    def post(self):
        title = self.request.get('title')
        content = self.request.get('content')
        params = dict(title=title, content=content)

        if content and title:
            # Creating a post
            post = Post(content=content, title=title,
                        author=self.user.key)
            post.put()

            # Redirecting to post permalink page
            post_id = post.key.id()
            self.redirect(self.uri_for("permalink", post_id=str(post_id)))
        else:
            # Showing errors
            if not title:
                params['post_title_error'] = "Post title cannot be empty"
            if not content:
                params['post_content_error'] = "Post content cannot be empty"
            self.render_page(**params)


class PostPermalinkPage(BlogHandler):
    """Displays a single blog post"""
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        if not post:
            self.error(404)
        else:
            author = User.get_by_id(post.author.id())
            self.render("post_permalink.html", post=post, author=author)

    def post(self, post_id):
        edit = self.request.get('post-edit', None)
        delete = self.request.get('post-delete', None)

        post = Post.get_by_id(int(post_id))
        current_user_id = self.user.key.id()

        if not post:
            logging.warning("Suspicious request: " + str(self.request))
            self.error(400)

        if post.author.id() != current_user_id:
            logging.warning("User {} tried to change post {}".format(
                current_user_id,
                post_id))
            return self.error(403)

        if edit is not None:
            self.write("editing post")
        elif delete is not None:
            post.key.delete()
            self.redirect(self.uri_for("home"))
        else:
            logging.warning("Suspicious request: " + str(self.request))
            self.error(400)


class WelcomePage(BlogRegisteredOnlyHandler):
    """Displays greeting for logged in user"""
    def get(self):
        self.render("welcome.html", username=self.user.name)


class SignupPage(BlogHandler):
    """Displays form allowing user to sign up.
    Adds user to database after successful registration"""
    USERNAME_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD_RE = re.compile("^.{3,20}$")
    EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")

    def valid_username(self, username):
        return SignupPage.USERNAME_RE.match(username)

    def valid_password(self, password):
        return SignupPage.PASSWORD_RE.match(password)

    def valid_email(self, email):
        return SignupPage.EMAIL_RE.match(email)

    def get(self):
        self.render("signup.html", username="")

    def form_is_valid(self, username, password, verify, email):
        """Validates form input.
        Returns (True, None) if input is valid,
        Returns (False, parameters to pass to template) if input is invalid"""

        template_params = dict(username=username, email=email)
        invalid_input = False

        # TODO: show valid values
        if not self.valid_username(username):
            template_params['username_error'] = "Invalid username"
            invalid_input = True
        if not self.valid_password(password):
            template_params['password_error'] = "Invalid password"
            invalid_input = True
        if password != verify:
            template_params['verify_error'] = "Passwords doesn't match"
            invalid_input = True
        if email and not self.valid_email(email):
            template_params['email_error'] = "Invalid email"
            invalid_input = True

        existing_user = User.by_name(username)
        if existing_user:
            template_params['username_error'] = "Such user already exists"
            invalid_input = True

        if invalid_input:
            return False, template_params
        else:
            return True, None

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        valid_input, params = self.form_is_valid(username, password,
                                                 verify, email)

        if not valid_input:
            self.render("signup.html", **params)
        else:
            user = User.register(username, password, email)
            user.put()

            self.login(user)
            self.redirect(self.uri_for("welcome"))


class LoginPage(BlogHandler):
    def render_login_form(self, username="", login_error=None):
        self.render("login.html", username=username, login_error=login_error)

    def get(self):
        self.render_login_form()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect(self.uri_for("welcome"))
        else:
            self.render_login_form(username, "Invalid login")


class LogoutHandler(BlogRegisteredOnlyHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
        self.redirect(self.uri_for("signup"))
