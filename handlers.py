import logging
import re
from blog_handler import BlogHandler, BlogRegisteredOnlyHandler
from post import Post
from user import User
from vote import Vote


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

    def form_is_valid(self, title, content):
        """Validates form input.
        Returns (True, None) if input is valid,
        Returns (False, parameters to pass to template) if input is invalid"""
        params = dict(title=title, content=content)
        invalid_input = False

        if not title:
            params['post_title_error'] = "Post title cannot be empty"
            invalid_input = True
        if not content:
            params['post_content_error'] = "Post content cannot be empty"
            invalid_input = True

        if invalid_input:
            return False, params
        else:
            return True, None

    def post(self):
        title = self.request.get('title')
        content = self.request.get('content')

        valid_input, params = self.form_is_valid(title, content)
        if valid_input:
            # Creating a post
            post = Post(content=content, title=title,
                        author=self.user.key)
            post.put()

            post_id = post.key.id()
            self.redirect(self.uri_for("permalink", post_id=str(post_id)))
        else:
            self.render_page(**params)


class PostEditPage(NewPostPage):
    """Displays form to edit posts"""

    def current_user_has_permissions(self, post_id):
        post = Post.get_by_id(post_id)
        current_user_id = self.user.key.id()
        has_permissions = post.author.id() == current_user_id
        if not has_permissions:
            logging.warning("User {} tried to change post {}".format(
                current_user_id, post_id))
        return has_permissions

    def get(self, post_id):
        post_id_int = int(post_id)
        post = Post.get_by_id(post_id_int)
        if not post:
            return self.error(404)

        if not self.current_user_has_permissions(post_id_int):
            return self.error(403)

        self.render_page(post_id=post_id,
                         title=post.title, content=post.content)

    def post(self, post_id):
        post_id_int = int(post_id)
        post = Post.get_by_id(post_id_int)
        if not post:
            return self.error(404)

        if not self.current_user_has_permissions(post_id_int):
            return self.error(403)

        title = self.request.get('title')
        content = self.request.get('content')
        valid_input, params = self.form_is_valid(title, content)
        if not valid_input:
            return self.render_page(**params)

        post.content = content
        post.title = title
        post.put()
        self.redirect(self.uri_for("permalink", post_id=post_id))


class PostPermalinkPage(BlogHandler):
    """Displays a single blog post"""

    def post_score(self, post_key):
        return Vote.score(post_key)

    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        if not post:
            self.error(404)
        else:
            author = User.get_by_id(post.author.id())
            self.render("post_permalink.html",
                        post=post, author=author,
                        post_score=self.post_score(post.key))

    def post(self, post_id):
        edit = self.request.get('post-edit', None) is not None
        delete = self.request.get('post-delete', None) is not None
        like = self.request.get('post-like', None) is not None
        unlike = self.request.get('post-unlike', None) is not None

        post = Post.get_by_id(int(post_id))
        current_user_id = self.user.key.id()

        if not post:
            logging.warning("Suspicious request: {}".format(self.request))
            self.error(400)

        change_operation = edit or delete
        post_change_allowed = post.author.id() == current_user_id
        if change_operation and not post_change_allowed:
            logging.warning("User {} tried to change post {}".format(
                current_user_id, post_id))
            return self.error(403)

        score_operation = like or unlike
        post_score_allowed = post.author.id() != current_user_id
        if score_operation and not post_score_allowed:
            logging.warning("User {} tried to like/unlike post {}".format(
                current_user_id, post_id))
            return self.error(403)

        if like:
            Vote.like_post(post.key, self.user.key)
            self.redirect(self.uri_for("permalink", post_id=post_id))
        elif unlike:
            Vote.dislike_post(post.key, self.user.key)
            self.redirect(self.uri_for("permalink", post_id=post_id))
        elif edit:
            self.redirect(self.uri_for("post_edit", post_id=post_id))
        elif delete:
            post.key.delete()
            self.redirect(self.uri_for("home"))
        else:
            logging.warning("Suspicious request: {}".format(self.request))
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
