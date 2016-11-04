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
            self.redirect("/blog/" + str(post_id))
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


class WelcomePage(BlogRegisteredOnlyHandler):
    """Displays greeting for logged in user"""
    def get(self):
        self.render("welcome.html", username=self.user.name)


class SignupPage(BlogHandler):
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

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

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
            self.render("signup.html", **template_params)
        else:
            user = User.register(username, password, email)
            user.put()

            self.login(user)
            self.redirect("/blog/welcome")


class LoginPage(BlogHandler):
    def get(self):
        self.render("login.html", username="")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect("/blog/welcome")
        else:
            self.render("login.html",
                        username=username,
                        login_error="Invalid login")


class LogoutHandler(BlogRegisteredOnlyHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
        self.redirect("/blog/signup")
