import logging
import re
from blog_handler import BlogHandler, BlogRegisteredOnlyHandler
from post import Post, Comment
from user import User


def get_post_from_request(self, post_id=None):
    """Gets post corresponding to post_id or self.request['post_id']
    Returns (None, None) if there is no post_id or no post corresponding to it
    Returns (post, post_id) if request has post_id"""
    post_id = post_id or self.request.get('post_id')
    post_id = int(post_id)
    if post_id is None:
        logging.warning("Suspicious request (no post id): {}".format(
            self.request))
        return None, None
    post = Post.get_by_id(int(post_id))
    if not post:
        return None, None
    return post, post_id


def make_vote(self, post, like, unlike):
    """Checks permissions and allows to like/unlike post if user has rights"""

    if like and unlike:
        logging.warning("Suspicious request (like and unlike): {}".format(
            self.request))
        return self.abort(400, "Liking and unliking simultaneosly forbidden")

    if not self.user:
        return self.redirect_to_uri("signup")

    if post.author.id() != self.user.key.id():
        if like:
            post.like(self.user.key)
            return self.redirect(self.request.url)
        elif unlike:
            post.dislike(self.user.key)
            return self.redirect(self.request.url)
    logging.warning("Suspicious request (user votes for himself): {}".format(
        self.request))
    return self.abort(403, "Voting for yourself forbidden")


def make_change(self, post, edit, delete):
    """Checks permissions and allows to edit/delete post if user has rights"""

    if edit and delete:
        logging.warning("Suspicious request (edit and delete): {}".format(
            self.request))
        return self.abort(400, "Edit and delete simultaneosly forbidden")

    if not self.user:
        return self.redirect_to_uri("signup")

    if post.author.id() == self.user.key.id():
        if edit:
            return self.redirect_to_uri("post_edit", post_id=post.key.id())
        elif delete:
            post.key.delete()
            return self.redirect_to_uri("home")
    logging.warning(
        "Suspicious request (user changes post of another user): {}".format(
            self.request))
    return self.abort(403, "You cannot change other user posts")


def make_comment_change(self, comment_id, edit, delete):
    """Checks permissions and allows to edit/delete comment"""

    if edit and delete:
        logging.warning("Forbidden edit and delete: {}".format(self.request))
        return self.abort(400, "Edit and delete simultaneosly forbidden")

    if not self.user:
        return self.redirect_to_uri("signup")

    comment = Comment.get_by_id(int(comment_id))
    if not comment:
        return self.abort(404, "No comment associated with request")

    key = comment.key

    if comment.user.id() == self.user.key.id():
        if edit:
            return self.redirect_to_uri("comment_edit", comment_id=key.id())
        elif delete:
            comment.key.delete()
            return self.redirect_to_uri("permalink", post_id=comment.post.id())
    logging.warning("User forbidden to change comment: {}".format(
        self.request))
    return self.abort(403, "You cannot change other user comments")


class HomePage(BlogHandler):
    """Displays blog home page with posts"""

    def get(self):
        posts = Post.query().order(-Post.creation_date).fetch(limit=10)
        self.render("main_page.html", posts=posts)

    def post(self):
        like = self.request.get('post-like', None) is not None
        unlike = self.request.get('post-unlike', None) is not None
        comment = self.request.get('post-comment', None) is not None

        post, post_id = get_post_from_request(self)
        if not post:
            return self.abort(404, "No post associated with request")

        if like or unlike:
            return make_vote(self, post, like, unlike)
        elif comment:
            return self.redirect_to_uri('newcomment', post_id=post_id)
        else:
            logging.warning("Suspicious request (no user action): {}".format(
                self.request))
            return self.abort(400, "No action in request")


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
            post = Post(content=content, title=title, author=self.user.key)
            post.put()

            post_id = post.key.id()
            self.redirect_to_uri("permalink", post_id=str(post_id))
        else:
            self.render_page(**params)


class PostEditPage(NewPostPage):
    """Displays form to edit posts"""

    def current_user_has_permissions(self, post_id):
        post, post_id = get_post_from_request(self, post_id)
        if not post:
            return self.abort(404, "No post associated with request")
        current_user_id = self.user.key.id()
        has_permissions = post.author.id() == current_user_id
        if not has_permissions:
            logging.warning("User {} tried to change post {}".format(
                current_user_id, post_id))
        return has_permissions

    def get(self, post_id):
        post, post_id = get_post_from_request(self, post_id)
        if not post:
            return self.abort(404, "No post associated with request")

        if not self.current_user_has_permissions(post_id):
            return self.abort(403, "You cannot change other user posts")

        self.render_page(
            post_id=post_id, title=post.title, content=post.content)

    def post(self, post_id):
        post, post_id = get_post_from_request(self, post_id)
        if not post:
            return self.abort(404, "No post associated with request")

        if not self.current_user_has_permissions(post_id):
            return self.abort(403, "You cannot change other user posts")

        title = self.request.get('title')
        content = self.request.get('content')
        valid_input, params = self.form_is_valid(title, content)
        if not valid_input:
            return self.render_page(**params)

        post.content = content
        post.title = title
        post.put()
        self.redirect_to_uri("permalink", post_id=post_id)


class PostPermalinkPage(BlogHandler):
    """Displays a single blog post"""

    def get(self, post_id):
        post, post_id = get_post_from_request(self, post_id)
        if not post:
            return self.abort(404, "No post associated with request")
        else:
            author = User.get_by_id(post.author.id())
            self.render("post_permalink.html", post=post, author=author)

    def post(self, post_id):
        edit = self.request.get('post-edit', None) is not None
        delete = self.request.get('post-delete', None) is not None

        like = self.request.get('post-like', None) is not None
        unlike = self.request.get('post-unlike', None) is not None

        comment = self.request.get('post-comment', None) is not None

        comment_id = self.request.get('comment_id')
        comment_edit = self.request.get('comment-edit', None) is not None
        comment_delete = self.request.get('comment-delete', None) is not None

        post, post_id = get_post_from_request(self, post_id)
        if not post:
            return self.abort(404, "No post associated with request")

        if like or unlike:
            return make_vote(self, post, like, unlike)
        elif edit or delete:
            return make_change(self, post, edit, delete)
        elif comment:
            return self.redirect_to_uri('newcomment', post_id=post_id)
        elif comment_id and (comment_edit or comment_delete):
            return make_comment_change(self, comment_id,
                                       comment_edit, comment_delete)
        else:
            logging.warning("Suspicious request (no user action): {}".format(
                self.request))
            return self.abort(400, "No action in request")


class NewCommentPage(BlogRegisteredOnlyHandler):
    """Displays form to submit new posts"""

    def render_page(self, **kw):
        self.render("new_comment.html", **kw)

    def get(self, post_id):
        post, post_id = get_post_from_request(self, post_id)
        if not post:
            return self.abort(404, "No post associated with request")

        self.render_page(post_id=post_id)

    def post(self, post_id):
        text = self.request.get('comment-text')
        params = dict(comment_text=text)

        post, post_id = get_post_from_request(self, post_id)
        if not post:
            return self.abort(404, "No post associated with request")
        params['post_id'] = post_id

        if text:
            # Creating comment
            comment = Comment(user=self.user.key, post=post.key, content=text)
            comment.put()

            self.redirect_to_uri("permalink", post_id=post_id)
        else:
            params['comment_error'] = "Comment cannot be empty"
            self.render_page(**params)


class EditCommentPage(BlogRegisteredOnlyHandler):
    """Displays form to submit new posts"""

    def render_page(self, **kw):
        self.render("new_comment.html", **kw)

    def get(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if not comment:
            return self.abort(404, "No comment associated with request")
        self.render_page(post_id=comment.post.id(), content=comment.content)

    def post(self, comment_id):
        text = self.request.get('comment-text')
        params = dict(comment_text=text)

        comment = Comment.get_by_id(int(comment_id))
        if not comment:
            return self.abort(404, "No comment associated with request")

        post_id = comment.post.id()
        params['post_id'] = post_id

        if text:
            comment.content = text
            comment.put()

            self.redirect_to_uri("permalink", post_id=post_id)
        else:
            params['comment_error'] = "Comment cannot be empty"
            self.render_page(**params)


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

        valid_input, params = self.form_is_valid(username, password, verify,
                                                 email)

        if not valid_input:
            self.render("signup.html", **params)
        else:
            user = User.register(username, password, email)
            user.put()

            self.login(user)
            self.redirect_to_uri("welcome")


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
            self.redirect_to_uri("welcome")
        else:
            self.render_login_form(username, "Invalid login")


class LogoutHandler(BlogRegisteredOnlyHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
        self.redirect_to_uri("signup")


class CreditsPage(BlogHandler):
    def get(self):
        self.render("credits.html")
