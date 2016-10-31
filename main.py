"""Multi-user blog"""

import os
import jinja2
import webapp2


class Handler(webapp2.RequestHandler):
    """Extends webapp2 handler to use jinja2 template files"""

    TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')
    JINJA_FS_LOADER = jinja2.FileSystemLoader(TEMPLATES_DIR)
    JINJA_ENV = jinja2.Environment(loader=JINJA_FS_LOADER, autoescape=True)

    @classmethod
    def render_template(cls, template_filename, **params):
        """Renders jinja2 template with specified params"""
        template = cls.JINJA_ENV.get_template(template_filename)
        return template.render(params)

    def write(self, *a, **kw):
        """Writes input parameters to output"""
        self.response.out.write(*a, **kw)

    def render(self, template_filename, **kw):
        """Use helper functions to output template with specified parameters"""
        self.write(Handler.render_template(template_filename, **kw))


class MainPage(Handler):
    """Handles blog main page"""

    def get(self):
        """Displays posts in blog"""
        self.render("main_page.html", posts=[])


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog', MainPage),
], debug=True)
