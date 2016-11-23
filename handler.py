import os
import re
import jinja2
import webapp2
from jinja2 import evalcontextfilter, Markup, escape


@evalcontextfilter
def nl2br(eval_ctx, value):
    value = escape(value)
    result = u'\n\n'.join(u'<p>%s</p>' % p.replace('\n', Markup('<br>\n'))
                          for p in Handler.PARAGRAPH_RE.split(value))
    if eval_ctx.autoescape:
        result = Markup(result)
    return result


class Handler(webapp2.RequestHandler):
    """Extends webapp2 handler to use jinja2 template files"""

    PARAGRAPH_RE = re.compile(r'(?:\r\n|\r|\n){2,}')
    TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')
    JINJA_FS_LOADER = jinja2.FileSystemLoader(TEMPLATES_DIR)
    JINJA_ENV = jinja2.Environment(loader=JINJA_FS_LOADER, autoescape=True)
    JINJA_ENV.filters['nl2br'] = nl2br
    JINJA_ENV.globals['uri_for'] = webapp2.uri_for

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

    def redirect_to_uri(self, uri_name, **kw):
        return self.redirect(self.uri_for(uri_name, **kw))
