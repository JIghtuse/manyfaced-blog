"""Multi-user blog"""

import webapp2
from routes import COMMON_ROUTES


app = webapp2.WSGIApplication(COMMON_ROUTES, debug=True)
