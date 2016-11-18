"""Multi-user blog"""

import webapp2
from routes import COMMON_ROUTES
from error_handlers import handler_400, handler_403, handler_404


app = webapp2.WSGIApplication(COMMON_ROUTES, debug=True)
app.error_handlers[400] = handler_400
app.error_handlers[403] = handler_403
app.error_handlers[404] = handler_404
