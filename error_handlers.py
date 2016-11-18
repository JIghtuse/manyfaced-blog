from handler import Handler


TEMPLATE_40X = "40x.html"


def render(**kw):
    return Handler.render_template(TEMPLATE_40X, **kw)


def handler_400(request, response, exception):
    page = render(error_title="Bad Request",
                  error_message="This request was invalid.",
                  error_details=exception.message)
    response.write(page)
    response.set_status(400)


def handler_403(request, response, exception):
    page = render(error_title="Forbidden",
                  error_message="Action forbidden.",
                  error_details=exception.message)
    response.write(page)
    response.set_status(403)


def handler_404(request, response, exception):
    page = render(error_title="File Not Found",
                  error_message="No such file found.",
                  error_details=exception.message)
    response.write(page)
    response.set_status(404)
