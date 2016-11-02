class Link:
    def __init__(self, url, description):
        self.url = url
        self.description = description


# TODO: need to distinguish links for logged in / logged out users
NAVIGATION_LINKS = [Link("/blog/", "Blog homepage"),
                    Link("/blog/newpost", "Add a new post"),
                    Link("/blog/signup", "Signup"),
                    Link("/blog/login", "Login"),
                    Link("/blog/logout", "Logout")]

COMMON_LINKS = {link.url.split('/')[-1]: link.url
                for link in NAVIGATION_LINKS}
COMMON_LINKS["welcome"] = "/blog/welcome"
