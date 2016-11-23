# manyfaced-blog
Multi-user blog for backend project on Udacity

## Requirements

You will need a Google App Engine SDK to make your own instance of this project
or to test it. See [Quickstart](https://cloud.google.com/appengine/docs/python/quickstart)
document for details on how to install SDK.


## Installation and Running

Clone this project source code from Github:

        $ git clone https://github.com/JIghtuse/manyfaced-blog.git
        $ cd manyfaced-blog

All the other steps can be done by App Engine tools.

You can launch development server to test application on your machine:

        $ dev_appserver.py .

To deploy application to Google App Engine, execute following command:

        $ gcloud app deploy

See [Deploying a Python App](https://cloud.google.com/appengine/docs/python/tools/uploadinganapp)
for details.


## Usage

Non-authorized users can only see blog posts and comments.

Authorized users can write new posts, edit and delete their posts. They
also write/edit/delete their comments. Changing content of other users is
forbidden. There is a like/dislike buttons for each post, and authorized
user can vote for other users posts (NOT for their own). User can vote for
a single post only one time.
