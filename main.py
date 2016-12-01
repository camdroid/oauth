from flask import Flask
from flask import abort, request
from secrets import reddit_id, reddit_secret, reddit_redirect_uri, reddit_auth_url
from secrets import goodreads_id, goodreads_auth_url, goodreads_redirect_url
from uuid import uuid4
import requests
import requests.auth
import urllib

app = Flask(__name__)

@app.route('/')
def homepage():
    text = '<a href="%s">Authenticate with reddit</a>'
    return text % make_authorization_url(
         reddit_id, reddit_auth_url,
         reddit_redirect_uri
        #goodreads_id, goodreads_auth_url, goodreads_redirect_url
    )

def make_authorization_url(_id=None, authorization_url=None, redirect_url=None):
    # Generate a random string for the state parameter
    # Save it for use later to prevent xsrf attacks
    state = str(uuid4())
    save_created_state(state)
    params = {"client_id": _id,
              "response_type": "code",
              "state": state,
              "redirect_uri": redirect_url,
              "duration": "temporary",
              "scope": "identity"}
    url = authorization_url + urllib.parse.urlencode(params)
    return url

@app.route('/reddit_callback')
def reddit_callback():
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = request.args.get('state', '')
    if not is_valid_state(state):
        # Uh-oh, this request wasn't started by us!
        abort(403)
    code = request.args.get('code')
    # We'll change this next line in just a moment
    import pdb; pdb.set_trace()
    return 'Username: {}'.format(get_reddit_username(get_token(code)))

def get_token(code):
    client_auth = requests.auth.HTTPBasicAuth(reddit_id, reddit_secret)
    post_data = {"grant_type": "authorization_code",
                 "code": code,
                 "redirect_uri": reddit_redirect_uri}
    response = requests.post("https://ssl.reddit.com/api/v1/access_token",
                             auth=client_auth,
                             data=post_data)
    token_json = response.json()
    if 'error' in token_json:
        raise Exception(token_json['message'])

    return token_json["access_token"]

def get_reddit_username(access_token):
    headers = {'Authorization': 'bearer ' + access_token}
    response = requests.get('https://oauth.reddit.com/api/v1/me', headers=headers)
    res_json = response.json()
    return res_json['name']

# Left as an exercise to the reader.
# You may want to store valid states in a database or memcache,
# or perhaps cryptographically sign them and verify upon retrieval.
def save_created_state(state):
    pass
def is_valid_state(state):
    return True


if __name__ == '__main__':
    app.run(debug=True, port=65010)

