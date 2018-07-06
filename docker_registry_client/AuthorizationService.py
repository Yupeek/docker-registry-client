import json
import logging
import os

# import urlparse
import requests
from requests.auth import AuthBase

try:
    from urllib.parse import urlsplit
except ImportError:
    from urlparse import urlsplit

logger = logging.getLogger(__name__)


class DockerConfigAuth(AuthBase):
    def __init__(self, docker_config_path, registry):
        self.registry = registry
        self.docker_config_path = docker_config_path

        with open(docker_config_path, 'r') as f:
            all_tokens = json.load(f)

        self.token_from_config = all_tokens.get('auths', {}).get(registry, {})\
            .get('auth', None)
        if self.token_from_config is None:
            raise Exception("token not found for registry %s in file %s" % (
                registry, docker_config_path))

    def __call__(self, r):
        r.headers['Authorization'] = 'Basic %s' % self.token_from_config


class AuthorizationService(object):
    """This class implements a Authorization Service for Docker registry v2.

    Specification can be found here :
    https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md

    The idea is to delegate authentication to a third party and use a token to
    authenticate to the registry. Token has to be renew each time we change
    "scope".
    """

    DEFAULT_CONFIG_PATH = os.environ.get('HOME') and os.path.join(
        os.environ.get('HOME'), '.docker', 'config.json')

    def __init__(self, registry, url="", auth=None, verify=False,
                 api_timeout=None, config_path=None):
        # Registry ip:port
        self.registry = urlsplit(registry).netloc
        # Service url, ip:port
        self.url = url
        # Authentication (user, password) or None. Used by request to do
        # basicauth
        if auth is None and self.DEFAULT_CONFIG_PATH:
            try:
                self.auth = DockerConfigAuth(
                    config_path or self.DEFAULT_CONFIG_PATH,
                    registry
                )
            except Exception:
                self.auth = None
                raise
        else:
            self.auth = auth
        # Timeout for HTTP request
        self.api_timeout = api_timeout

        # Desired scope is the scope needed for the next operation on the
        # registry
        self.desired_scope = ""
        # Scope of the token we have
        self.scope = ""
        # Token used to authenticate
        self.token = ""
        # Boolean to enfore https checks. Used by request
        self.verify = verify

        # If we have no url then token are not required. get_new_token will not
        # be called
        if url:
            split = urlsplit(url)
            # user in url will take precedence over giver username
            if split.username and split.password:
                self.auth = (split.username, split.password)

            self.token_required = True
        else:
            self.token_required = False

    def get_new_token(self):
        rsp = requests.get("%s/v2/token?service=%s&scope=%s" %
                           (self.url, self.registry, self.desired_scope),
                           auth=self.auth, verify=self.verify,
                           timeout=self.api_timeout)
        if not rsp.ok:
            logger.error("Can't get token for authentication")
            self.token = ""

        self.token = rsp.json()['token']
        # We managed to get a new token, update the current scope to the one we
        # wanted
        self.scope = self.desired_scope
