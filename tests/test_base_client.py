from __future__ import absolute_import

import json
import os
import tempfile

from docker_registry_client._BaseClient import BaseClientV1, BaseClientV2
from docker_registry_client.AuthorizationService import AuthorizationService
from drc_test_utils.mock_registry import (TEST_NAME, TEST_TAG,
                                          mock_v1_registry, mock_v2_registry)


class TestBaseClientV1(object):
    def test_check_status(self):
        url = mock_v1_registry()
        BaseClientV1(url).check_status()


class TestBaseClientV2(object):
    def test_check_status(self):
        url = mock_v2_registry()
        BaseClientV2(url).check_status()

    def test_get_manifest_and_digest(self):
        url = mock_v2_registry()
        manifest, digest = BaseClientV2(url).get_manifest_and_digest(TEST_NAME,
                                                                     TEST_TAG)

    def test_get_config(self):
        url = mock_v2_registry()
        t = tempfile.NamedTemporaryFile(delete=False)
        t.write(json.dumps({
            "auths": {
                url: {
                    "auth": "ocucouhibou=="
                },
                "https://index.docker.io/v1/": {
                    "auth": "lolilol==",
                    "email": "github@exemple.com"
                },
            }}).encode('utf-8'))
        t.close()

        AuthorizationService.DEFAULT_CONFIG_PATH = t.name

        c = BaseClientV2(url)
        c.check_status()
        assert c.auth.auth is not None
        assert c.auth.auth.token_from_config == "ocucouhibou=="

        os.unlink(t.name)

    def test_basic_auth(self):
        url = mock_v2_registry()

        AuthorizationService.DEFAULT_CONFIG_PATH = None

        c = BaseClientV2(url, username='toto', password='tete')
        c.check_status()
        assert c.auth.auth is not None
        assert c.auth.auth == ('toto', 'tete')
