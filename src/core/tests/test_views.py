__copyright__ = "Copyright 2024 Birkbeck, University of London"
__author__ = "Open Library of Humanities"
__license__ = "AGPL v3"
__maintainer__ = "Open Library of Humanities"

from uuid import uuid4
from django.test import Client, TestCase, override_settings
from mock import patch

from utils.testing import helpers

from core import models as core_models


class NextURLTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.press = helpers.create_press()
        cls.journal_one, cls.journal_two = helpers.create_journals()
        helpers.create_roles(['author'])
        cls.user_email = 'sukv8golcvwervs0y7e5@example.org'
        cls.user_password = 'xUMXW1oXn2l8L26Kixi2'
        cls.user = core_models.Account.objects.create_user(
            email=cls.user_email,
            password=cls.user_password,
        )
        cls.user_orcid = 'https://orcid.org/0000-0001-2345-6789'
        cls.user.orcid = cls.user_orcid
        cls.orcid_token_str = uuid4()
        cls.orcid_token = core_models.AccountToken.objects.create(
            token=cls.orcid_token_str,
            identifier=cls.user_orcid,
        )
        cls.reset_token_str = uuid4()
        cls.reset_token = core_models.AccountToken.objects.create(
            account=cls.user,
            token=cls.reset_token_str,
        )
        cls.user.save()

        # The unicode string of a 'next' URL
        cls.next_url = '/target/page/?a=b&x=y'
        # The above string url-encoded with safe='/'
        cls.next_url_encoded = '/target/page/%3Fa%3Db%26x%3Dy'
        # The above string prepended with 'next='
        cls.next_url_query_string = 'next=/target/page/%3Fa%3Db%26x%3Dy'
        # The core_login url with encoded next url
        cls.core_login_with_next = '/login/?next=/target/page/%3Fa%3Db%26x%3Dy'

    def setUp(self):
        self.client = Client()

    @patch('core.views.authenticate')
    @override_settings(ENABLE_OIDC=True)
    def test_user_login_oidc_link_next_url(self, authenticate):
        authenticate.return_value = None
        data = {
            'next': self.next_url_encoded,
        }
        response = self.client.get('/login/', data, follow=True)
        self.assertIn(
            f'/oidc/authenticate?next={self.next_url_encoded}',
            response.content.decode(),
        )

    @patch('core.views.orcid.get_orcid_record_details')
    @patch('core.views.orcid.retrieve_tokens')
    @override_settings(ENABLE_ORCID=True)
    def test_user_login_orcid_next_url_no_backup_email(
        self,
        retrieve_tokens,
        orcid_details,
    ):
        # Change ORCID so it doesn't work
        retrieve_tokens.return_value = 'https://orcid.org/0000-0001-2312-3123'

        orcid_details.return_value = {'emails': []}
        data = {
            'code': '12345',
            'next': self.next_url,
        }
        response = self.client.get('/login/orcid/', data, follow=True)
        self.assertIn(
            self.next_url_query_string,
            response.redirect_chain[0][0],
        )

    @patch('core.views.orcid.retrieve_tokens')
    @override_settings(ENABLE_ORCID=True)
    def test_user_login_orcid_next_url_cannot_retrieve(self, retrieve_tokens):
        retrieve_tokens.return_value = None
        data = {
            'code': '12345',
            'next': self.next_url,
        }
        response = self.client.get('/login/orcid/', data, follow=True)
        self.assertIn((self.core_login_with_next, 302), response.redirect_chain)

    @patch('core.views.orcid.retrieve_tokens')
    @override_settings(ENABLE_ORCID=True)
    def test_user_login_orcid_next_url_no_code(self, retrieve_tokens):
        retrieve_tokens.return_value = self.user_orcid
        data = {
            'next': self.next_url,
        }
        response = self.client.get('/login/orcid/', data, follow=True)
        self.assertIn((self.core_login_with_next, 302), response.redirect_chain)

    @patch('core.views.logic.start_reset_process')
    def test_get_reset_token_next_url(self, _start_reset):
        data = {
            'email_address': self.user_email,
            'next': self.next_url,
        }
        response = self.client.post('/reset/step/1/', data, follow=True)
        self.assertIn((self.core_login_with_next, 302), response.redirect_chain)

    @patch('core.views.logic.password_policy_check')
    def test_reset_password_next_url(self, password_check):
        password_check.return_value = None
        data = {
            'password_1': 'qsX1roLama3ADotEopfq',
            'password_2': 'qsX1roLama3ADotEopfq',
            'next': self.next_url,
        }
        reset_step_2_path = f'/reset/step/2/{self.reset_token.token}/'
        response = self.client.post(reset_step_2_path, data, follow=True)
        self.assertIn((self.core_login_with_next, 302), response.redirect_chain)

    @patch('core.views.logic.password_policy_check')
    @override_settings(CAPTCHA_TYPE='')
    @override_settings(ENABLE_ORCID=True)
    def test_user_register_email_next_url(self, password_check):
        password_check.return_value = None
        data = {
            'email': 'kjhsaqccxf7qfwirhqia@example.org',
            'password_1': 'qsX1roLama3ADotEopfq',
            'password_2': 'qsX1roLama3ADotEopfq',
            'first_name': 'New',
            'last_name': 'User',
            'next': self.next_url,
        }
        response = self.client.post('/register/step/1/', data, follow=True)
        self.assertIn((self.core_login_with_next, 302), response.redirect_chain)

    @patch('core.views.orcid.get_orcid_record_details')
    @patch('core.views.logic.password_policy_check')
    @override_settings(CAPTCHA_TYPE='')
    @override_settings(ENABLE_ORCID=True)
    def test_user_register_orcid_next_url(self, password_check, get_orcid_details):
        get_orcid_details.return_value = {}
        password_check.return_value = None
        data = {
            'email': 'kjhsaqccxf7qfwirhqia@example.org',
            'password_1': 'qsX1roLama3ADotEopfq',
            'password_2': 'qsX1roLama3ADotEopfq',
            'first_name': 'New',
            'last_name': 'User',
            'token': self.orcid_token_str,
            'next': self.next_url,
        }
        response = self.client.post('/register/step/1/', data, follow=True)
        self.assertIn((self.core_login_with_next, 302), response.redirect_chain)

    @patch('core.views.models.Account.objects.get')
    def test_activate_account_next_url(self, objects_get):
        objects_get.return_value = self.user
        data = {
            'next': self.next_url,
        }
        response = self.client.post('/register/step/2/12345/', data, follow=True)
        self.assertIn((self.core_login_with_next, 302), response.redirect_chain)

    @patch('core.views.authenticate')
    def test_user_login_next_url(self, authenticate):
        authenticate.return_value = self.user
        data = {
            'user_name': self.user_email,
            'user_pass': self.user_password,
            'next': self.next_url,
        }
        response = self.client.post('/login/', data, follow=True)
        self.assertIn((self.next_url, 302), response.redirect_chain)

    @patch('core.views.orcid.retrieve_tokens')
    @override_settings(ENABLE_ORCID=True)
    def test_user_login_orcid_next_url(self, retrieve_tokens):
        retrieve_tokens.return_value = self.user_orcid
        orcid_token = core_models.AccountToken.objects.create()
        data = {
            'code': '12345',
            'state': orcid_token.token,
        }
        response = self.client.get('/login/orcid/', data, follow=True)
        self.assertIn((self.next_url, 302), response.redirect_chain)

    @patch('core.views.orcid.get_orcid_record_details')
    @patch('core.views.orcid.retrieve_tokens')
    @override_settings(ENABLE_ORCID=True)
    def test_user_login_orcid_next_url_backup_email(
        self,
        retrieve_tokens,
        orcid_details,
    ):
        # Change ORCID so it doesn't work
        retrieve_tokens.return_value = 'https://orcid.org/0000-0001-2312-3123'
        orcid_details.return_value = {'emails': [self.user_email]}

        orcid_token = core_models.AccountToken.objects.create()
        data = {
            'code': '12345',
            'state': orcid_token.token,
        }
        response = self.client.get('/login/orcid/', data, follow=True)
        self.assertIn((self.next_url, 302), response.redirect_chain)
