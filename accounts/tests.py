from django.test import TestCase
from django.urls import reverse


class AccountsURLTests(TestCase):
    def test_login_url_resolves(self):
        """
        Ensure that reverse('login') returns the correct URL path for the login view.
        """
        url = reverse('login')
        self.assertEqual(url, '/accounts/login/')
