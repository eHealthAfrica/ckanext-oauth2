# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.

import logging
import constants
import oauth2

import ckan.lib.helpers as helpers
import ckan.lib.base as base

from ckanext.oauth2.plugin import toolkit
from urlparse import urlparse


log = logging.getLogger(__name__)


class OAuth2Controller(base.BaseController):

    def callback(self):
        try:
            oauth2helper = oauth2.OAuth2Helper()
            token = oauth2helper.get_token()
            user_name = oauth2helper.identify(token)
            oauth2helper.remember(user_name)
            oauth2helper.update_token(user_name, token)
            oauth2helper.redirect_from_callback()
        except Exception as e:

            # If the callback is called with an error, we must show the message
            error_description = toolkit.request.GET.get('error_description')
            if not error_description:
                if e.message:
                    error_description = e.message
                elif hasattr(e, 'description') and e.description:
                    error_description = e.description
                elif hasattr(e, 'error') and e.error:
                    error_description = e.error
                else:
                    error_description = type(e).__name__

            toolkit.response.status_int = 302
            redirect_url = oauth2.get_came_from(toolkit.request.params.get('state'))
            redirect_url = '/' if redirect_url == constants.INITIAL_PAGE else redirect_url
            toolkit.response.location = redirect_url
            helpers.flash_error(error_description)

    def _get_previous_page(self, default_page):
        if 'came_from' not in toolkit.request.params:
            came_from_url = toolkit.request.headers.get('Referer', default_page)
        else:
            came_from_url = toolkit.request.params.get('came_from', default_page)

        came_from_url_parsed = urlparse(came_from_url)
        # Avoid redirecting users to external hosts
        if came_from_url_parsed.netloc != '' and came_from_url_parsed.netloc != toolkit.request.host:
            came_from_url = default_page

        # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
        # he/she must be redirected to the dashboard
        pages = ['/', '/user/logged_out_redirect']
        if came_from_url_parsed.path in pages:
            came_from_url = default_page

        return came_from_url

    def oauth_login(self):
        log.debug('Oauth login')

        oauth2helper = oauth2.OAuth2Helper()

        # Log in attemps are fired when the user is not logged in and they click
        # on the log in button

        # Get the page where the user was when the loggin attemp was fired
        # When the user is not logged in, he/she should be redirected to the dashboard when
        # the system cannot get the previous page
        came_from_url = self._get_previous_page(constants.INITIAL_PAGE)

        oauth2helper.challenge(came_from_url)