# -*- coding: utf-8 -*-
#
# REST endpoint Authentication module for Matrix synapse
# Copyright (C) 2017 Kamax Sarl
#
# https://www.kamax.io/
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import logging
import requests
import json
import time

logger = logging.getLogger(__name__)


class RestAuthProvider(object):

    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        if not config.endpoint:
            raise RuntimeError('Missing endpoint config')

        self.endpoint = config.endpoint
        self.api_token = config.api_token
        self.regLower = config.regLower
        self.config = config

        logger.info('Endpoint: %s', self.endpoint)
        logger.info('API Token provided: %s', 'Yes' if self.api_token else 'No')
        logger.info('Enforce lowercase username during registration: %s', self.regLower)

    async def check_password(self, user_id, password):
        logger.info("Got password check for %s", user_id)
    
        # Extract the localpart from user_id (e.g., '@username:domain.com' -> 'username')
        if user_id.startswith('@'):
            localpart = user_id[1:].split(':', 1)[0]
        else:
            localpart = user_id.split(':', 1)[0]
    
        logger.info("Extracted localpart (username): %s", localpart)
    
        # Prepare data payload
        data = {
            'api_token': self.api_token,
            'username': localpart,
            'password': password
        }
    
        # Send the POST request to your Laravel API
        try:
            response = requests.post(self.endpoint, data=data)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error("HTTP request failed: %s", e)
            return False
    
        # Parse the response
        try:
            result = response.json()
            logger.debug("Response from authentication server: %s", result)
        except ValueError:
            logger.error("Invalid JSON response")
            return False
    
        # Check the authentication result
        if result.get('success'):
            logger.info("Authentication successful for user %s", user_id)
        else:
            logger.info("Authentication failed for user %s", user_id)
            return False
    
        # Proceed with registration or login in Synapse
        registration = False
        if not (await self.account_handler.check_user_exists(user_id)):
            logger.info("User %s does not exist yet, creating...", user_id)
    
            if localpart != localpart.lower() and self.regLower:
                logger.info('User %s cannot be created due to username lowercase policy', localpart)
                return False
    
            user_id, access_token = await self.account_handler.register(localpart=localpart)
            registration = True
            logger.info("Registration based on REST data was successful for %s", user_id)
        else:
            logger.info("User %s already exists, registration skipped", user_id)
    
        # Return True to indicate successful authentication
        return True


    @staticmethod
    def parse_config(config):
        # verify config sanity
        _require_keys(config, ["endpoint", "api_token"])

        class _RestConfig(object):
            endpoint = ''
            api_token = ''
            regLower = True
            setNameOnRegister = True
            setNameOnLogin = False
            updateThreepid = True
            replaceThreepid = False

        rest_config = _RestConfig()
        rest_config.endpoint = config["endpoint"]
        rest_config.api_token = config["api_token"]

        try:
            rest_config.regLower = config['policy']['registration']['username']['enforceLowercase']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.setNameOnRegister = config['policy']['registration']['profile']['name']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.setNameOnLogin = config['policy']['login']['profile']['name']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.updateThreepid = config['policy']['all']['threepid']['update']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.replaceThreepid = config['policy']['all']['threepid']['replace']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        return rest_config


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "REST Auth enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )


def time_msec():
    """Get the current timestamp in milliseconds
    """
    return int(time.time() * 1000)
