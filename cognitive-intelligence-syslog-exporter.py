#!/usr/bin/env python

"""
This script will get Cognitive Intelligence incidents from a Stealthwatch Enterprise SMC and send them as syslog.

For more information on these APIs, please visit:
https://developer.cisco.com/docs/stealthwatch/enterprise/

 -

See README.md for installation, configuration, and user guides.

 -

Copyright (c) 2020, Cisco Systems, Inc. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import unicode_literals
import base64
import six
from Crypto import Random
from Crypto.PublicKey import RSA
import random
import string
import configparser
import requests
import logging
import logging.handlers
import getpass
import socket
import json
import sys
import os
import datetime

'''
Initializes the logger
'''
def _initialize_logger():
    # gets log path (and creates log directory if it doesn't already exist)
    log_directory = "{}/logs".format(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isdir(log_directory):
        os.mkdir(log_directory)
    log_file = 'cognitive-intelligence-syslog-exporter.log'
    log_path = os.path.join(log_directory, log_file)
    # creates the log handler
    handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)-s -- %(module)s:%(lineno)d - %(message)s'))
    # creates the logger
    logger = logging.getLogger(log_file[-4])
    logger.setLevel('INFO')
    logger.addHandler(handler)
    # returns the logger object
    return logger


'''
Prints messages to both stdout and logger
'''
def _print_message(logger, message, error=None):
    # if no error occurred
    if error is None:
        print(message)
        logger.info(message)
    # if an error occurred
    else:
        print(message)
        print(error)
        logger.error(message)
        logger.error(error)


'''
Get the configuration file
'''
def get_config(logger):
    # Get the config file path
    config_path = "{}/env.conf".format(os.path.dirname(os.path.abspath(__file__)))
    _print_message(logger, "Attempting to read configuration file \"{}\".".format(config_path))
    # if config file does not exist, create it
    if not os.path.isfile(config_path):
        create_config(config_path, logger)
    # read in the config file
    config = configparser.ConfigParser()
    config.read(config_path)
    # if config file is not populated or formatted correctly, create a new one
    if "STEALTHWATCH" not in config or config["STEALTHWATCH"]["SMC"] is None or len(config["STEALTHWATCH"]["SMC"]) == 0:
        create_config(config_path, logger)
        # read in the new config file
        config = configparser.ConfigParser()
        config.read(config_path)
    _print_message(logger, "Done reading configuration file \"{}\".".format(config_path))
    return config


'''
Create a new configuration file
'''
def create_config(config_path, logger):
    _print_message(logger, "The configuration file \"{}\" does not exist (or contains errors).".format(config_path))
    _print_message(logger, "Generating configuration file \"{}\"...".format(config_path))
    # if config file already exists, delete it to create a new one
    if os.path.isfile(config_path):
        os.remove(config_path)
    # get the config values from the user
    smc = input("SMC IP: ")
    user = input("SMC user (must have \"master admin\" role): ")
    password = getpass.getpass("SMC user's password: ")
    rsa = RSAEncryption()
    encrypted_password = rsa.encrypt(password).decode('ascii')
    destination = input("Syslog Destination IP: ")
    port = input("Syslog destination port: ")
    # write the config values to the new config file
    with open(config_path, "w") as conf_file:
        conf_file.write("[STEALTHWATCH]")
        conf_file.write("\nSMC = {}".format(smc))
        conf_file.write("\nUSER = {}".format(user))
        conf_file.write("\nPASSWORD = {}".format(encrypted_password))
        conf_file.write("\n\n[SYSLOG]")
        conf_file.write("\nDESTINATION = {}".format(destination))
        conf_file.write("\nPORT = {}".format(port))
    _print_message(logger, "Done generating configuration file \"{}\".".format(config_path))


'''
Create timestamp file for when the last query ran
'''
def update_last_run_timestamp(timestamp):
    # Get the timestamp file path
    timestamp_path = "{}/logs/.timestamp".format(os.path.dirname(os.path.abspath(__file__)))
    # write the timestamp of the last runtime to a file
    with open(timestamp_path, "w") as conf_file:
        conf_file.write(timestamp)


'''
Read timestamp file for when the last query ran
'''
def get_last_run_timestamp():
    # Get the timestamp file path
    timestamp_path = "{}/logs/.timestamp".format(os.path.dirname(os.path.abspath(__file__)))
    last_run_timestamp = None
    # get the current timestamp to replace the previous timestamp
    current_timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    # if timestamp file doesn't exist, create it and return none
    if not os.path.isfile(timestamp_path):
        update_last_run_timestamp(current_timestamp)
        return None
    # read the timestamp of the last runtime to a file
    with open(timestamp_path, 'r') as thisFile:
        last_run_timestamp = thisFile.read()
    # update the timestamp with the latest run timestamp
    update_last_run_timestamp(current_timestamp)
    return last_run_timestamp


'''
Get Cognitive Intelligence incidents from Stealthwatch
'''
def get_cognitive_incidents(config, logger):
    # declares the variable to be returned
    incidents = None
    # disables unnecessary warnings with the python requests module
    try:
        requests.packages.urllib3.disable_warnings()
    except:
        pass
    # sets the URL for SMC login
    url = "https://{}/token/v2/authenticate".format(config["STEALTHWATCH"]["SMC"])
    # create the login request data
    rsa = RSAEncryption()
    login_request_data = {
        "username": config["STEALTHWATCH"]["USER"],
        "password": rsa.decrypt(config["STEALTHWATCH"]["PASSWORD"])
    }
    # initializes the Requests session
    api_session = requests.Session()
    # performs the POST request to login
    response = api_session.request("POST", url, verify=False, data=login_request_data)
    # If the login was successful
    if (response.status_code == 200):
        # gets the list of Cognitive Intelligence incidents from the SMC
        url = 'https://{}/sw-reporting/v2/tenants/0/incidents?limit=1000'.format(config["STEALTHWATCH"]["SMC"])
        # get the last run timestamp (to remove duplicates)
        last_run_timestamp = get_last_run_timestamp()
        # if last run timestamp exists, add it to the query
        if last_run_timestamp is not None:
            url += "&lastUpdatedTimeFrom={}".format(last_run_timestamp)
        response = api_session.request("GET", url, verify=False)
        # If successfully able to get list of Cognitive Intelligence incidents
        if (response.status_code == 200):
            results = json.loads(response.content)
            # if no errors in the response
            if not "errors" in results:
                # Loads the incidents into a dictionary object
                incidents = json.loads(response.content)["data"]
            # if an error is in the response
            else:
                _print_message(logger,
                               "An error has ocurred, while fetching Cognitive Intelligence incidents.".format(
                                   response.status_code), error=response.content.decode("ascii"))
        # If unable to fetch list of Cognitive Intelligence incidents
        else:
            _print_message(logger,
                           "An error has ocurred, while fetching Cognitive Intelligence incidents, with the following code: {}".format(
                               response.status_code), error=response.content.decode("ascii"))
        # logs out of the SMC
        uri = 'https://{}/token'.format(config["STEALTHWATCH"]["SMC"])
        response = api_session.delete(uri, timeout=30, verify=False)
    # If the login was unsuccessful
    else:
        _print_message(logger, "An error has ocurred while logging in, with the following code: {}".format(
            response.status_code), error=response.content.decode("ascii"))
    # returns the results
    return incidents


'''
Get Cognitive Intelligence incidents from Stealthwatch
'''
def process_incidents(incidents, config, logger):
    # if incidents query failed with error, exit
    if incidents is None:
        sys.exit()
    # if no new or updated incidents found
    elif len(incidents) == 0:
        _print_message(logger, "No new incidents found.")
    # if new or updated incidents exist
    else:
        # parse each incident
        for incident in incidents:
            incident_details = json.loads(incident["incidentDetails"])
            # delete unnecessary values from the results
            keys_to_delete = ["relationships", "related", "clusters", "related", "links"]
            for key_to_delete in keys_to_delete:
                if key_to_delete in incident_details:
                    del incident_details[key_to_delete]
            # move nested fields into parent field for easier reporting
            for key, value in incident_details["attributes"].items():
                # if start/end timestamps, move to parent object and convert timestamp from epoch to readable string
                if key == "duration":
                    for duration_key, duration_value in value.items():
                        duration_value = str(duration_value)
                        duration_value = datetime.datetime.utcfromtimestamp(int(duration_value[:-3])).strftime(
                            "%Y-%m-%dT%H:%M:%S.{}".format(duration_value[-3:]))
                        incident_details[duration_key] = duration_value
                # if other timestamps, move to parent object and convert timestamp from epoch to readable string
                elif "time" in key.lower() and value is not None:
                    value = str(value)
                    value = datetime.datetime.utcfromtimestamp(int(value[:-3])).strftime(
                        "%Y-%m-%dT%H:%M:%S.{}".format(value[-3:]))
                    incident_details[key] = value
                # move all other values to parent object except the ones in the list
                elif key not in ["escalations", "stateChanges", "categoriesWithRisk", "userNote", "userFeedback"]:
                    incident_details[key] = value
            # delete the unnessary child fields and object that holds it
            try:
                del incident_details["attributes"]
            except KeyError:
                pass
            # remove nesting and bring to parent object
            if "state" in incident_details and "stateType" in incident_details["state"]:
                incident_details["state"] = incident_details["state"]["stateType"]
            # remove nesting and bring to parent object, plus combine lists into string
            if "incidentTypes" in incident_details:
                incident_details["incidentTypes"] = str(incident_details["incidentTypes"]).strip("['']").replace("', '",
                                                                                                                 "|")
            # remove nesting and bring to parent object, plus combine lists into string
            if "clusterLabels" in incident_details:
                incident_details["clusterLabels"] = str(incident_details["clusterLabels"]).strip("['']").replace("', '",
                                                                                                                 "|")
            # move username and IP details into parent object
            if "user" in incident_details:
                incident_details["userName"] = incident_details["user"]["userName"]
                incident_details["ipAddress"] = incident_details["user"]["ipAddresses"][0]["ipAddress"]
                del incident_details["user"]
            # send the details as an alert
            formatted_alert = str(incident_details).replace("'", "").replace(": ", "=").strip("{}")
            send_udp_alert(config, formatted_alert, logger)


'''
Get Cognitive Intelligence incidents from Stealthwatch
'''
def send_udp_alert(config, data, logger):
    # sets the UDP syslog destination and port
    destination_addr = (config["SYSLOG"]["DESTINATION"], int(config["SYSLOG"]["PORT"]))
    # sends the UDP syslog to the specified destination and port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(bytes(data + '\n', 'utf-8'), destination_addr)
        sock.close()
        _print_message(logger,
                       'Sent UDP syslog to {}:{} :: {}'.format(config["SYSLOG"]["DESTINATION"],
                                                               config["SYSLOG"]["PORT"], data))
    # if an error occurs sending the UDP syslog
    except Exception as e:
        _print_message(logger, "Error: Unable to send UDP alert.", error=e)


'''
Encryption class
'''
class PublicKeyFileExists(Exception): pass
class RSAEncryption():

    '''
    Initialize the encryption object
    '''
    def __init__(self):
        # Override base sesttings from parent
        self.PRIVATE_KEY_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs', 'private',
                                                  'id_rsa')
        self.PUBLIC_KEY_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs', 'public',
                                                 'id_rsa.pub')

    '''
    Encrypt a string
    '''
    def encrypt(self, message):
        private_key, public_key = self._generate_keys()
        public_key_object = RSA.importKey(public_key)
        random_phrase = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
        encrypted_message = public_key_object.encrypt(self._to_format_for_encrypt(message), random_phrase)[0]
        return base64.b64encode(encrypted_message)

    '''
    Decrypt a string
    '''
    def decrypt(self, encoded_encrypted_message):
        encrypted_message = base64.b64decode(encoded_encrypted_message)
        private_key, public_key = self._generate_keys()
        private_key_object = RSA.importKey(private_key)
        decrypted_message = private_key_object.decrypt(encrypted_message)
        try:
            out = six.text_type(decrypted_message, encoding='utf8')
        except UnicodeDecodeError:
            out = ''
        return out

    '''
    Generates encryption keys
    '''
    def _generate_keys(self):
        if os.path.isfile(self.PUBLIC_KEY_FILE_PATH):
            return self._get_private_key(), self._get_public_key()
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        private, public = key.exportKey(), key.publickey().exportKey()
        self._create_directories()
        with open(self.PRIVATE_KEY_FILE_PATH, 'wb') as private_file:
            private_file.write(private)
        with open(self.PUBLIC_KEY_FILE_PATH, 'wb') as public_file:
            public_file.write(public)
        return private, public

    '''
    Creates keystore directories
    '''
    def _create_directories(self, for_private_key=True):
        public_key_path = self.PUBLIC_KEY_FILE_PATH.rsplit('/', 1)
        if not os.path.exists(public_key_path[0]):
            os.makedirs(public_key_path[0])
        if for_private_key:
            private_key_path = self.PRIVATE_KEY_FILE_PATH.rsplit('/', 1)
            if not os.path.exists(private_key_path[0]):
                os.makedirs(private_key_path[0])

    '''
    Gets the public key
    '''
    def _get_public_key(self):
        with open(self.PUBLIC_KEY_FILE_PATH, 'rb') as _file:
            return _file.read()

    '''
    Gets the private key
    '''
    def _get_private_key(self):
        with open(self.PRIVATE_KEY_FILE_PATH, 'rb') as _file:
            return _file.read()

    '''
    Formats a string for proper encryption
    '''
    def _to_format_for_encrypt(self, value):
        if isinstance(value, int):
            return six.binary_type(value)
        for str_type in six.string_types:
            if isinstance(value, str_type):
                return value.encode('utf8')
        if isinstance(value, six.binary_type):
            return value


'''
The main function
'''
def main():
    # initialize the logger
    logger = _initialize_logger()
    # get the config
    config = get_config(logger)
    # get the Cognitive Intelligence Incidents from the SMC
    incidents = get_cognitive_incidents(config, logger)
    # process the Cognitive Intelligence incidents
    process_incidents(incidents, config, logger)


if __name__ == '__main__':
    main()
