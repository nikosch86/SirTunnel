#!/usr/bin/env python3

import sys
import json
import time
import argparse
from urllib import request
import base64
from bcrypt import hashpw, gensalt
import logging
import coloredlogs
import signal


def signal_handler(sig, frame):
    cleanup_and_die('Interrupt signal triggered')


def cleanup_and_die(msg):
    cleanup_tunnel(tunnel_id)
    logger.critical(msg)
    sys.exit(2)


def cleanup_tunnel(tunnel_id):
    logger.info("Cleaning up tunnel '{}'".format(tunnel_id))
    delete_url = 'http://127.0.0.1:2019/id/' + tunnel_id
    try:
        req = request.Request(method='DELETE', url=delete_url)
        request.urlopen(req)
    except Exception as Message:
        logger.critical("Error occured while trying to cleanup the tunnel '{}': {}".format(
            tunnel_id, Message))


signal.signal(signal.SIGINT, signal_handler)
argparser = argparse.ArgumentParser()
argparser.add_argument('-d', '--fqdn', required=True, action='store',
                       help='FQDN used as vhost')
argparser.add_argument('-p', '--port', default='443', action='store',
                       help='Port to connect on (default: %(default)s)')
argparser.add_argument('-a', '--authentication', required=False, action='store',
                       help='Authentication string for http basic auth')
argparser.add_argument("--verbose", "-v", action='count', default=0)
args = argparser.parse_args()

logger = logging.getLogger(__name__)
levels = [logging.WARNING, logging.INFO, logging.DEBUG]
level = levels[min(len(levels)-1, args.verbose)]
coloredlogs.install(level=level)

host = args.fqdn
port = args.port

# TODO: find a nicer way to keep the tunnel id around for deletion of the tunnel on signal handler
global tunnel_id
tunnel_id = '{}-{}'.format(host, port)

caddy_add_route_request = {
    "@id": tunnel_id,
    "match": [{
        "host": [host],
    }],
    "handle": [{
        "handler": "reverse_proxy",
        "upstreams": [{
            "dial": ':' + port
        }]
    }]
}

logger.debug('sending request to caddy api')
logger.debug(caddy_add_route_request)

body = json.dumps(caddy_add_route_request).encode('utf-8')
headers = {
    'Content-Type': 'application/json'
}
create_url = 'http://127.0.0.1:2019/config/apps/http/servers/srv0/routes'
try:
    req = request.Request(method='POST', url=create_url, headers=headers)
    request.urlopen(req, body)
except Exception as Message:
    cleanup_and_die(
        "Error occured while trying to register new routing information: {}".format(Message))

if vars(args).get('authentication'):
    credentials = args.authentication.split(':')
    if len(credentials) < 2:
        logger.warning(
            "credentials should be provided in the form of 'username:password', skipping authentication for this  tunnel")
    else:
        username = credentials[0]
        password = credentials[1]
        password_bcrypt = base64.b64encode(
            hashpw(password.encode('ascii'), gensalt())).decode('ascii')
        logger.debug("Setting credentials %s:%s" % (username, password_bcrypt))
        caddy_set_authentication_request = {
            "handler": "authentication",
            "providers": {
                "http_basic": {
                    "accounts": [{
                        "username": username,
                        "password": password_bcrypt
                    }]
                }
            }
        }
        logger.debug(caddy_set_authentication_request)
        credential_url = 'http://127.0.0.1:2019/id/' + tunnel_id + '/handle/0'
        try:
            req = request.Request(
                method='PUT', url=credential_url, headers=headers)
            request.urlopen(req, json.dumps(
                caddy_set_authentication_request).encode('utf-8'))
        except Exception as Message:
            cleanup_and_die(
                "Error occured while trying to configure authentication handler: ".format(Message))

logger.info("Tunnel created successfully")

if vars(args).get('authentication'):
    print('https://' + args.authentication + '@' + host + '/')
else:
    print('https://' + host + '/')

while True:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        cleanup_tunnel(tunnel_id)
