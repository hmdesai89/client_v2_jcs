#!/usr/bin/env python

# Copyright 2016, Reliance Industries Ltd, all rights reserved.
# Author: Deepak Agrawal

import os
import sys
import datetime
from jcs_iam_client import generate_iam_token_from_key
import httplib
import requests
import json
from oslo_serialization import jsonutils

params, headers = {}, {}
method = 'GET'
path, port, auth_path = '', '', ''
body, host, protocol = '', '', ''

def add_params(string):
    length = len(string)
    parts = string.split('&')
    for p in parts:
        (key, val) = p.split('=')
        params[key] = val

def create_neutron_curl_req(token):
    net_url = 'https://vpc.ind-west-1.staging.jiocloudservices.com:9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}
    
    url_path_net_list = 'v2.0/networks'
    json_data = {}
    verify=False
    response = requests.request('GET', net_url+url_path_net_list,
                                verify=verify,
                                headers=headers)
    json_response = json.loads(response.text)
    print response
    print json_response

def main():
    #req = sys.argv[1]
    iam_token_response = generate_iam_token_from_key()
    print iam_token_response
    create_neutron_curl_req(iam_token_response)

main()
