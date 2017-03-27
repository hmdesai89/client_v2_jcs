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


def neutron_quota_service(token, tenant_id=None):
    net_url = 'https://vpc.ind-west-1.staging.jiocloudservices.com:9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}

    # neutron quota-show for a tenant
    url_path_net_list = 'v2.0/quotas/{'+tenant_id+'}'
    json_data = {}
    verify=False
    response = requests.request('GET', net_url+url_path_net_list,
                                verify=verify,
                                headers=headers)
    json_response = json.loads(response.text)
    print response
    print json_response

def create_neutron_curl_req(token):
    net_url = JCS_VPC_URL+':9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}

    # neutron net-list
    url_path_net_list = 'v2.0/networks'
    #url_path_net_list = 'v2.0/security-group-rules/9b418b1c-e7ef-425a-a2f7-963527e02adb'
    json_data = {}
    verify=False
    response = requests.request('GET', net_url+url_path_net_list,
                                verify=verify,
                                headers=headers)
    print response
    json_response = json.loads(response.text)
    print response
    print json_response
    return json_response

def create_neutron_port_create_req(token, network_id, port_name):
    net_url = JCS_VPC_URL+':9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}
    port_info_dict = {
          'network_id'     : network_id,
          'name'           : port_name,
          'admin_state_up' : 'true',
    }
    port_create_data = {
          'port': port_info_dict,
    }
    port_create_data_json = jsonutils.dumps(port_create_data)
    print port_create_data_json
    # neutron net-list
    url_path_net_list = 'v2.0/ports'
    verify=False
    response = requests.request('POST', net_url+url_path_net_list,
                                verify=verify, data=port_create_data_json,
                                headers=headers)
    json_response = json.loads(response.text)
    print json_response
    return { 'status' : response.status_code , 
             'data'   : json_response
           }



def update_neutron_port_create_req(token, port_id, port_name):
    net_url = JCS_VPC_URL+':9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}
    port_info_dict = {
          'name'           : port_name,
    }
    port_create_data = {
          'port': port_info_dict,
    }
    port_create_data_json = jsonutils.dumps(port_create_data)
    print port_create_data_json
    # neutron net-list
    url_path_net_list = 'v2.0/ports/'+port_id
    verify=False
    response = requests.request('PUT', net_url+url_path_net_list,
                                verify=verify, data=port_create_data_json,
                                headers=headers)
    json_response = json.loads(response.text)
    print json_response
    return { 'status' : response.status_code ,
             'data'   : json_response
           }



def delete_neutron_port_create_req(token, port_id):
    net_url = JCS_VPC_URL+':9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}
    url_path_net_list = 'v2.0/ports/'+ port_id
    verify=False
    response = requests.request('DELETE', net_url+url_path_net_list,
                                verify=verify,
                                headers=headers)
    return { 'status' : response.status_code}


def list_neutron_ports_create_req(token, filter_param = None):
    #filter_param['type']
    net_url = JCS_VPC_URL+':9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}
    url_path_net_list = 'v2.0/ports'
    verify=False
    response = requests.request('GET', net_url+url_path_net_list,
                                verify=verify,
                                headers=headers)
    json_response = json.loads(response.text)
    print json_response
    return { 'status' : response.status_code,
              'data' : json_response }




def list_neutron_networks_create_req(token, filter_param = None):
    #filter_param['type']
    net_url = JCS_VPC_URL+':9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}
    url_path_net_list = 'v2.0/networks.json'
    if filter_param:
       url_path_net_list += '?'+filter_param['type']+'='+filter_param['value']
    verify=False
    response = requests.request('GET', net_url+url_path_net_list,
                                verify=verify,
                                headers=headers)
    json_response = json.loads(response.text)
    print json_response
    return { 'status' : response.status_code,
              'data' : json_response }



def list_neutron_port_create_req(token, port_id):
    net_url = JCS_VPC_URL+':9696/'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}
    url_path_net_list = 'v2.0/ports/'+port_id
    verify=False
    response = requests.request('GET', net_url+url_path_net_list,
                                verify=verify,
                                headers=headers)
    json_response = json.loads(response.text)
    print json_response
    return { 'status' : response.status_code,
              'data' : json_response }



def verify_token_auth(token):
    net_url = 'https://iam.ind-west-1.staging.jiocloudservices.com/token-auth'
    headers = {'X-Auth-Token': token, 'User-Agent': 'curl/7.35.0'}
    
    creds_dict = {}
    creds_dict['action_resource_list']= []
    verify=False
    response = requests.request('POST', net_url,
                                verify=verify,
                                data=creds_dict,
                                headers=headers)
    json_response = json.loads(response.text)
    print response
    print json_response


def main():
    #req = sys.argv[1]
    iam_token_response = generate_iam_token_from_key()
    print iam_token_response
    create_neutron_curl_req(iam_token_response)
    #create_neutron_port_create_req(iam_token_response, '88a7e079-96aa-4ae4-ad8c-3a518a6cd1c5', 'vpc_user_0036_p1')
    #neuw
    tron_quota_service(iam_token_response, '00000000000000000000961655772674')
    #verify_token_auth(iam_token_response)

JCS_VPC_URL =           os.environ.get('VPC_URL')


class NeutronClient():

    def __init__(self,access_key, secret_key):
        self.access_key = access_key
	self.secret_key = secret_key



    def create_port(self,network_id, name  = None):
        token = generate_iam_token_from_key(self.access_key, self.secret_key)
	return create_neutron_port_create_req(token, network_id, name)

    def delete_port(self, port_id ):
        token = generate_iam_token_from_key(self.access_key, self.secret_key)
	return delete_neutron_port_create_req(token, port_id)



    def update_port(self,port_id, name=None ):
        token = generate_iam_token_from_key(self.access_key, self.secret_key)
        return update_neutron_port_create_req(token, port_id, name)


    def list_port(self, port_id):
        token = generate_iam_token_from_key(self.access_key, self.secret_key)
        return list_neutron_port_create_req(token, port_id)


    def list_ports(self):
        token = generate_iam_token_from_key(self.access_key, self.secret_key)
        return list_neutron_ports_create_req(token)

    def list_networks(self, _filter = None):
        token = generate_iam_token_from_key(self.access_key, self.secret_key)
        return list_neutron_networks_create_req(token, _filter)



if __name__ == '__main__' :
    main()
