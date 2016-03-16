# Copyright 2016, Reliance Industries Ltd, all rights reserved.
# Author: Deepak Agrawal

import os
import requests
import json
from oslo_serialization import jsonutils
def generate_url(access_key, secret_key, host, port, path, params):
    import base64, hashlib, hmac, time
    from urllib import urlencode, quote_plus

    base_url = "https://%s:%s%s"%(host,port, path)
    url_params = dict(
        JCSAccessKeyId=access_key,
        SignatureVersion='2',
        SignatureMethod='HmacSHA256')


    url_params['Timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
#    url_params['Timestamp'] = '2016-01-11T09:11:49Z'
    url_params.update(params)
    # Sort the URL parameters by key
    keys = url_params.keys()
    keys.sort()
    # Get the values in the same order of the sorted keys
    values = map(url_params.get, keys)

    # Reconstruct the URL parameters and encode them
    url_string = urlencode(zip(keys,values))
    #Construct the string to sign
    string_to_sign = "GET\n%s\n%s\n%s" % (host,path,url_string)
    #   print string_to_sign
    # Sign the request
    signature = hmac.new(
        key=secret_key,
        msg=string_to_sign,
        digestmod=hashlib.sha256).digest()

    # Base64 encode the signature
    signature = base64.encodestring(signature).strip()

    # Make the signature URL safe
    urlencoded_signature = quote_plus(signature)
    url_string += "&Signature=%s" % urlencoded_signature
    response = generateEc2Request(access_key,secret_key, host, port,path,url_params,signature)
    #   print "%s?%s\n\n%s\n\n%s" % (base_url, url_string, urlencoded_signature, signature)
    # return "%s?%s"%(base_url,url_string)
    return response

def generateEc2Request(access_key, secret_key, host, port, path, params, signature):
    cred_dict = {
            'access': access_key,
            'signature': signature,
            'host': host,
            'verb': 'GET',
            'path': path,
            'params': params,
            'headers': {},
            'body_hash': ''
     }
    token_url = 'https://10.140.215.24:5000/v2.0/ec2-auth?action=jrn:jcs:iam:ListUsers&resource=jrn:jcs:identity:a5:a2:hhhh&implicit_allow=false'
    creds = {'ec2Credentials': cred_dict}
    creds_json = jsonutils.dumps(creds)
    #print creds_json
    headers = {'Content-Type': 'application/json'}
    verify = False
    #print json.dumps(response.json(),indent=4,sort_keys=False)
    token_url = 'https://10.140.215.24:5000/v2.0/ec2-auth'
    cred_dict["action_resource_list"]= json.loads('[]')
    creds = {'ec2Credentials': cred_dict}
    creds_json = jsonutils.dumps(creds)
    print creds_json
    headers = {'Content-Type': 'application/json', 'Accept-Encoding': 'identity', 'User-Agent': 'curl/7.35.0'}
    verify = False
    response = requests.request('POST', token_url, verify=verify,
                             data=creds_json, headers=headers)
    print response.text
    print response
    return response




def generate_iam_token_from_key():
    AWS_ACCESS_KEY_ID = os.environ.get('JCS_ACCESS_KEY')
    AWS_SECRET_ACCESS_KEY = os.environ.get('JCS_SECRET_KEY')

    if (not  AWS_ACCESS_KEY_ID) or (not AWS_SECRET_ACCESS_KEY) :
       print "Please set env variable JCS_ACCESS_KEY and JCS_SECRET_KEY"
       return 0
    params = {'Action':'ListUsers'}
    response =  generate_url(AWS_ACCESS_KEY_ID,
            AWS_SECRET_ACCESS_KEY,'10.140.215.24','5000','/v2.0/ec2-auth',params)
    return response


if __name__ == "__main__": generate_iam_token_from_key()
