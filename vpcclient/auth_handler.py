import base64
import copy
import datetime
import time
import hmac
import os
import posixpath
import hashlib
from urllib import urlencode, quote_plus
#import six
#from six.moves import urllib

class HTTPRequest(object):

    def __init__(self, method, protocol, host, #path, auth_path,
                 params, headers, body):
        self.method = method
        self.protocol = protocol
        self.host = host
        #self.port = port
        #self.path = path
        #if auth_path is None:
        #    auth_path = path
        #self.auth_path = auth_path
        self.params = params
        # chunked Transfer-Encoding should act only on PUT request.
        self.headers = headers
        self.body = body

    def __str__(self):
        return (('method:(%s) protocol:(%s) host(%s) port(%s)'
                 ' params(%s) headers(%s) body(%s)') % (self.method,
                 self.protocol, self.host, self.params,
                 self.headers, self.body))


class V2Handler(object):
    
    def __init__(self, host, service_name=None, region_name=None):
        # You can set the service_name and region_name to override the
        # values which would otherwise come from the endpoint, e.g.
        # <service>.<region>.amazonaws.com.
        self.host = host
        self.service_name = service_name
        self.region_name = region_name
        self.access_key = os.environ.get('JCS_ACCESS_KEY')
        self.secret_key = os.environ.get('JCS_SECRET_KEY')

    def add_params(self, req):
        req.params['JCSAccessKeyId'] = self.access_key
        req.params['SignatureVersion'] = '2'
        req.params['SignatureMethod'] = 'HmacSHA256'
        req.params['Timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @staticmethod
    def _get_utf8_value(value):
        """Get the UTF8-encoded version of a value."""
        if not isinstance(value, (six.binary_type, six.text_type)):
            value = str(value)
        if isinstance(value, six.text_type):
            return value.encode('utf-8')
        else:
            return value

    def sort_params(self, params):
        keys = params.keys()
        keys.sort()
        pairs = []
        for key in keys:
            val = V2Handler._get_utf8_value(params[key])
            val = urllib.parse.quote(val, safe='-_~')
            pairs.append(urllib.parse.quote(key, safe='') + '=' + val)
        qs = '&'.join(pairs)
        return qs

    def string_to_sign(self, req):
        ss = req.method + '\n' + req.host + ':' + req.port + '\n'
        ss += req.path + '\n'
        self.add_params(req)
        qs = self.sort_params(req.params)
        ss += qs
        return ss

    def generate_signature(self, req):
     
        self.add_params(req)
 
        url_params = dict(JCSAccessKeyId=self.access_key,
                          SignatureVersion='2',
                          SignatureMethod='HmacSHA256') 

        url_params['Timestamp'] = req.params['Timestamp']

        url_params.update(req.params) 

        keys = url_params.keys()

        keys.sort()

        values = map(url_params.get, keys)

        url_string = urlencode(zip(keys,values))

        string_to_sign = "GET\n%s\n%s\n%s" % (req.host,'/',url_string)

        signature = hmac.new(key=self.secret_key,
                             msg=string_to_sign,
                             digestmod=hashlib.sha256).digest()

        signature = base64.encodestring(signature).strip()

        urlencoded_signature = quote_plus(signature)

        return urlencoded_signature

    def add_auth(self, req):
       
        signature = self.generate_signature(req)
 
        req.params['Signature'] = signature

        return req
        
    #def add_auth(self, req):
    #    hmac_256 = hmac.new(self.secret_key, digestmod=hashlib.sha256)
    #    canonical_string = self.string_to_sign(req)
    #    print "req : " + req
    #    print "canonical_string : " + canonical_string
    #    hmac_256.update(canonical_string.encode('utf-8'))
    #    b64 = base64.b64encode(hmac_256.digest()).decode('utf-8')
    #    req.params['Signature'] = b64
    #    return req

