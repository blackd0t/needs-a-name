'''
Common functions used across program.
'''

from Exceptions import BadFormatRSAKey, BadFormatSignature

def get_rsa_pub_key(data):
    '''Return the raw public key.

    data should be a StringIO or File object at the line beginning with
    '-----BEGIN RSA PUBLIC KEY-----'. returns the key with newlines 
    stripped out.
    '''

    line = data.readline().strip()
    if line != '-----BEGIN RSA PUBLIC KEY-----':
        raise BadFormatRSAKey("Missing '-----BEGIN RSA PUBLIC KEY-----' "
                              "line in key.")

    line = data.readline().strip()
    key = ''
    while line !=  '-----END RSA PUBLIC KEY-----':
        key += line
        line = data.readline().strip()
    return key

def get_signature(data):
    '''Return raw signature

    data should be a StringIO or File object at the line beginning with
    '-----BEGIN SIGNATURE-----'. returns the signature with newlines
    stripped out.
    '''
    line = data.readline().strip()
    if line != '-----BEGIN SIGNATURE-----':
        raise BadFormatSignature("Missing '-----BEGIN SIGNATURE-----' "
                              "line in key.")

    line = data.readline().strip()
    sig = ''
    while line !=  '-----END SIGNATURE-----':
        sig += line
        line = data.readline().strip()
    return sig

def get_id_signature(data):
    '''Return id signature

    data should be a StringIO or File object at the line beginning with
    '-----BEGIN ID-----'. returns the signature with newlines
    stripped out.
    '''
    line = data.readline().strip()
    if line != '-----BEGIN ID SIGNATURE-----':
        raise BadFormatSignature("Missing '-----BEGIN ID SIGNATURE-----' "
                              "line in key.")

    line = data.readline().strip()
    _id = ''
    while line !=  '-----END ID SIGNATURE-----':
        _id += line
        line = data.readline().strip()
    return _id