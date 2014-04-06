#! /usr/bin/env python3

'''Quick example of grabbing the tor network consensus and decompressing.

See tor dir-spec for details of what's going on here.  directory_auth is
the ip address of a directory authority grabbed from src/or/config.c in
the Tor source code.

We don't want to suck up directory authority bandwidth in testing this 
thing, so it currently just reads from a local file.  If you want to test
actually grabbing a real consensus, just call 
'''

# XXX next steps:
#                   - check signatures
#                   - write a little toy parser
#                   - get other kinds of docs besides consensus

from urllib import request
from zlib import decompress


def doc_from_web(directory_auth, doc):
    '''Grab doc from directory_auth and return decompressed ascii
    representation.

    doc should be, starting after the hostname, the full path
    to the network document we want. directory_auth can be an
    ip or a hostname of a tor directory authority - look these
    up in /src/or/config.c in tor source code.
    '''
    with request.urlopen('http://' + directory_auth + doc) as f:
        data = decompress(f.read()).decode('ascii')
    return data

def doc_from_file(fname):
    '''Simulate doc_from_web by reading from a local file.

    Just use this for testing and playing around so we don't
    waste directory authority bandwidth.
    '''
    with open(fname, 'rb') as f:
        data = decompress(f.read()).decode('ascii')
    return data


if __name__ == '__main__':
    fname = 'files/consensus.z'

    directory_auth = '194.109.206.212'
    doc = '/tor/status-vote/current/consensus.z'

    print(doc_from_file(fname))
    #print(doc_from_web(directory_auth, doc))
