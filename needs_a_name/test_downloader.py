#! /usr/bin/python

'''
Experimental code for a consensus downloader.

Buggy and error-prone.
'''

import random
import sys
import time

from twisted.internet.protocol import Protocol
from twisted.internet import reactor

from stem.descriptor.networkstatus import NetworkStatusDocumentV3

import Common as Com
import Config as Conf

class DocDownloader(object):

    def __init__(self):
        self.consensus = None

    def get_consensus(self):
        '''Get a fresh network consensus document.

        First try using a directory cache (if we already have information or
        an old consensus on disk).  If this is not possible, grab a new 
        consensus from a directory authority.
        '''

        try:
            self.consensus = self.read_consensus_from_file()
        except Exception as e:
            # log here
            pass

        self.get_remote_consensus()

    def get_remote_consensus(self):
        '''Get a fresh consensus from directory cache if we can, otherwise 
        from directory authority.
        '''
        v2c = [self.consensus.routers[i] for i in self.consensus.routers \
                if 'V2Dir' in self.consensus.routers[i].flags]

        choice = random.choice(v2c)
        data = Com.download_network_doc(choice.address, 
                                        choice.dir_port, 
                                        Conf.consensus_url)

        self.consensus = NetworkStatusDocumentV3(data)

    def read_consensus_from_file(self):
        '''Read an old consensus stored on disk and return 
        NetworkStatusDocumentV3 object.
        '''

        with open(Conf.consensus_cache_file, 'rb') as f:
            data = f.read()
        return NetworkStatusDocumentV3(data)

def download_helper():
    '''Download a fresh consensus doc at interval according
    to dir-spec.

    We need this helper to do thread-safe things with twisted.
    '''
    global consensus

    while True:
        current_time = Com.get_current_time()
        fresh_until = Com.date_to_timestamp(str(consensus.fresh_until))
        print current_time, fresh_until
        print 'sleeping for ' + str(fresh_until - current_time)
        time.sleep(fresh_until - current_time)
        print 'waking up'
        d = DocDownloader()
        d.get_consensus()
        consensus = d.consensus


def get_initial_consensus():
    '''Get a fresh consensus when we first start up.
    '''
    d = DocDownloader()
    d.get_consensus()
    return d.consensus

consensus = get_initial_consensus()

reactor.callFromThread(download_helper)
reactor.run()
     
if __name__ == '__main__':
    #d = DocDownloader()
    #d.get_consensus()
    current_time = Com.get_current_time()
    fresh_until = Com.date_to_timestamp(str(consensus.fresh_until))
    print current_time, fresh_until
    print 'sleeping for ' + str(fresh_until - current_time)
