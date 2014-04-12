'''Get network status documents.

Get network consensus, router descriptors, and directory authority keys.
'''
# XXX possible strategy for when to request new documents:
#       - use scheduler module, and when we initially get the consensus
#         doc, schedule the task based on specified time formula to 
#         execute once.  then, every time that function is called,
#         reschedule it to run again based on time in consensus

from urllib import request
from zlib import decompress

class NetworkConsensus:
    '''Network consensus document.
    '''
    def __init__(self):
        pass

    def get_fresh_consensus(self):
        '''Get a fresh network consensus.

        First try to get consensus from directory caches.  If that
        is not possible, go straight to directory authorities.
        '''
        pass

    def get_consensus_from_dircache(self):
        '''Get fresh consensus doc from randomly chosen v3 dir cache.
        '''
        pass

    def get_consensus_from_dirauth(self):
        '''Get fresh consensus doc from randomly chosen directory authority.
        '''
        pass

    def write_doc_to_disc(self, doc):
        '''Write consensus doc to cache on disk.
        '''
        pass
                    
