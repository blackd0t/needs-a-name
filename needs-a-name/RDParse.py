# XXX: Notes
#   - what format are keys in, and do we have to do anything with them?
#       - apparently, onion-key is PEM and ntor is base-64-encoded
#           - do we need to do any additional conversions of these?
#   - need a 'cleanup' function to check that all required values are
#     present and to set shit like 'caches-extra-info' to the default if
#     the option is not present (in the case of caches-extra-info, False)


#TODO:
#   -  Check parsed data for errors - consider implementing separate 
#       validation functions for each keyword rather than doing the 
#       validation inside the parsing function itself
#
#           XXX: lots of this error checking (e.g. for valid port numbers) should
#                be done in a file like 'Common.py' and then imported so we can
#                use the same code elsewhere
#
#           a.  Make sure first line in file starts with keyword 'router'
#           b.  Make sure last line in file starts with keyword 
#               'router-signature'
#           c.  Make sure that keywords don't appear more than they are 
#               allowed to
#           d.  Make sure the parameters to keywords are in the correct 
#               format and are valid
#   -  Test code
#           a. Against valid files
#           b. Against invalid files
#           c. Create Unit Tests???

from io import StringIO

from Common import get_rsa_pub_key, get_signature
from Exceptions import BadRouterDoc

class RDParser:
    '''Parse a router descriptor.

    Attributes:
        values (dict): values from router descriptor       
    '''
    
    def __init__(self, data):
        self.data = StringIO(data)
        
        # keywords in values dict are keywords in router descriptor file
        self.values = {
            'router' : None,
            'bandwidth' : None,
            'platform' : None,
            'published' : None,
            'fingerprint' : None,
            'hibernating' : None,
            'uptime' : None,
            'onion-key' : None,
            'ntor-onion-key' : None,
            'signing-key' : None,
            'exit-policy': None,
            'ipv6-policy' : None,
            'router-signature' : None,
            'contact' : None,
            'family' : None,
            'read-history' : None,
            'write-history' : None,
            'eventdns' : None,
            'caches-extra-info' : None,
            'extra-info-digest' : None,
            'hidden-service-dir' : None,
            'protocols' : None,
            'allows-single-hop-exits' : None,
            'or-address' : None
        }
        # mapping of keywords to processing functions
        # avoid enormous if-statement
        self.functions = {
            'router' : self.parse_router,
			'bandwidth' : self.parse_bandwidth,
			'platform' : self.parse_platform,
			'published' : self.parse_published,
			'fingerprint' : self.parse_fingerprint,
			'hibernating' : self.parse_hibernating,
			'uptime' : self.parse_uptime,
			'onion-key' : self.parse_onion_key,
			'ntor-onion-key' : self.parse_ntor_onion_key,
			'signing-key' : self.parse_signing_key,
			'accept' : self.parse_accept,
			'reject' : self.parse_reject,
			'ipv6-policy' : self.parse_ipv6_policy,
			'router-signature' : self.parse_router_signature,
			'contact' : self.parse_contact,
			'family' : self.parse_family,
			'read-history' : self.parse_read_history,
			'write-history' : self.parse_write_history,
			'eventdns' : self.parse_eventdns,
			'caches-extra-info' : self.parse_caches_extra_info,
			'extra-info-digest' : self.parse_extra_info_digest,
			'hidden-service-dir' : self.parse_hidden_service_dir,
			'protocols' : self.parse_protocols,
			'allows-single-hop-exits' : self.parse_allows_single_hop_exits,
			'or-address' : self.parse_or_address,
        }

    def check_router_start(self):
        '''Check the beginning of a router descriptor file.
        '''
        self.parse_router(self.data.readline().split())

    def parse(self):
        '''Parse router descriptor and save keyword values in values dict.
        '''
        
        self.check_router_start()


        # for each line, grab its keyword and parse the rest of 
        # the line if the keyword is recognized
        for line in self.data:
            line = line.strip().split()
            if line[0] in self.functions:
                self.functions[line[0]](line)
  
    def parse_router(self, line):
        '''Parse router keyword line.
        '''

        if len(line) < 6:
            raise BadRouterDoc("The keyword 'router' "
                               "requires at least 5 parameters")

        if self.values['router'] is not None:
            self.multi_word_exc('router')

        self.values['router'] = {}
        self.values['router']['nickname'] = line[1]
        self.values['router']['address'] = line[2]
        self.values['router']['ORPort'] = line[3]
        self.values['router']['SOCKSPort'] = line[4]
        self.values['router']['DirPort'] = line[5]
        
    def parse_bandwidth(self, line):
        '''Parse bandwidth line of router descriptor.
        '''

        if len(line) < 4:
            raise BadRouterDoc("The keyword 'bandwidth' "
                               "requires at least 5 parameters.")

        if self.values['bandwidth'] is not None:
            self.multi_word_exc('bandwidth')

        self.values['bandwidth'] = {}
        self.values['bandwidth']['avg'] = line[1]
        self.values['bandwidth']['burst'] = line[2]
        self.values['bandwidth']['observed'] = line[3]
        
    def parse_platform(self, line):
        '''Parse platform line.
        '''

        if self.values['platform'] is not None:
            self.multi_word_exc('platform')

        self.values['platform'] = line[1:]
        
    def parse_published(self, line):
        '''Parse published line.
        '''

        if len(line) < 3:
            raise BadRouterDoc("The keyword 'published' "
                               "requires at least 2 parameters")

        if self.values['published'] is not None:
            self.multi_word_exc('published')

        self.values['published'] = line[1:]
        
    def parse_fingerprint(self, line):
        '''Parse fingerprint line.
        '''
        if self.values['fingerprint'] is not None:
            self.multi_word_exc('fingerprint')
            
        self.values['fingerprint'] = ''.join(line[1:])
        
    def parse_hibernating(self, line):
        '''Parse hibernating line.
        '''
        if self.values['hibernating'] is not None:
            self.multi_word_exc('hibernating')
        self.values['hibernating'] = line[1]
        
    def parse_uptime(self, line):
        '''Parse uptime line.
        '''
        if self.values['uptime'] is not None:
            self.multi_word_exc('uptime')
        self.values['uptime'] = line[1]

    def parse_onion_key(self, line):
        '''Parse onion key line
        '''
        if self.values['onion-key'] is not None:
            self.multi_line_exc('onion-key')
        self.values['onion-key'] = get_rsa_pub_key(self.data)
        
    def parse_ntor_onion_key(self, line):
        '''Parse ntor onion key line.
        '''
        if self.values['ntor-onion-key'] is not None:
            self.multi_line_exc('ntor-onion-key')
        self.values['ntor-onion-key'] = line[1]
        
    def parse_signing_key(self, line):
        '''Parse signing key line.
        '''
        if self.values['signing-key'] is not None:
            self.multi_line_exc('signing-key')
        self.values['signing-key'] = get_rsa_pub_key(self.data)
        
    def parse_accept(self, line):
        '''Parse accept line.
        '''
        if self.values['exit-policy'] == None:
            self.values['exit-policy'] = []
        self.values['exit-policy'].append(line[1:])
        
    def parse_reject(self, line):
        '''Parse reject line.
        '''
        if self.values['exit-policy'] == None:
            self.values['exit-policy'] = []
        self.values['exit-policy'].append(line[1:])
        
    def parse_ipv6_policy(self, line):
        '''Parse ipv6 line.
        '''
        print("Function: 'parse_ipv6_policy()' not yet implemented.")
        
    def parse_router_signature(self, line):
        '''Parse router signature line.
        '''
        if self.values['router-signature'] is not None:
            self.multi_line_exc('router-signature')
        self.values['router-signature'] = get_signature(self.data)
        
    def parse_contact(self, line):
        '''Parse contact line.
        '''
        if self.values['contact'] is not None:
            self.multi_line_exc('contact')
        self.values['contact'] = line[1:]
        
    def parse_family(self, line):
        '''Parse family line.
        '''
        if self.values['family'] is not None:
            self.multi_line_exc('family')
        self.values['family'] = line[1:]
        
    def parse_read_history(self, line):
        '''Parse read history line.
        '''
        if self.values['read-history'] is not None:
            self.multi_line_exc('read-history')
        # we're not using this
        pass
        
    def parse_write_history(self, line):
        '''Parse write history.
        '''
        if self.values['write-history'] is not None:
            self.multi_line_exc('write-history')
        # not using this
        pass
        
    def parse_eventdns(self, line):
        '''Parse event dns line.
        '''
        if self.values['eventdns'] is not None:
            self.multi_line_exc('eventdns')
        # obsolete
        pass
        
    def parse_caches_extra_info(self, line):
        '''Parse caches extra info
        '''
        if self.values['caches-extra-info'] is not None:
            self.multi_line_exc('caches-extra-info')
        self.values['caches-extra-info'] = True
        
    def parse_extra_info_digest(self, line):
        '''Parse extra info digest
        '''
        if self.values['extra-info-digest'] is not None:
            self.multi_line_exc('extra-info-digest')
        self.values['extra-info-digest'] = line[1:]
        
    def parse_hidden_service_dir(self, line):
        '''Parse hidden service dir line.
        '''
        if self.values['hidden-service-dir'] is not None:
            self.multi_line_exc('hidden-service-dir')
        self.values['hidden-service-dir'] = line[1:]
        
    def parse_protocols(self, line):
        '''Parse protocols line.
        '''
        if self.values['protocols'] is not None:
            self.multi_line_exc('protocols')
        self.values['protocols'] = line[1:]
        
    def parse_allows_single_hop_exits(self, line):
        '''Parse allows single hop exists line.
        '''
        if self.values['allow-single-hop-exits'] is not None:
            self.multi_line_exc('allow-single-hop-exits')
        self.values['allow-single-hop-exits'] = True
        
    def parse_or_address(self, line):
        '''Parse or address line.
        '''
        if self.values['or-address'] is None:
            self.values['or-address'] = []
        self.values['or-address'].append(line[1:])

    def multi_word_exc(self, keyword):
        raise BadRouterDoc("Only one '{0}' line allowed per "
                           "router descriptor.".format(keyword))

if __name__ == '__main__':
    with open('data/rd.txt', 'r') as f:
        d = f.read()
    r = RDParser(d)
    r.parse()
    for i in r.values:
        print(i, r.values[i])
