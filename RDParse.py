#TODO:
#   1.  Finish implementing keyword parsing functions
#   2.  Check parsed data for errors - consider implementing separate 
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
#   3.  Test code
#           a. Against valid files
#           b. Against invalid files
#           c. Create Unit Tests???
#   4.  Write module level docstring (see PEP 257 for details)
#   5.  Write custom exceptions

from io import StringIO

class RDParser:
    '''Parse a router descriptor.

    Attributes:
        values (dict): dictionary of values from router descriptor       
    '''
    
    # XXX:  will anything be inheriting from RDParser?
    #       if not (or even if so but there's little danger
    #       of name collision), we should remove '__' prefixes from stuff
    #       for readability
    def __init__(self, data=""):
        '''Initialize data and function mapping dict.

        Args:
            data (str): data is the raw string of router descriptor info
                        data MUST be decompressed, decoded, and its signature
                        verified before being passed in
        '''
        self.__data = StringIO(data)
        
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
            'accept' : None,
            'reject' : None,
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
        self.__functions = {
            'router' : self.__parse_router,
			'bandwidth' : self.__parse_bandwidth,
			'platform' : self.__parse_platform,
			'published' : self.__parse_published,
			'fingerprint' : self.__parse_fingerprint,
			'hibernating' : self.__parse_hibernating,
			'uptime' : self.__parse_uptime,
			'onion-key' : self.__parse_onion_key,
			'ntor-onion-key' : self.__parse_ntor_onion_key,
			'signing-key' : self.__parse_signing_key,
			'accept' : self.__parse_accept,
			'reject' : self.__parse_reject,
			'ipv6-policy' : self.__parse_ipv6_policy,
			'router-signature' : self.__parse_router_signature,
			'contact' : self.__parse_contact,
			'family' : self.__parse_family,
			'read-history' : self.__parse_read_history,
			'write-history' : self.__parse_write_history,
			'eventdns' : self.__parse_eventdns,
			'caches-extra-info' : self.__parse_caches_extra_info,
			'extra-info-digest' : self.__parse_extra_info_digest,
			'hidden-service-dir' : self.__parse_hidden_service_dir,
			'protocols' : self.__parse_protocols,
			'allows-single-hop-exits' : self.__parse_allows_single_hop_exits,
			'or-address' : self.__parse_or_address,
        }

    def parse(self):
        '''Parse router descriptor and save keyword values in values dict.
        '''
        # for each line, grab its keyword and parse the rest of 
        # the line if the keyword is recognized
        for line in self.__data:
            line = line.strip()
            if line.split()[0] in self.__functions:
                self.__functions[line.split()[0]](line)
  
    # TODO  - add some error/sanity checking for all this stuff
    #       - should raise custom exceptions here
    def __parse_router(self, line):
        '''Parse router keyword line.

        Args:
            line (str): line to parse
        '''
        line = line.split()

        if len(line) < 6:
            raise Exception("The keyword 'router' \
                            requires at least 5 parameters")

        self.values['router'] = {}
        self.values['router']['nickname'] = line[1]
        self.values['router']['address'] = line[2]
        self.values['router']['ORPort'] = line[3]
        self.values['router']['SOCKSPort'] = line[4]
        self.values['router']['DirPort'] = line[5]
        
    def __parse_bandwidth(self, line):
        '''Parse bandwidth line.

        Args:
            line (str): line to parse
        '''
        line = line.split()

        if len(line) < 4:
            raise Exception("The keyword 'bandwidth'\
                            requires at least 5 parameters")

        self.values['bandwidth'] = {}
        self.values['bandwidth']['bandwidth-avg'] = line[1]
        self.values['bandwidth']['bandwidth-burst'] = line[2]
        self.values['bandwidth']['bandwidth-observed'] = line[3]
        
    def __parse_platform(self, line):
        '''Parse platform line.

        Args:
            line (str): line to parse
        '''
        self.values['platform'] = line[8:].strip()
        
    def __parse_published(self, line):
        '''Parse published line.

        Args:
            line (str): line to parse
        '''
        line = line.split()

        if len(line) < 3:
            raise Exception("The keyword 'published' \
                            requires at least 2 parameters")

        self.values['published'] = {}
        self.values['published']['YYYY-MM-DD'] = line[1]
        self.values['published']['HH:MM:SS'] = line[2]
        
    def __parse_fingerprint(self, line):
        '''Parse fingerprint line.

        Args:
            line (str): line to parse
        '''
        self.values['fingerprint'] = line[11:].strip()
        
    def __parse_hibernating(self, line):
        '''Parse hibernating line.

        Args:
            line (str): line to parse
        '''
        self.values['hibernating'] = line[11:].strip()
        
    def __parse_uptime(self, line):
        '''Parse uptime line.

        Args:
            line (str): line to parse
        '''
        self.values['uptime'] = line[6:].strip()
        
    def __parse_onion_key(self, line):
        '''Parse onion key line

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_onion_key()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_ntor_onion_key(self, line):
        '''Parse ntor onion key line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_ntor_onion_key()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_signing_key(self, line):
        '''Parse signing key line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_signing_key()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_accept(self, line):
        '''Parse accept line.

        Args:
            line (str): line to parse
        '''
        if self.values['accept'] == None:
            self.values['accept'] = []
        self.values['accept'].append(line[6:].strip())
        
    def __parse_reject(self, line):
        '''Parse reject line.

        Args:
            line (str): line to parse
        '''
        if self.values['reject'] == None:
            self.values['reject'] = []
        self.values['reject'].append(line[6:].strip())
        
    def __parse_ipv6_policy(self, line):
        '''Parse ipv6 line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_ipv6_policy()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_router_signature(self, line):
        '''Parse router signature line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_router_signature()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_contact(self, line):
        '''Parse contact line.

        Args:
            line (str): line to parse
        '''
        self.values['contact'] = line[7:].strip()
        
    def __parse_family(self, line):
        '''Parse family line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_family()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_read_history(self, line):
        '''Parse read history line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_read_history()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_write_history(self, line):
        '''Parse write history.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_write_history()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_eventdns(self, line):
        '''Parse event dns line.

        Args:
            line (str): line to parse
        '''
        self.values['event-dns'] = line[9:].strip()
        
    def __parse_caches_extra_info(self, line):
        '''Parse caches extra info

        Args:
            line (str): line to parse
        '''
        self.values['caches-extra-info'] = True
        
    def __parse_extra_info_digest(self, line):
        '''Parse extra info digest

        Args:
            line (str): line to parse
        '''
        self.values['extra-info-digest'] = line[17:].strip()
        
    def __parse_hidden_service_dir(self, line):
        '''Parse hidden service dir line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_hidden_service_dir()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_protocols(self, line):
        '''Parse protocols line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_protocols()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_allows_single_hop_exits(self, line):
        '''Parse allows single hop exists line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_allows_single_hop_exits()' \
              not yet implemented.")
        #TODO: Implement Function
        
    def __parse_or_address(self, line):
        '''Parse or address line.

        Args:
            line (str): line to parse
        '''
        print("Function: '__parse_or_address()' not yet implemented.")
        #TODO: Implement Function
