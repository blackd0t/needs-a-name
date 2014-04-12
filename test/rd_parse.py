#TODO:
#   1.  Finish implementing keyword parsing functions
#   2.  Check parsed data for errors - consider implementing separate validation functions for each keyword rather than doing the validation inside the parsing function itself
#           a.  Make sure first line in file starts with keyword 'router'
#           b.  Make sure last line in file starts with keyword 'router-signature'
#           c.  Make sure that keywords don't appear more than they are allowed to
#           d.  Make sure the parameters to keywords are in the correct format and are valid
#   3.  Test code
#           a. Against valid files
#           b. Against invalid files
#           c. Create Unit Tests???

import io
import copy

class RDParser:
    
    '''
    The constructor takes in a string of data representing a Router Directory File. This data specifies many
    different parameters which need to be stored. These parameters will be stored in a dictionary
    called __keywords. Initially the values associated with the keyword keys will be set to None.
    This makes it easy for the parsing function to determine if a keyword has already been read or not,
    as some keywords can only be specified once in the file. The constructor also creates a dictionary called
    __functions, which specifies which functions parse each keyword line in the data.
    '''    
    def __init__(self, data=""):
        self.__data = io.StringIO(data)
        
        '''
        The values associated with each keyword might be anything, including a list or even another dictionary.
        As the number of parameters that go with each keyword varies (and furthermore is subject to change in the future),
        it is up to each keyword's parsing function to set the datatype of the value associated with each key.
        '''
        self.__keywords = {
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
  
    '''
    The functions used to parse each line containing a keyword start here.
    If a keyword takes in multiple unique parameters, the datatype of its value in the __keywords dictionary will
    typically be set to a hashtable. If a keyword takes in multiple non-unique parameters, the datatype of its value
    in the __keywords dictionary will typically be set to a list. If a keyword only takes in one parameter
    (such as a boolean value or a string), the datatype of its value in the __keywords dictionary is
    typically set to whatever datatype the parameter has.
    '''
    def __parse_router(self, line):
        line = line.split()
        if len(line) < 6:
            raise Exception("The keyword 'router' requires at least 5 parameters")
        self.__keywords['router'] = {}
        self.__keywords['router']['nickname'] = line[1]
        self.__keywords['router']['address'] = line[2]
        self.__keywords['router']['ORPort'] = line[3]
        self.__keywords['router']['SOCKSPort'] = line[4]
        self.__keywords['router']['DirPort'] = line[5]
        
    def __parse_bandwidth(self, line):
        line = line.split()
        if len(line) < 4:
            raise Exception("The keyword 'bandwidth' requires at least 5 parameters")
        self.__keywords['bandwidth'] = {}
        self.__keywords['bandwidth']['bandwidth-avg'] = line[1]
        self.__keywords['bandwidth']['bandwidth-burst'] = line[2]
        self.__keywords['bandwidth']['bandwidth-observed'] = line[3]
        
    def __parse_platform(self, line):
        self.__keywords['platform'] = line[8:].strip()
        
    def __parse_published(self, line):
        line = line.split()
        if len(line) < 3:
            raise Exception("The keyword 'published' requires at least 2 parameters")
        self.__keywords['published'] = {}
        self.__keywords['published']['YYYY-MM-DD'] = line[1]
        self.__keywords['published']['HH:MM:SS'] = line[2]
        
    def __parse_fingerprint(self, line):
        self.__keywords['fingerprint'] = line[11:].strip()
        
    def __parse_hibernating(self, line):
        self.__keywords['hibernating'] = line[11:].strip()
        
    def __parse_uptime(self, line):
        self.__keywords['uptime'] = line[6:].strip()
        
    def __parse_onion_key(self, line):
        print("Function: '__parse_onion_key()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_ntor_onion_key(self, line):
        print("Function: '__parse_ntor_onion_key()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_signing_key(self, line):
        print("Function: '__parse_signing_key()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_accept(self, line):
        if self.__keywords['accept'] == None:
            self.__keywords['accept'] = []
        self.__keywords['accept'].append(line[6:].strip())
        
    def __parse_reject(self, line):
        if self.__keywords['reject'] == None:
            self.__keywords['reject'] = []
        self.__keywords['reject'].append(line[6:].strip())
        
    def __parse_ipv6_policy(self, line):
        print("Function: '__parse_ipv6_policy()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_router_signature(self, line):
        print("Function: '__parse_router_signature()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_contact(self, line):
        self.__keywords['contact'] = line[7:].strip()
        
    def __parse_family(self, line):
        print("Function: '__parse_family()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_read_history(self, line):
        print("Function: '__parse_read_history()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_write_history(self, line):
        print("Function: '__parse_write_history()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_eventdns(self, line):
        self.__keywords['event-dns'] = line[9:].strip()
        
    def __parse_caches_extra_info(self, line):
        self.__keywords['caches-extra-info'] = True
        
    def __parse_extra_info_digest(self, line):
        self.__keywords['extra-info-digest'] = line[17:].strip()
        
    def __parse_hidden_service_dir(self, line):
        print("Function: '__parse_hidden_service_dir()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_protocols(self, line):
        print("Function: '__parse_protocols()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_allows_single_hop_exits(self, line):
        print("Function: '__parse_allows_single_hop_exits()' not yet implemented.")
        #TODO: Implement Function
        
    def __parse_or_address(self, line):
        print("Function: '__parse_or_address()' not yet implemented.")
        #TODO: Implement Function
    
    '''
    Parses the data currently saved in __data and saves the information in __keywords.
    '''
    def parse(self):
        #For each line, grab its keyword and parse the rest of the line if the keyword is recognized
        for line in self.__data:
            line = line.strip()
            if line.split()[0] in self.__functions:
                self.__functions[line.split()[0]](line)
            
    '''
    Returns a deep copy of the __keywords dictionary. This prevents the dictionarys already
    returned by this function from being changed when this RDParser object is used to parse
    a different file.
    '''
    def get_keywords(self):
        return copy.deepcopy(self.__keywords)
