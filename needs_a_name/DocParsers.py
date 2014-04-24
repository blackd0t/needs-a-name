'''
Classes to parse network status documents.

Values are stored in a dict called 'values' in parsers.

Current parsers:
    - ConsensusParser: parse a network consensus
    - RouterParser: parse a router descriptor
    - KeyCertParser: parse all authority keys document
'''

# TODO:
#       - make sure values are reasonable (i.e. date/times are correct, etc.)
#       - make sure *REQUIRED* keywords are present
#       - refactor some stuff to be simpler
#       - check that we actually have all required stuff

from io import StringIO

import Common as Com
import Exceptions as Exc

class ConsensusParser:
    '''Parse a network consensus.
    '''
    
    def __init__(self, data):
        '''Initialize data and function mapping dict.
        '''
        self.data = StringIO(data)

        self.values = {
            'preamble': {
                'network-status-version': None,
                'vote-status': None,
                'consensus-method': None,
                'valid-after': None,
                'fresh-until': None,
                'valid-until': None,
                'voting-delay': None,
                'client-versions': None,
                'server-versions': None,
                'known-flags': None,
                'params': None,
            },
            'authority_values': {},
            'router_status': {},
            'bandwidth_weights': None,
            'directory_signatures': {},
        }

        # parsing functions
        self.parsers = {
            'network-status-version': self.check_consensus_start,
            'vote-status': self.parse_vote_status,
            'consensus-method': self.parse_consensus_method,
            'valid-after': self.parse_valid_after,
            'fresh-until': self.parse_fresh_until,
            'valid-until': self.parse_valid_until,
            'voting-delay': self.parse_voting_delay,
            'client-versions': self.parse_client_versions,
            'server-versions': self.parse_server_versions,
            'known-flags': self.parse_known_flags,
            'params': self.parse_params,
            'dir-source': self.parse_dir_source,
            'r': self.router_parser,
            'bandwidth-weights': self.parse_bandwidth_weights,
            'directory-signature': self.parse_dir_signature,
        }

    def parse(self):
        '''Parse network consensus preamble.

        We don't actually need some of this info since we're just a client,
        so just verify it's formatted correctly and skip over unneeded parts.
        '''

        self.check_consensus_start()

        for line in self.data:
            line = line.strip().split()
            if len(line) == 0:
                continue
            if line[0] in self.parsers:
                self.parsers[line[0]](line)
            else:
                raise Exc.BadConsensusDoc('Bad keyword {0} in network '
                                          'consensus.'.format(line[0]))

    def parse_dir_signature(self, line):
        '''Parse directory signature line.
        '''
        # we have an algorithm specified
        if len(line) == 4:
            # stop pylint complaining about line lengths 
            k = line[2]
            d = line[3]
            self.values['directory_signatures'][line[2]]['algorithm'] = line[1]
            self.values['directory_signatures'][k]['signing-key-digest'] = d
        # no algorithm specified; use sha1
        elif len(line) == 3:
            k = line[1]
            d = line[2]
            self.values['directory_signatures'][line[1]] = {}
            self.values['directory_signatures'][line[1]]['algorithm'] = 'sha1'
            self.values['directory_signatures'][k]['signing-key-digest'] = d
        else:
            raise Exc.BadConsensusDoc('Invalid arguments to '
                                  'directory-signature line.')

        sig = self.get_signature(self.data.readline())
        self.values['directory_signatures'][line[1]]['signature'] = sig

    def get_signature(self, line):
        '''Get a signature from consensus doc.
        '''
        sig = ''
        line = self.data.readline()
        while not line.startswith('-----END SIGNATURE-----'):
            sig += line.strip()
            line = self.data.readline()
        return sig
         
    def parse_bandwidth_weights(self, line):
        '''Parse bandwidth weights line.
        '''
        if self.values['bandwidth_weights'] is not None:
            raise Exc.BadConsensusDoc('Only one bandwidth-weights '
                                  'section allowed in consensus.')

        self.values['bandwidth_weights'] = {}
        keys = [i.split('=') for i in line[1:]]
        for i in keys:
            self.values['bandwidth_weights'][i[0]] = i[1]

    def add_new_router(self, line):
        '''Helper for router_parser: add a new entry to router_status and
        return key to use as reference.
        '''
        key = line[2]
        self.values['router_status'][key] = {}
        self.values['router_status'][key]['nickname'] = line[1]
        self.values['router_status'][key]['digest'] = line[3]

        try:
            timestamp = Com.date_to_timestamp(line[4] + ' ' + line[5])
            self.values['router_status'][key]['publication'] = timestamp
        except ValueError:
            raise Exc.BadConsensusDoc('Badly formed publication time for router.')

        self.values['router_status'][key]['ip'] = line[6]
        self.values['router_status'][key]['orport'] = line[7]
        self.values['router_status'][key]['dirport'] = line[8]

        return key

    def router_parser(self, line):
        '''Parse a router status entry in consensus doc.
        '''
        
        if len(line) != 9:
            raise Exc.BadConsensusDoc('Invalid arguments to \'r\' line '
                                  'in consensus doc.')
        
        key = self.add_new_router(line)

        # go until we hit 'directory-footer'
        l = self.data.readline()
        while not l.startswith('directory-footer'):
            if l.startswith('a'):
                if 'ipv6' not in self.values['router_status'][key]:
                    self.values['router_status'][key]['ipv6'] = []
                l = l.split()
                l = [i.strip() for i in l]
                self.values['router_status'][key]['ipv6'].append(l[1:])
            elif l.startswith('s'):
                if 'flags' in self.values['router_status'][key]:
                    raise Exc.BadConsensusDoc('Only one flags argument per '
                                          'router allowed in consensus.')
                l = l.split()
                l = [i.strip() for i in l]
                self.values['router_status'][key]['flags'] = l[1:]
            elif l.startswith('v'):
                if 'version' in self.values['router_status'][key]:
                    raise Exc.BadConsensusDoc('Only one version argument per '
                                          'router allowed in consensus.')
                l = l.split()
                l = [i.strip() for i in l]
                self.values['router_status'][key]['version'] = l[1:]
            elif l.startswith('w'):
                if 'bandwidth' in self.values['router_status'][key]:
                    raise Exc.BadConsensusDoc('Only one bandwidth argument per '
                                          'router allowed in consensus.')
            elif l.startswith('p'):
                if 'ports' in self.values['router_status'][key]:
                    raise Exc.BadConsensusDoc('Only one ports argument per '
                                          'router allowed in consensus.')
                # ignore this; we'll use info from descriptors
                pass
            elif l.startswith('m'):
                # ignore this for now; not present in recent consensus
                pass
            elif l.startswith('r'):
                l = l.split()
                key = self.add_new_router(l)
            else:
                raise Exc.BadConsensusDoc('Unrecognized consensus keyword {0}'
                                      .format(l.split()[0]))
                
            l = self.data.readline()

    def parse_dir_source(self, line):
        '''Parse dir-source keyword line, contact line, and vote-digest line.
        '''
        if len(line) != 7:
            raise Exc.BadConsensusDoc('Invalid number of arguments to dir-source.')

        # indexed by authority identity key
        key = line[2]
        self.values['authority_values'][key] = {}
        self.values['authority_values'][key]['nickname'] = line[1]
        self.values['authority_values'][key]['address'] = line[3]
        self.values['authority_values'][key]['ip'] = line[4]
        self.values['authority_values'][key]['dirport'] = line[5]
        self.values['authority_values'][key]['orport'] = line[6]

        # get contact info
        line = self.data.readline().split()
        if line[0] != 'contact':
            raise Exc.BadConsensusDoc('Bad keyword {0} in consensus doc - '
                                  'expected \'contact\'.'.format(line[0]))

        self.values['authority_values'][key]['contact'] = line[1:]

        # get vote digest
        line = self.data.readline().split()
        if len(line) != 2:
            raise Exc.BadConsensusDoc('Invalid arguments to vote-digest '
                                  'line in dir-source.')
        if line[0] != 'vote-digest':
            raise Exc.BadConsensusDoc('Bad keyword {0} in consensus doc - '
                                  'expected \'vote-digest\'.'.format(line[0]))

        self.values['authority_values'][key]['vote-digest'] = line[1]

    def verify_line(self, line, keyword, length, single=True):
        '''Helper to parse consensus.

        Verify keyword is first item in line, length is len(line, and,
        if single is True, that this is the first occurence of keyword.
        '''
        if len(line) != length:
            raise Exc.BadConsensusDoc('Not enough arguments for {0}.'\
                                  .format(keyword))

        if line[0] != keyword:
            raise Exc.BadConsensusDoc("Expected {0} in network consensus "
                                  "- got '{1}'".format(keyword, line[0]))

        if self.values['preamble'][keyword] and single:
            raise Exc.BadConsensusDoc("Too many {0} keywords - expected "
                                  "EXACTLY one or AT MOST one.".format(keyword))

    def check_consensus_start(self):
        '''Check consensus starts with good keyword.

        Network consensus docs must start with 'network-status-version' and,
        currently, this version must be '3'.
        '''

        line = self.data.readline().strip().split()
        self.verify_line(line, 'network-status-version', 2)

        if line[1] != '3':
            raise Exc.BadConsensusDoc("network-status-version must be '3'.")

        self.values['preamble'][line[0]] = line[1]

    def parse_vote_status(self, line):
        '''Verify vote-status is consensus.
        '''
        self.verify_line(line, 'vote-status', 2)

        if line[1] != 'consensus':
            raise Exc.BadConsensusDoc("Expected vote-status type 'consensus' "
                                  " - got {0}".format(line[1]))

        self.values['preamble'][line[0]] = line[1]

    def parse_consensus_method(self, line):  
        '''Parse consensus method.
    
        We don't use this for now, so just ignore value.
        '''
        self.verify_line(line, 'consensus-method', 2)
        # don't care about the values so just ignore
        if line[1] != '17':
            raise Exc.BadConsensusDoc("We currently only support "
                                  "consensus-method 17.")
        self.values['preamble'][line[0]] = line[1]

    # XXX need to verify we have a valid date/time
    def parse_valid_after(self, line):
        '''Parse valid-after keyword line.

        valid-after is the start of the interval for this vote.
        '''
        self.verify_line(line, 'valid-after', 3)
        try:
            timestamp = Com.date_to_timestamp(' '.join(line[1:]))
        except ValueError:
            raise Exc.BadConsensusDoc('Improperly formatted date for valid-after')

        self.values['preamble'][line[0]] = timestamp

    def parse_fresh_until(self, line):
        '''Parse fresh-until keyword line.

        fresh-until is the time the next consensus should be produced.
        '''
        self.verify_line(line, 'fresh-until', 3)
        try:
            timestamp = Com.date_to_timestamp(' '.join(line[1:]))
        except ValueError:
            raise Exc.BadConsensusDoc('Improperly formatted date for '
                                  'fresh-until.')

        self.values['preamble'][line[0]] = timestamp

    def parse_valid_until(self, line):
        '''Parse valid-until keyword line.

        End of the interval for this vote.
        '''
        self.verify_line(line, 'valid-until', 3)
        try:
            timestamp = Com.date_to_timestamp(' '.join(line[1:]))
        except ValueError:
            raise Exc.BadConsensusDoc('Improperly formatted date for '
                                  'valid-until.')

        self.values['preamble'][line[0]] = timestamp

    def parse_voting_delay(self, line):
        '''Parse voting-delay keyword.

        Number of seconds votes and signatures can be collected.
        '''
        self.verify_line(line, 'voting-delay', 3)

        self.values['preamble'][line[0]] = line[1:]

    def parse_client_versions(self, line):
        '''Parse client-versions keyword.

        client-versions are recommended Tor versions in ascending order.
        Should match version-spec.txt from tor specification docs.
        '''
        if self.values['preamble'][line[0]] is not None:
            raise Exc.BadConsensusDoc('Keyword {0} must occur at most once '
                                  'in consensus doc.'.format(line[0]))
        self.values['preamble'][line[0]] = line[1:]

    def parse_server_versions(self, line):
        '''Parse server-versions keyword.

        server-versions are recommended relay versions in ascending order.
        should match version-spec.txt in tor spec docs.
        '''
        if self.values['preamble'][line[0]] is not None:
            raise Exc.BadConsensusDoc('Keyword {0} must occur at most once '
                                  'in consensus doc.'.format(line[0]))
        self.values['preamble'][line[0]] = line[1:]

    def parse_known_flags(self, line):
        '''Parse known-flags keyword line.
        '''
        if self.values['preamble'][line[0]] is not None:
            raise Exc.BadConsensusDoc('Keyword {0} must occur exactly once '
                                  'in consensus doc.'.format(line[0]))

        self.values['preamble'][line[0]] = line[1:]

    def parse_params(self, line):
        '''Parse params keyword line.
        '''
        if self.values['preamble'][line[0]] is not None:
            raise Exc.BadConsensusDoc('Keyword {0} must occur at most once '
                                  'in consensus doc.'.format(line[0]))
        self.values['preamble'][line[0]] = {}
        for i in line[1:]:
            i = i.split('=')
            self.values['preamble'][line[0]][i[0]] = i[1]

    def multi_word_exc(self, keyword):
        '''Raise exception if we have more than one keyword that must appear
        either exactly once or at most once.
        '''
        raise Exc.BadConsensusDoc("Only one '{0}' line allowed per network "
                              "consensus document.".format(keyword))

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
class RouterParser:
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
            raise Exc.BadRouterDoc("The keyword 'router' "
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
            raise Exc.BadRouterDoc("The keyword 'bandwidth' "
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
            raise Exc.BadRouterDoc("The keyword 'published' "
                               "requires at least 2 parameters")

        try:
            timestamp = Com.date_to_timestamp(' '.join(line[1:]))
        except ValueError:
            raise Exc.BadRouterDoc('Badly formatted published date in '
                               'router descriptor')

        if self.values['published'] is not None:
            self.multi_word_exc('published')

        self.values['published'] = timestamp
        
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
        self.values['onion-key'] = Com.get_rsa_pub_key(self.data)
        
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
        self.values['signing-key'] = Com.get_rsa_pub_key(self.data)
        
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
        self.values['router-signature'] = Com.get_signature(self.data)
        
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
        raise Exc.BadRouterDoc("Only one '{0}' line allowed per "
                           "router descriptor.".format(keyword))

# TODO:
#       - consider converting dates/times into timestamps
#       - make sure values are reasonable (i.e. date/times are correct, etc.)
#       - make sure *REQUIRED* keywords are present
#       - refactor some stuff to be simpler
#       - check that we actually have all required stuff
class KeyCertParser:
    '''Parse a key certificate file.
    '''
    
    def __init__(self, data):
        '''Initialize data and function mapping dict.
        '''
        self.data = StringIO(data)

        self.values = {}

        # parsing functions
        self.parsers = {
            'dir-address': self.parse_dir_address,
            'dir-key-published': self.parse_dir_key_pub,
            'dir-identity-key': self.parse_dir_ident_key,
            'dir-key-expires': self.parse_dir_key_expires,
            'dir-signing-key': self.parse_dir_sign_key,
            'dir-key-crosscert': self.parse_dir_crosscert,
            'dir-key-certification': self.parse_dir_key_cert,
        }

    def parse(self):
        '''Parse key certificate document.
        '''

        # each entry has multiple lines and values, so we first get
        # the line we need to start, and then parse the rest of the
        # entry for a specific fingerprint
        for line in self.data:
            line = line.strip().split()
            if line[0] == 'dir-key-certificate-version':
                self.add_new_entry(line)
            else:
                raise Exc.BadKeyDoc('Wrong format for key certificate document.')

    def add_new_entry(self, line):
        '''Add a new entry to directory cert dictionary 'values'

        line is the 'dir-key-certificate-version' line, and this entry
        should be indexed by its fingerprint.
        '''
        l = self.data.readline().strip().split()
        if l[0] != 'fingerprint':
            raise Exc.BadKeyDoc("Missing 'fingerprint' line in key "
                            " certificate document.")
        if len(l) != 2:
            raise Exc.BadKeyDoc("Missing fingerprint in key "
                            "certificate document.")

        key = l[1]
        self.values[key] = {}
        self.values[key]['dir-key-certificate-version'] = line[1]

        line = self.data.readline().strip().split()
        while line[0] != 'dir-key-certification':
            if line[0] in self.parsers:
               self.parsers[line[0]](line, key)
            else:
                raise Exc.BadKeyDoc('Invalid or misplaced keyword {0} in key '
                                'certification document.'.format(line[0]))
            line = self.data.readline().strip().split()
        # handle dir-key-certification line - ends this entry
        self.parse_dir_key_cert(line, key)

    def parse_dir_address(self, line, key):
        '''Parse dir-address line for key certificate.

        line is the current line we're on, and key is the key used to 
        reference this entry in the values dict.
        '''
        if 'dir-address' in self.values[key]:
            raise Exc.BadKeyDoc("Only one 'dir-address' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-address'] = line[1]

    def parse_dir_ident_key(self, line, key):
        '''Parse dir-identity-key line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-ident-key' in self.values[key]:
            raise Exc.BadKeyDoc("Only one 'dir-ident-key' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-ident-key'] = Com.get_rsa_pub_key(self.data)

    def parse_dir_key_pub(self, line, key):
        '''Parse dir-key-published line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-key-published' in self.values[key]:
            raise Exc.BadKeyDoc("Only one 'dir-key-published' line allowed "
                            "in key certificate document.")

        try:
            timestamp = Com.date_to_timestamp(' '.join(line[1:]))
        except ValueError:
            raise Exc.BadConsensusDoc('Badly formatted dir-key-published date '
                                  'in key certificates.')

        self.values[key]['dir-key-published'] = timestamp

    def parse_dir_sign_key(self, line, key):
        '''Parse dir-signing-key line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-signing-key' in self.values[key]:
            raise Exc.BadKeyDoc("Only one 'dir-key-published' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-signing-key'] = Com.get_rsa_pub_key(self.data)

    def parse_dir_key_expires(self, line, key):
        '''Parse dir-key-expires line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-key-expires' in self.values[key]:
            raise Exc.BadKeyDoc("Only one 'dir-key-expires' line allowed "
                            "in key certificate document.")

        try:
            timestamp = Com.date_to_timestamp(' '.join(line[1:]))
        except ValueError:
            raise Exc.BadConsensusDoc('Badly formatted dir-key-expires date '
                                  'in key certificates.')

        self.values[key]['dir-key-expires'] = timestamp

    def parse_dir_crosscert(self, line, key):
        '''Parse dir-key-expires line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-key-crosscert' in self.values[key]:
            raise Exc.BadKeyDoc("Only one 'dir-key-crosscert' line allowed "
                            "in key certificate document.")

        self.values[key]['dir-key-crosscert'] = Com.get_id_signature(self.data)

    def parse_dir_key_cert(self, line, key):
        '''Parse dir-key-expires line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-key-certification' in self.values[key]:
            raise Exc.BadKeyDoc("Only one 'dir-key-certification' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-key-certification'] = Com.get_signature(self.data)

if __name__ == '__main__':
    def test_all():
        with open('data/keys.txt', 'r') as f:
            text = f.read()
        k = KeyCertParser(text)
        k.parse()
        for i in k.values:
            print('***\n' + i + '\n***')
            for j in k.values[i]:
                print(j, k.values[i][j])
    
        with open('data/cached-consensus', 'r') as f:
            text = f.read()
        c = ConsensusParser(text)
        c.parse()
        for i in c.values:
            print('***\n' + i + '\n***')
            for j in c.values[i]:
                print(j, c.values[i][j])
    
        with open('data/rd.txt', 'r') as f:
            d = f.read()
        r = RouterParser(d)
        r.parse()
        for i in r.values:
            print(i, r.values[i])

    test_all()
