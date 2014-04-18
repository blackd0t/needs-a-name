# TODO:
#       - make sure values are reasonable (i.e. date/times are correct, etc.)
#       - make sure *REQUIRED* keywords are present (maybe at end of 
#                                                    parse_preamble)
#       - refactor some stuff to be simpler
#       - check that we actually have all required stuff
#       - remove preamble_values and instead use one dict for everything,
#         with nested dicts if needed for other stuff

from io import StringIO

from Exceptions import BadConsensusDoc

class ConsensusParser:
    '''Parse a network consensus.
    '''
    
    def __init__(self, data):
        '''Initialize data and function mapping dict.
        '''
        self.data = StringIO(data)

        self.preamble_values = {
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
        }

        self.authority_values = {}

        self.router_status = {}

        self.bandwidth_weights = None

        self.directory_signatures = {}

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

        # stop when we hit 'r' and put line back in stream --
        # this means we've hit router status entries
        for line in self.data:
            line = line.strip().split()
            if len(line) == 0:
                continue
            if line[0] in self.parsers:
                self.parsers[line[0]](line)
            else:
                raise BadConsensusDoc('Bad keyword {0} in network consensus.'\
                                      .format(line[0]))

    def parse_dir_signature(self, line):
        '''Parse directory signature line.
        '''
        # we have an algorithm specified
        if len(line) == 4:
            self.directory_signatures[line[2]] = {}
            self.directory_signatures[line[2]]['algorithm'] = line[1]
            self.directory_signatures[line[2]]['signing-key-digest'] = line[3]
        # no algorithm specified; use sha1
        elif len(line) == 3:
            self.directory_signatures[line[1]] = {}
            self.directory_signatures[line[1]]['algorithm'] = 'sha1'
            self.directory_signatures[line[1]]['signing-key-digest'] = line[2]
        else:
            raise BadConsensusDoc('Invalid arguments to '
                                  'directory-signature line.')

        sig = self.get_signature(self.data.readline())
        self.directory_signatures[line[1]]['signature'] = sig

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
        if self.bandwidth_weights is not None:
            raise BadConsensusDoc('Only one bandwidth-weights '
                                  'section allowed in consensus.')

        self.bandwidth_weights = {}
        keys = [i.split('=') for i in line[1:]]
        for i in keys:
            self.bandwidth_weights[i[0]] = i[1]

    def router_parser(self, line):
        '''Parse a router status entry in consensus doc.
        '''
        
        if len(line) != 9:
            raise BadConsensusDoc('Invalid arguments to \'r\' line '
                                  'in consensus doc.')
        
        key = line[2]
        self.router_status[key] = {}
        self.router_status[key]['nickname'] = line[1]
        self.router_status[key]['digest'] = line[3]
        self.router_status[key]['publication'] = line[4] + ' ' + line[5]
        self.router_status[key]['ip'] = line[6]
        self.router_status[key]['orport'] = line[7]
        self.router_status[key]['dirport'] = line[8]

        # go until we hit 'directory-footer'
        l = self.data.readline()
        while not l.startswith('directory-footer'):
            if l.startswith('a'):
                if 'ipv6' not in self.router_status[key]:
                    self.router_status[key]['ipv6'] = []
                l = l.split()
                l = [i.strip() for i in l]
                self.router_status[key]['ipv6'].append(l[1:])
            elif l.startswith('s'):
                if 'flags' in self.router_status[key]:
                    raise BadConsensusDoc('Only one flags argument per '
                                          'router allowed in consensus.')
                l = l.split()
                l = [i.strip() for i in l]
                self.router_status[key]['flags'] = l[1:]
            elif l.startswith('v'):
                if 'version' in self.router_status[key]:
                    raise BadConsensusDoc('Only one version argument per '
                                          'router allowed in consensus.')
                l = l.split()
                l = [i.strip() for i in l]
                self.router_status[key]['version'] = l[1:]
            elif l.startswith('w'):
                if 'bandwidth' in self.router_status[key]:
                    raise BadConsensusDoc('Only one bandwidth argument per '
                                          'router allowed in consensus.')
            elif l.startswith('p'):
                if 'ports' in self.router_status[key]:
                    raise BadConsensusDoc('Only one ports argument per '
                                          'router allowed in consensus.')
                # ignore this; we'll use info from descriptors
                pass
            elif l.startswith('m'):
                # ignore this for now; not present in recent consensus
                pass
            elif l.startswith('r'):
                l = l.split()
                key = l[2]
                self.router_status[key] = {}
                self.router_status[key]['nickname'] = l[1]
                self.router_status[key]['digest'] = l[3]
                self.router_status[key]['publication'] = l[4] + ' ' + l[5]
                self.router_status[key]['ip'] = l[6]
                self.router_status[key]['orport'] = l[7]
                self.router_status[key]['dirport'] = l[8]
            else:
                raise BadConsensusDoc('Unrecognized consensus keyword {0}'
                                      .format(l.split()[0]))
                
            l = self.data.readline()

        # get 's' line
        #line = self.data.readline().split()
        #if len(line) != 4:
        #    raise BadConsensusDoc('Invalid arguments to \'s\' line '
        #                          'in consensus doc.')
        #if line[0] != 's':
        #    raise BadConsensusDoc('Missing \'s\' keyword in router status.')
        #
        #self.router_status[key]['flags'] = line[1:]
        #
        # get 'v' line
        #line = self.data.readline().split()
        #if len(line) != 3:
        #    raise BadConsensusDoc('Invalid arguments to \'v\' line '
        #                          'in consensus doc.')
        #if line[0] != 'v':
        #    raise BadConsensusDoc('Missing \'v\' keyword in router status.')
        #
        #self.router_status[key]['flags'] = line[1:]

    def parse_dir_source(self, line):
        '''Parse dir-source keyword line, contact line, and vote-digest line.
        '''
        if len(line) != 7:
            raise BadConsensusDoc('Invalid number of arguments to dir-source.')

        # indexed by authority identity key
        key = line[2]
        self.authority_values[key] = {}
        self.authority_values[key]['nickname'] = line[1]
        self.authority_values[key]['address'] = line[3]
        self.authority_values[key]['ip'] = line[4]
        self.authority_values[key]['dirport'] = line[5]
        self.authority_values[key]['orport'] = line[6]

        # get contact info
        line = self.data.readline().split()
        if line[0] != 'contact':
            raise BadConsensusDoc('Bad keyword {0} in consensus doc - '
                                  'expected \'contact\'.'.format(line[0]))

        self.authority_values[key]['contact'] = line[1:]

        # get vote digest
        line = self.data.readline().split()
        if len(line) != 2:
            raise BadConsensusDoc('Invalid arguments to vote-digest '
                                  'line in dir-source.')
        if line[0] != 'vote-digest':
            raise BadConsensusDoc('Bad keyword {0} in consensus doc - '
                                  'expected \'vote-digest\'.'.format(line[0]))

        self.authority_values[key]['vote-digest'] = line[1]

    def verify_line(self, line, keyword, length, single=True):
        '''Helper to parse consensus.

        Verify keyword is first item in line, length is len(line, and,
        if single is True, that this is the first occurence of keyword.
        '''
        if self.preamble_values[keyword] and single:
            raise BadConsensusDoc("Too many {0} keywords - expected "
                                  "EXACTLY one.".format(keyword))
        if len(line) != length:
            raise BadConsensusDoc('Not enough arguments for {0}.'\
                                  .format(keyword))

    def check_consensus_start(self):
        '''Check consensus starts with good keyword.

        Network consensus docs must start with 'network-status-version' and,
        currently, this version must be '3'.
        '''

        line = self.data.readline().strip().split()
        self.verify_line(line, 'network-status-version', 2)

        self.preamble_values[line[0]] = line[1]



    def parse_vote_status(self, line):
        '''Verify vote-status is consensus.
        '''

        self.verify_line(line, 'vote-status', 2)

        if line[1] != 'consensus':
            raise BadConsensusDoc("Expected type 'consensus' "
                                  " - got {0}".format(line[1]))

        self.preamble_values[line[0]] = line[1]

    def parse_consensus_method(self, line):  
        '''Parse consensus method.
    
        We don't use this for now, so just ignore value.
        '''
        self.verify_line(line, 'consensus-method', 2)
        # don't care about the values so just ignore
        self.preamble_values[line[0]] = line[1]

    def parse_valid_after(self, line):
        '''Parse valid-after keyword line.

        valid-after is the start of the interval for this vote.
        '''
        self.verify_line(line, 'valid-after', 3)

        self.preamble_values[line[0]] = line[1:]

    def parse_fresh_until(self, line):
        '''Parse fresh-until keyword line.

        fresh-until is the time the next consensus should be produced.
        '''
        self.verify_line(line, 'fresh-until', 3)

        self.preamble_values[line[0]] = line[1:]

    def parse_valid_until(self, line):
        '''Parse valid-until keyword line.

        End of the interval for this vote.
        '''
        self.verify_line(line, 'valid-until', 3)

        self.preamble_values[line[0]] = line[1:]

    def parse_voting_delay(self, line):
        '''Parse voting-delay keyword.

        Number of seconds votes and signatures can be collected.
        '''
        self.verify_line(line, 'voting-delay', 3)

        self.preamble_values[line[0]] = line[1:]

    def parse_client_versions(self, line):
        '''Parse client-versions keyword.

        client-versions are recommended Tor versions in ascending order.
        Should match version-spec.txt from tor specification docs.
        '''

        if self.preamble_values[line[0]] is not None:
            raise BadConsensusDoc('Keyword {0} must occur at most once '
                                  'in consensus doc.'.format(line[0]))
        self.preamble_values[line[0]] = line[1:]

    def parse_server_versions(self, line):
        '''Parse server-versions keyword.

        server-versions are recommended relay versions in ascending order.
        should match version-spec.txt in tor spec docs.
        '''
        if self.preamble_values[line[0]] is not None:
            raise BadConsensusDoc('Keyword {0} must occur at most once '
                                  'in consensus doc.'.format(line[0]))
        self.preamble_values[line[0]] = line[1:]

    def parse_known_flags(self, line):
        '''Parse known-flags keyword line.
        '''
        if self.preamble_values[line[0]] is not None:
            raise BadConsensusDoc('Keyword {0} must occur exactly once '
                                  'in consensus doc.'.format(line[0]))

        self.preamble_values[line[0]] = line[1:]

    def parse_params(self, line):
        '''Parse params keyword line.
        '''
        if self.preamble_values[line[0]] is not None:
            raise BadConsensusDoc('Keyword {0} must occur at most once '
                                  'in consensus doc.'.format(line[0]))
        self.preamble_values[line[0]] = {}
        for i in line[1:]:
            i = i.split('=')
            self.preamble_values[line[0]][i[0]] = i[1]

if __name__ == '__main__':
    with open('data/cns.txt', 'r') as f:
        text = f.read()
    c = ConsensusParser(text)
    c.parse()
    for i in c.preamble_values:
        print(i, c.preamble_values[i])
    for i in c.authority_values:
        print(i, c.authority_values[i])
    for i in c.router_status:
        print(i, c.router_status[i])
    for i in c.bandwidth_weights:
        print(i, c.bandwidth_weights[i])
    for i in c.directory_signatures:
        print(i, c.directory_signatures[i])
