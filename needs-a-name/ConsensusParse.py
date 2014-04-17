# contains:
#   - preamble 
#   - authority section
#   - a list of router status entries
#   - one or more footer signatures 
#   (in exactly this order)

# some important rules:
#   - SP *must* be single space character (hex 20)
#   - order of stuff matters

# TODO:
#       - make sure values are reasonable (i.e. date/times are correct, etc.)
#       - make sure *REQUIRED* keywords are present (maybe at end of 
#                                                    parse_preamble)

from io import StringIO

from Exceptions import BadConsensusDoc

class ConsensusParser:
    '''Parse a network consensus.
    '''
    
    def __init__(self, data):
        '''Initialize data and function mapping dict.

        Args:
            data (str): data is the raw string of router descriptor info
                        data MUST be decompressed, decoded, and its signature
                        verified before being passed in
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
        }


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

    def parse_preamble(self):
        '''Parse network consensus preamble.

        We don't actually need some of this info since we're just a client,
        so just verify it's formatted correctly and skip over unneeded parts.
        '''

        self.check_consensus_start()

        # stop when we hit 'r' and put line back in stream --
        # this means we've hit router status entries
#        for line in self.data:
        while True:
            line = self.data.readline()
            line = line.strip().split()
            if line[0] in self.parsers:
                self.parsers[line[0]](line)
            elif line[0] == 'dir-source':
                self.data.seek(-len(''.join(line)), 1)
                break
            else:
                raise BadConsensusDoc('Bad keyword {0} in network consensus.'\
                                      .format(line[0]))



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


    def parse(self):
        self.parse_preamble()
        for i in self.preamble_values:   
            print(i, self.preamble_values[i])

if __name__ == '__main__':
    with open('data/cns.txt', 'r') as f:
        text = f.read()
    c = ConsensusParser(text)
    c.parse()
