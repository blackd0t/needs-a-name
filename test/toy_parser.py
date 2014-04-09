#! /usr/bin/env python3

'''Example of some ideas for implementing a simple parser.

Not actually functionally, just a little prototype.
'''

class RouterDescParser():
    '''Example class for parsing router descriptors.
    '''

    def __init__(self, data):
        self.data = data
        self.keys = set('orport', 'dirport', 'something_else')

    def parse(self):
        '''Iterate through data line by line, calling appropriate
        function if we see a keyword, otherwise skipping.

        *NOTE* need to figure out exactly what the rules say
        about unrecognized keywords and whether to error or skip.
        '''

        router_desc_info = {}

        data = self.data.split('\n')

        for line in range(len(data)):
            key = line.split(' ')[0].strip()
            if key in keys:
                if key == 'orport':
                    line += self.parse_orport(data, line, router_desc_info)
                elif key == 'dir_port':
                    line += self.parse_dirport(data, line, router_desc_info)
            else:
                line += self.unknown_key(data, line)

        return router_desc_info

    def parse_orport(self, data, line, rinfo):
        '''Parse orport keyword line according to rules in dir-spec.
        '''
        skip_lines = 0
        # do some parsing here
        # track how many lines to skip (if we just parse 1 line, skip zero)
        rinfo['orport'] = orport

        return skip_lines

    def parse_dirport(self, data, line, rinfo):
        '''Same as above
        '''
        pass

    def handle_unknown_key(self, data, line):
        '''Handle unknown key according to dir-spec.
        '''
        pass
        
