# TODO:
#       - consider converting dates/times into timestamps
#       - make sure values are reasonable (i.e. date/times are correct, etc.)
#       - make sure *REQUIRED* keywords are present
#       - refactor some stuff to be simpler
#       - check that we actually have all required stuff

from io import StringIO

from Exceptions import BadConsensusDoc
from Common import get_rsa_pub_key, get_signature, get_id_signature

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
                raise BadKeyDoc('Wrong format for key certificate document.')

    def add_new_entry(self, line):
        '''Add a new entry to directory cert dictionary 'values'

        line is the 'dir-key-certificate-version' line, and this entry
        should be indexed by its fingerprint.
        '''
        l = self.data.readline().strip().split()
        if l[0] != 'fingerprint':
            raise BadKeyDoc("Missing 'fingerprint' line in key "
                            " certificate document.")
        if len(l) != 2:
            raise BadKeyDoc("Missing fingerprint in key "
                            "certificate document.")

        key = l[1]
        self.values[key] = {}
        self.values[key]['dir-key-certificate-version'] = line[1]

        line = self.data.readline().strip().split()
        while line[0] != 'dir-key-certification':
            if line[0] in self.parsers:
               self.parsers[line[0]](line, key)
            else:
                raise BadKeyDoc('Invalid or misplaced keyword {0} in key '
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
            raise BadKeyDoc("Only one 'dir-address' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-address'] = line[1]

    def parse_dir_ident_key(self, line, key):
        '''Parse dir-identity-key line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-ident-key' in self.values[key]:
            raise BadKeyDoc("Only one 'dir-ident-key' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-ident-key'] = get_rsa_pub_key(self.data)

    def parse_dir_key_pub(self, line, key):
        '''Parse dir-key-published line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-key-published' in self.values[key]:
            raise BadKeyDoc("Only one 'dir-key-published' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-key-published'] = line[1:]

    def parse_dir_sign_key(self, line, key):
        '''Parse dir-signing-key line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-signing-key' in self.values[key]:
            raise BadKeyDoc("Only one 'dir-key-published' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-signing-key'] = get_rsa_pub_key(self.data)

    def parse_dir_key_expires(self, line, key):
        '''Parse dir-key-expires line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-key-expires' in self.values[key]:
            raise BadKeyDoc("Only one 'dir-key-expires' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-key-expires'] = line[1:]

    def parse_dir_crosscert(self, line, key):
        '''Parse dir-key-expires line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-key-crosscert' in self.values[key]:
            raise BadKeyDoc("Only one 'dir-key-crosscert' line allowed "
                            "in key certificate document.")

        self.values[key]['dir-key-crosscert'] = get_id_signature(self.data)

    def parse_dir_key_cert(self, line, key):
        '''Parse dir-key-expires line in key certificate document.

        line is the current line we're on, and key is used to reference
        the current entry in the values dict.
        '''
        if 'dir-key-certification' in self.values[key]:
            raise BadKeyDoc("Only one 'dir-key-certification' line allowed "
                            "in key certificate document.")
        self.values[key]['dir-key-certification'] = get_signature(self.data)

if __name__ == '__main__':
    with open('data/keys.txt', 'r') as f:
        text = f.read()
    k = KeyCertParser(text)
    k.parse()
    for i in k.values:
        print('***\n' + i + '\n***')
        for j in k.values[i]:
            print(j, k.values[i][j])
