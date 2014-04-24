import unittest

from DocParsers import ConsensusParser
from Exceptions import *

class PreambleTest(unittest.TestCase):

    def test_missing_network_stat_version(self):
        '''Test for missing network-status-version keyword at start.
        '''
        text = 'vote-status consensus\n'
        self.assert_raises_helper(text, BadConsensusDoc)

    def test_too_many_network_stat_args(self):
        '''Test for too many network-status-version args.
        '''
        text = 'network-status-version 3 t\n'
        self.assert_raises_helper(text, BadConsensusDoc)

    def test_wrong_network_stat_version(self):
        '''We only support network-status-version 3.
        '''
        text = 'network-status-version 2\n'
        self.assert_raises_helper(text, BadConsensusDoc)

    def test_vote_status_too_many_args(self):
        '''vote-status only has 1 argument.
        '''
        text = 'network-status-version 3\nvote-status consensus t\n'
        self.assert_raises_helper(text, BadConsensusDoc)

    def test_vote_status_wrong_type(self):
        '''vote-status must be 'consensus'
        '''
        text = 'network-status-version 3\nvote-status vote\n'
        self.assert_raises_helper(text, BadConsensusDoc)

    def test_consensus_method_arg_number(self):
        '''consensus-method has 1 argument.
        '''
        text = 'network-status-version 3\nvote-status consensus\n'
        text += 'consensus-method 17 3\n'
        self.assert_raises_helper(text, BadConsensusDoc)

    def test_consensus_method_args(self):
        '''verify consensus-method has valid arg (currently only support 17)
        '''
        text = 'network-status-version 3\nvote-status consensus\n'
        text += 'consensus-method 16\n'
        self.assert_raises_helper(text, BadConsensusDoc)

    def assert_raises_helper(self, text, exc):
        '''assertRaises(exc) on string text
        '''
        with self.assertRaises(BadConsensusDoc):
            c = ConsensusParser(text)
            c.parse()

if __name__ == '__main__':
    unittest.main()
