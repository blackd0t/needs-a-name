import calendar
import os
import unittest

from datetime import datetime

import Exceptions as Exc

from DocParsers import ConsensusParser

working_dir = os.path.dirname(os.path.realpath(__file__))
doc_path = working_dir + '/files/test-consensus'

with open(doc_path, 'r') as f:
    good_consensus = f.read()

flag_list = [
    'Authority', 
    'BadExit', 
    'Exit', 
    'Fast', 
    'Guard',
    'HSDir',
    'Named',
    'Running',
    'Stable',
    'Unnamed',
    'V2Dir',
    'Valid'
]

params = {
    'CircuitPriorityHalflifeMsec': 30000,
    'NumNTorsPerTAP': 100,
    'UseNTorHandshake': 1,
    'UseOptimisticData': 1,
    'bwauthpid': 1,
    'cbttestfreq': 1000000,
    'pb_disablepct': 0,
    'usecreatefast': 0,
}

# XXX finished with preamble tests, with notable exception of checking for
#     all required values. note that failing because of not having all required
#     values is both: a) something we have to do and b) something that will 
#     break some of these tests...oh well

class ConsensusParserTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        c = ConsensusParser(good_consensus)
        c.parse()
        cls.values = c.values

    def test_missing_network_stat_version(self):
        '''Test for missing network-status-version keyword at start.
        '''
        text = 'vote-status consensus\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_too_many_network_stat_args(self):
        '''Test for too many network-status-version args.
        '''
        text = 'network-status-version 3 t\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_wrong_network_stat_version(self):
        '''We only support network-status-version 3.
        '''
        text = 'network-status-version 2\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_vote_status_too_many_args(self):
        '''vote-status only has 1 argument.
        '''
        text = 'network-status-version 3\nvote-status consensus t\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_vote_status_wrong_type(self):
        '''vote-status must be 'consensus'
        '''
        text = 'network-status-version 3\nvote-status vote\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_consensus_method_arg_number(self):
        '''consensus-method has 1 argument.
        '''
        text = 'network-status-version 3\nvote-status consensus\n'
        text += 'consensus-method 17 3\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_consensus_method_args(self):
        '''verify consensus-method has valid arg (currently only support 17)
        '''
        text = 'network-status-version 3\nvote-status consensus\n'
        text += 'consensus-method 16\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_valid_after(self):
        '''verify valid-after only accepts 3 args, fails if bad args, and
        can format a timestamp properly.
        '''
        text = 'network-status-version3\nvalid-after 2014-01-01 13:00:00'
        bad = text + ' 1\n'
        # too many args
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)
        # improperly formatted date
        bad = text + 'x\n'
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)
        # make sure we get a correct timestamp
        correct = datetime.strptime('2014-04-24 15:00:00', '%Y-%m-%d %H:%M:%S')
        correct = calendar.timegm(correct.utctimetuple())
        self.assertEqual(correct, self.values['preamble']['valid-after'])

    def test_fresh_until(self):
        '''test fresh_until arg count, bad arg behavior, and timestamp format
        '''
        text = 'network-status-version3\nfresh-until 2014-01-01 13:00:00'
        bad = text + ' 1\n'
        # too many args
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)
        # improperly formatted date
        bad = text + 'x\n'
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)
        # make sure we get a correct timestamp
        correct = datetime.strptime('2014-04-24 16:00:00', '%Y-%m-%d %H:%M:%S')
        correct = calendar.timegm(correct.utctimetuple())
        self.assertEqual(correct, self.values['preamble']['fresh-until'])

    def test_valid_until(self):
        '''test valid_until arg count, bad arg behavior, and timestamp format
        '''
        text = 'network-status-version 3\nvalid-until 2014-01-01 13:00:00'
        bad = text + ' 1\n'
        # too many args
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)
        # improperly formatted date
        bad = text + 'x\n'
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)
        # make sure we get a correct timestamp
        correct = datetime.strptime('2014-04-24 18:00:00', '%Y-%m-%d %H:%M:%S')
        correct = calendar.timegm(correct.utctimetuple())
        self.assertEqual(correct, self.values['preamble']['valid-until'])

    def test_voting_delay(self):
        '''test voting delay arg count and format
        '''
        text = 'network-status-version 3\nvoting-delay 300 300'
        bad = text + ' 1\n'
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)
        bad = text + 'x\n'
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)

    def test_client_versions(self):
        '''don't care about values - just check arg number
        '''
        text = 'network-status-version 3\nclient-versions \n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)
        text = 'network-status-version 3\nclient-versions x x\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_server_versions(self):
        '''don't care about values - just check arg number
        '''
        text = 'network-status-version 3\nclient-versions \n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)
        text = 'network-status-version 3\nclient-versions x x\n'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)

    def test_known_flags(self):
        '''test that we can read flags correctly.
        '''
        for i in flag_list:
            self.assertTrue(i in self.values['preamble']['known-flags'])


    def test_params(self):
        '''test invalid args and that we get correct values.
        '''
        text = 'network-status-version 3\nparams cbttestfreq=x'
        self.assert_raises_helper(text, Exc.BadConsensusDoc)
        for i in params:
            self.assertTrue(params[i] == self.values['preamble']['params'][i])

    def assert_raises_helper(self, text, exc):
        '''assertRaises(exc) on string text
        '''
        with self.assertRaises(Exc.BadConsensusDoc):
            c = ConsensusParser(text)
            c.parse()
