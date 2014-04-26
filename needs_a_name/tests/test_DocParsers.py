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

bad_tor26_nickname = '''
network-status-version 3
dir-source tor27 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38 86.59.21.38 80 443
contact Peter Palfrader
vote-digest A0D395CA16E77BF496D816D2BFE88B007E7DA046
'''

bad_tor26_port = '''
network-status-version 3
dir-source tor26 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38 86.59.21.38 80 444
contact Peter Palfrader
vote-digest A0D395CA16E77BF496D816D2BFE88B007E7DA046
'''

bad_tor26_ip = '''
network-status-version 3
dir-source tor26 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.34 86.59.21.38 80 443
contact Peter Palfrader
vote-digest A0D395CA16E77BF496D816D2BFE88B007E7DA046
'''

bad_tor26_v3 = '''
network-status-version 3
dir-source tor26 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B 86.59.21.38 86.59.21.38 80 443
contact Peter Palfrader
vote-digest A0D395CA16E77BF496D816D2BFE88B007E7DA046
'''

bad_r_date = '''
network-status-version 3
known-flags Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid
r TorNinurtaName AA8YrCza5McQugiY3J4h5y4BF9g 5iqAr4PxmFuGsJtcMAB3hUe0T1E 2014-04-246 00:29:18 151.236.6.198 9001 9030
s Fast HSDir Running Stable V2Dir Valid
v Tor 0.2.3.25
w Bandwidth=193
p reject 1-65535
'''

bad_r_ip = '''
network-status-version 3
known-flags Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid
r TorNinurtaName AA8YrCza5McQugiY3J4h5y4BF9g 5iqAr4PxmFuGsJtcMAB3hUe0T1E 2014-04-24 00:29:18 151.236.6.1987 9001 9030
s Fast HSDir Running Stable V2Dir Valid
v Tor 0.2.3.25
w Bandwidth=193
p reject 1-65535
'''

bad_r_port = '''
network-status-version 3
known-flags Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid
r TorNinurtaName AA8YrCza5McQugiY3J4h5y4BF9g 5iqAr4PxmFuGsJtcMAB3hUe0T1E 2014-04-24 00:29:18 151.236.6.198 9001 90304
s Fast HSDir Running Stable V2Dir Valid
v Tor 0.2.3.25
w Bandwidth=193
p reject 1-65535
'''

bad_s_flag = '''
network-status-version 3
known-flags Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid
r TorNinurtaName AA8YrCza5McQugiY3J4h5y4BF9g 5iqAr4PxmFuGsJtcMAB3hUe0T1E 2014-04-24 00:29:18 151.236.6.198 9001 9030
s Fast HSDir Running Stable V2Dir Valid InvalidRouterFlag
v Tor 0.2.3.25
w Bandwidth=193
p reject 1-65535
'''

bad_w_band = '''
network-status-version 3
known-flags Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid
r TorNinurtaName AA8YrCza5McQugiY3J4h5y4BF9g 5iqAr4PxmFuGsJtcMAB3hUe0T1E 2014-04-24 00:29:18 151.236.6.198 9001 9030
s Fast HSDir Running Stable V2Dir Valid
v Tor 0.2.3.25
w Bandwidth=BadBandwidth
p reject 1-65535
'''

bad_p_reject = '''
network-status-version 3
known-flags Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid
r TorNinurtaName AA8YrCza5McQugiY3J4h5y4BF9g 5iqAr4PxmFuGsJtcMAB3hUe0T1E 2014-04-24 00:29:18 151.236.6.198 9001 9030
s Fast HSDir Running Stable V2Dir Valid
v Tor 0.2.3.25
w Bandwidth=BadBandwidth
p reject 1-65536
'''

bad_a_ipv6 = '''
network-status-version 3
known-flags Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid
r tor1rufus /baOacH+/u/tl/0o3slYR4P5zc0 4vpiFgwPkfXz/zmyCMLmDz8W1Wg 2014-04-24 09:08:13 209.240.71.9 9001 9002
a [2001:4980:1:2121::9j]:9001
s Fast Guard HSDir Running Stable Unnamed V2Dir Valid
v Tor 0.2.5.2-alpha
w Bandwidth=519
p reject 1-65535
'''

bad_p_accept = '''
network-status-version 3
known-flags Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid
r Unnamed /kCKj6j4jeQpjIKchLpdqr95Pw0 bQmrSzX9PeUOt4NeWofFYaW8oj4 2014-04-23 21:19:44 173.208.196.215 9001 0
s Exit Fast Running Stable Valid
v Tor 0.2.4.21
w Bandwidth=614
p accept 20-23,43,53,79-81,88,110,143,194,220,389,443,464,531,543-544,554,563,636,706,749,873,902-904,981,989-995,1194,1220,1293,1500,1533,1677,1723,1755,1863,2082-2083,2086-2087,2095-2096,2102-2104,3128,3389,3690,4321,4643,5050,5190,5222-5223,5228,5900,6660-6669,6679,6697,8000,8008,8074,8080,8087-8088,8332-8333,8443,8888,9418,9999-10000,11371,12350,19294,19638,23456,33033,64738,65555
'''

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

    # start of authority section tests
    def test_dir_source_single_entry(self):
        '''test dir-source line parsing in authority section for a single entry
        '''
        text = 'network-status-version 3\n'
        line1 = 'dir-source tor26 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 '
        line1 += '86.59.21.38 86.59.21.38 80 443\n'
        line2 = 'contact Peter Palfrader\n'
        line3 = 'vote-digest A0D395CA16E77BF496D816D2BFE88B007E7DA046\n'

        # missing argument
        bad = line1[:-4] + '\n' + line2 + line3
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)

        # invalid hostname
        bad = ' '.join(line1.split()[:2]) + ' 8677.59.21.38 ' 
        bad += ' '.join(line1.split()[4:]) + '\n' + line2 + line3
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)

        # invalid ip
        bad = ' '.join(line1.split()[:4]) + ' 8677.59.21.38 ' 
        bad += ' '.join(line1.split()[5:]) + '\n' + line2 + line3
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)

        # invalid port - processing same for dirport and orport
        bad = ' '.join(line1.split()[:6]) + ' 65536\n'
        bad += line2 + line3
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)

        # missing contact info
        bad = line1 + 'contact\n' + line3
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)

        # XXX do we need to validate length/chars of digest too?
        # missing digest
        bad = line1 + line2 + 'vote-digest\n'
        self.assert_raises_helper(bad, Exc.BadConsensusDoc)

    def test_dir_source_all(self):
        '''verify we throw exception if dir auth identity key, address, etc.
        does not match what is hardcoded.
        '''
        self.assert_raises_helper(bad_tor26_v3, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_tor26_ip, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_tor26_nickname, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_tor26_port, Exc.BadConsensusDoc)

    def test_router_status(self):
        '''test router status entries fail when they should.
        '''
        self.assert_raises_helper(bad_r_date, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_r_ip, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_r_port, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_s_flag, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_w_band, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_p_reject, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_p_accept, Exc.BadConsensusDoc)
        self.assert_raises_helper(bad_a_ipv6, Exc.BadConsensusDoc)



    def assert_raises_helper(self, text, exc):
        '''assertRaises(exc) on string text
        '''
        with self.assertRaises(exc):
            c = ConsensusParser(text, False)
            c.parse()
