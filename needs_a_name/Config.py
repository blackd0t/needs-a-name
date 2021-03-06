'''Long-lived configuration values.

******************************************
*************** WARNING ******************
******************************************
We need to ensure this information is
always current and exactly matches the
hardcoded info in tor/src/or/config.c in
the actual tor source code.
******************************************
******************************************
******************************************

We use this information to bootstrap ourselves in the tor network
and get initial network status documents.  After getting our first
consensus, we can use directory caches in the future.

In Config.py:
    - directory_auth_info: hardcoded directory authority nickname,
    orport, v3ident digest, ip address, fingerprint, and (for Tonga) bridge
'''

directory_auth_info = [
    {
        'nickname': 'moria1',
        'orport': 9101,
        'v3ident': 'D586D18309DED4CD6D57C18FDB97EFA96D330566',
        'ip': '128.31.0.34:9131',
        'fingerprint': '9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31',
    },
    {
        'nickname': 'tor26',
        'orport': 443,
        'v3ident': '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
        'ip': '86.59.21.38:80',
        'fingerprint': '847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D',
    },
    {
        'nickname': 'dizum',
        'orport': 443,
        'v3ident': 'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58',
        'ip': '194.109.206.212:80',
        'fingerprint': '7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755',
    },
    # Tonga is a bridge directory authority
    {
        'nickname': 'Tonga',
        'orport': 443,
        'ip': '82.94.251.203:80',
        'fingerprint': '4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D',
        'v3ident': None,
        'bridge': True,
    },
    {
        'nickname': 'turtles',
        'orport': 9090,
        'v3ident': '27B6B5996C426270A5C95488AA5BCEB6BCC86956',
        'ip': '76.73.17.194:9030',
        'fingerprint': 'F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B',
    },
    {
        'nickname': 'gabelmoo',
        'orport': 443,
        'v3ident': 'ED03BB616EB2F60BEC80151114BB25CEF515B226',
        'ip': '212.112.245.170:80',
        'fingerprint': 'F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281',
    },
    {
        'nickname': 'dannenberg',
        'orport': 443,
        'v3ident': '585769C78764D58426B8B52B6651A5A71137189A',
        'ip': '193.23.244.244:80',
        'fingerprint': '7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123',
    },
    {
        'nickname': 'urras',
        'orport': 80,
        'v3ident': '80550987E1D626E3EBA5E5E75A458DE0626D088C',
        'ip': '208.83.223.34:443',
        'fingerprint': '0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417',
    },
    {
        'nickname': 'maatuska',
        'orport': 80,
        'v3ident': '49015F787433103580E3B66A1707A00E60F2D15B',
        'ip': '171.25.193.9:443',
        'fingerprint': 'BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810',
    },
    {
        'nickname': 'Faravahar',
        'orport': 443,
        'v3ident': 'EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97',
        'ip': '154.35.32.5:80',
        'fingerprint': 'CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC',
    },
]

bandwidth_weights = [
    'Wgg',
    'Wgm',
    'Wgd',
    'Wmg',
    'Wmm',
    'Wme',
    'Wmd',
    'Weg',
    'Wem',
    'Wee',
    'Wed',
    'Wgb',
    'Wmb',
    'Web',
    'Wdb',
    'Wbg',
    'Wbm',
    'Wbe',
    'Wbd',
]

consensus_cache_file = 'data/cached-consensus'
key_cache_file       = 'data/cached-keys'

consensus_url = '/tor/status-vote/current/consensus.z'
key_url       = '/tor/keys/all.z'
