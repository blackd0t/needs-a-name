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
        'nickaname': 'moria1',
        'orport': 9101,
        'v3ident': 0x0,
        'ip': '128.31.0.39:9131',
        'fingerprint': 0x0,
    },
    {
        'nickname': 'tor26',
        'orport': 443,
        'v3ident': 0x0,
        'ip': '86.59.21.38:80',
        'fingerprint': 0x0,
    },
    {
        'nickname': 'dizum',
        'orport': 443,
        'v3ident': 0x0,
        'ip': '194.109.206.212:80',
        'fingerprint': 0x0,
    },
    # Tonga is a bridge directory authority
    {
        'nickname': 'Tonga',
        'orport': 443,
        'v3ident': 0x0,
        'ip': '82.94.251.203:80',
        'fingerprint': 0x0,
        'bridge': True,
    },
    {
        'nickname': 'turtles',
        'orport': 9090,
        'v3ident': 0x0,
        'ip': '76.73.17.194:9030',
        'fingerprint': 0x0,
    },
    {
        'nickname': 'gabelmoo',
        'orport': 443,
        'v3ident': 0x0,
        'ip': '212.112.245.170:80',
        'fingerprint': 0x0,
    },
    {
        'nickname': 'dannenberg',
        'orport': 443,
        'v3ident': 0x0,
        'ip': '193.23.244.244:80',
        'fingerprint': 0x0,
    },
    {
        'nickname': 'urras',
        'orport': 80,
        'v3ident': 0x0,
        'ip': '208.83.223.34:443',
        'fingerprint': 0x0,
    },
    {
        'nickname': 'maatuska',
        'orport': 80,
        'v3ident': 0x0,
        'ip': '171.25.193.9:443',
        'fingerprint': 0x0,
    },
    {
        'nickname': 'Faravahar',
        'orport': 443,
        'v3ident': 0x0,
        'ip': '154.35.32.5:80',
        'fingerprint': 0x0,
    },
]

consensus_cache_file = 'data/cached-consensus'
key_cache_file       = 'data/cached-keys'

consensus_url = '/tor/status-vote/current/consensus.z'
key_url       = '/tor/keys/all.z'
