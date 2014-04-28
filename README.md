needs-a-name
============
This is a Python implementation of a Tor client.

## Warning
**Do Not**, under any circumstances, use this tool if you want anonymity
or privacy.  You should use the official Tor software from the Tor Project
(specifically, either the Tor Browser Bundle or Tails).  We are not affiliated
with the Tor Project and are writing this simply to understand the Tor protocol
better and learn more about onion routing and anonymity systems.

All further references to Tor (or tor), unless otherwise specified, refer to
the protocol and not to the organization.

#### Design
We're using stem for consensus and descriptor parsing and data structures.
Still experimenting with what asynchronous networking framework will be
best to use.
