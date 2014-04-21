'''
Download network status documents.

We follow some simple rules: 

    * Network Consensus Documents *

    - try to have a live consensus network-status document at all times
        ("live" means time in valid-until field has not passed)
    - when we have to ns consensus, download randomly from an authority,
      otherwise (i.e. if we have an old cached version) download randomly
      from a cache we think is a V3 directory server
    - discard any documents we didn't request
    - on failure, wait "briefly" and then try from another cache
    - download fresh consensus at randomly chosen time
        (chosen uniformly at random from the interval between the time 3/4
         into the first interval after the consensus is no longer fresh, and
         7/8 of the time remaining after that before consensus is invalid)

    * Router Descriptor Documents *

    - always try to have "best" router descriptor for each router
        ("best" == listed in consensus doc)
    - check approx. every 10 seconds if there are any "downloadable" 
      descriptors. a descriptor is "downloadable" if:
        - it's the "best" descriptor for some router
        - it was published at least 10 min in the past
        - we don't have it
        - we're not trying to download it
        - we wouldn't immediately discard it
        - we think it's both running and valid (flags)
    - if at least 16 known routers have downloadable descriptors, or if
      enough time (10 minutes) has passed since the last time we tried
      to download descriptors, we should launch requests for all available
      descriptors
    - when downloading multiple descriptors:
        - at least 3 different mirrors are used, except with this would result
          in more than one request for under 4 descriptors
        - no more than 128 descriptors are requested from a single mirror
        - otherwise, use as few mirrors as possible
    - after choosing mirrors, divide descriptors among them randomly
    - we must discard any descriptors we didn't request
    - when a download fails, don't try again until X time has passed
        (X == 0 seconds for first failure, 60 seconds for the second failure,
         5 minutes for the thrid failure, 10 minutes for the fourth, and
         1 day for all future failures -- *reset* failure count every hour)
    - retain most recent descriptor for 48 hours *OR* so long as no better
      descriptor for this router has been downloaded
    - 

'''
