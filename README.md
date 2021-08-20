# ciphersack

A proof of concept showing steganographic file storage. Here's an (abstract)
use case:

Imagine you'd like to set up a file sharing service and have no resources to
monitor its usage nor want to violate other people's privacy. Ideally, a system
should let anyone write to the service and share the results, but only people
who have the metadata file (in this case: a .torrent file) can access it.
You'd also prefer not to leak the information about how much data there is.

This PoC attempts to solve this in the following way:

1. Fill the hard drive with pseudo-random data,
2. Split the file into hashed chunks like BitTorrent does
3. For each chunk, calculate its offset on the drive based on the hash contents,
4. Store the chunk, AES-encrypted (CTR mode) under that offset
