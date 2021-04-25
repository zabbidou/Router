# Router
Communication Protocols homework in which we had to code a simulation for a packet router in C, including routing tables, ARP tables and ARP requests. For the routing table, I chose to "memorize" it as a 4-ary trie, for quick lookup.

## General operation
When the router receives a package, it checks for the checksum and TTL. If TTL is less or equal to 1, the router replies back with ICMP Timeout. If the TTL is okay, it decrements it.

After the initial checks, the router either forwards it or replies to it, depending on the destination IP. The packets the router replies to are ICMP Echo Request and ARP Request.
If it received an ARP Reply, the router updates its ARP table and checks if it has any packets that weren't sent because the router didn't have a MAC address.

The ARP tables is coded as a fixed size vector. For my homework, it satisfied the contraints, as I had only one end device connected to each of its 4 interfaces, but it can be easily changed to a list. For the lookup in the ARP table, I wasn't interested in performance.
