# CS168 IP/TCP Projects

## Design
### TCP
- We use a channel based architecture to implement TCP state machine.
- One thread per TCB, runs its state machine.
- Separate threads are spawned for each timeout event.


### Status
- Connection teardown is not fully implemented.
- Retransmission works but doesn't stop.
- File transfer is currently limited to files under 64KiB
- RTO of 1ms is used for the time being.


### IP
#### Link Layer Abstraction
Link layer consists of a central data structure `DataLink` storing the local UDP socket and a list of local interfaces. Primary interface into this layer is `send_packet()` which is only used by the IP layer. There is a separate thread maintained to receive datagrams from the network and pass them onto the IP layer using a channel.

#### RIP Thread Model
We maintain a RIP thread to both send periodic (5s) updates including the routing table to a node's local network. This thread also expires route entries if they have not been refreshed in 12s.

#### Processing IP Packets

##### Sending a packet
We have implemented a `send` interface conforming to that described in RFC 791 pg. 32. If the packet comes from RIP, we deliver it to the specified local interface using the link layer's `get_interface_by_dst()`. Else, RIP is consulted to find the next hop to deliver the packet to.

##### Receiving a packet
This is done on a dedicated thread which calls `handle_packet` for each packet received.
1. Validate checksum
1. If `dst` is local, pass it to higher layers (RIP here, or print it)
1. If not local, we forward it after decrementing TTL and reseting checksum.

## Reference
### TCP
- [Handout](http://cs.brown.edu/courses/csci1680/f16/content/projects/tcp.pdf)
- [RFC 793 -- TRANSMISSION CONTROL PROTOCOL](https://tools.ietf.org/html/rfc793)
- [RFC 2525 -- Known TCP Implementation Problems](https://tools.ietf.org/html/rfc2525)
- More here

### IP
- [Handout](http://cs.brown.edu/courses/csci1680/f16/content/projects/ip.pdf)
- [RFC 791 -- INTERNET PROTOCOL](https://tools.ietf.org/html/rfc791)
- (Optional) [RFC 792 -- INTERNET CONTROL MESSAGE PROTOCOL](https://tools.ietf.org/html/rfc792)
- [RFC 2453 -- RIP Version 2](https://tools.ietf.org/html/rfc2453)


## Authors
- Kartik Singhal (ksinghal)
- Sumukha Tumkur Vani (stumkurv)
