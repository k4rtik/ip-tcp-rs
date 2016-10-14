# CS168 IP/TCP Projects

## Design
### Link Layer Abstraction
Link layer consists of a central data structure `DataLink` storing the local UDP socket and a list of local interfaces. Primary interface into this layer is `send_packet()` which is only used by the IP layer. There is a separate thread maintained to receive datagrams from the network and pass them onto the IP layer using a channel.

### RIP Thread Model
We maintain a RIP thread to both send periodic (5s) updates including the routing table to a node's local network. This thread also expires route entries if they have not been refreshed in 12s.

### Processing IP Packets

#### Sending a packet
We have implemented a `send` interface conforming to that described in RFC 791 pg. 32. If the packet comes from RIP, we deliver it to the specified local interface using the link layer's `get_interface_by_dst()`. Else, RIP is consulted to find the next hop to deliver the packet to.

#### Receiving a packet
This is done on a dedicated thread which calls `handle_packet` for each packet received.
1. Validate checksum
1. If `dst` is local, pass it to higher layers (RIP here, or print it)
1. If not local, we forward it after decrementing TTL and reseting checksum.

## Known Bugs
- We observe with the ABC network that, if our implementation acts as node B, and the reference implementation acts as nodes A and C, we recieve some infinite routes from one of the reference nodes. This results in inconsistency in routing at times.
- Expiry timeout is not tested.

## Reference
### IP
- [Handout](http://cs.brown.edu/courses/csci1680/f16/content/projects/ip.pdf)
- [RFC 791 -- INTERNET PROTOCOL](https://tools.ietf.org/html/rfc791)
- (Optional) [RFC 792 -- INTERNET CONTROL MESSAGE PROTOCOL](https://tools.ietf.org/html/rfc792)
- [RFC 2453 -- RIP Version 2](https://tools.ietf.org/html/rfc2453)

## Authors
- Kartik Singhal (ksinghal)
- Sumukha Tumkur Vani (stumkurv)
