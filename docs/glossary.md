# Glossary

- **Adjacent peer**: a node directly reachable through the selected underlay profile.
- **Candidate responder**: a node eligible to answer a bounded discovery, such as a gateway or service endpoint.
- **Discovery**: a bounded control-plane operation that creates temporary reverse state and obtains one or more route candidates.
- **Discovery ID**: a random identifier used for duplicate suppression and lifecycle correlation within one discovery instance.
- **Endpoint identity**: a long-term identity key or address used by an application to name a destination.
- **Hop label**: an opaque, short-lived forwarding capability interpreted only by the relay that created it.
- **Initiator**: the endpoint that starts discovery.
- **Privacy profile**: a deployment-specific set of padding, batching, scheduling, and observation assumptions.
- **Relay**: a node that forwards protocol messages and stores bounded ephemeral route state.
- **Responder**: a node that accepts a discovery and starts the acknowledgement path.
- **Reverse state**: state installed during outward discovery that permits a response to travel toward the initiator.
- **Forward state**: state installed during acknowledgement that permits later traffic toward the responder.
