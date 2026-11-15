# ADR-0016: Network operations belong in the flyw8t console

Status: accepted (operator direction, 2026-11-14).

flyw8t owns network operations alongside endpoint management. NetViz is a discovery
provider; PortGlass is a device-interface access capability. AnchorDesk remains the
service/ticketing integration. Products retain independent engines and deployment.

Network assets are agentless, site-scoped records with stable UUIDs and collected/received
observations. Collector credentials are a separate identity plane bound to organization,
site and range at registration. They never inherit a user's API permissions. Existing
NetViz v1 push compatibility is retained. Access links identify an already-pinned PortGlass
probe and prefill a local review; they do not create trust or authorize a destination.

The first sprint delivers collector registration/revocation, inventory, bounded discovery
history, site navigation and access handoff. Health collection, alerting, physical topology,
configuration management and flow analysis extend this model in later sprints.

Visual integration follows the family contract in [product-family.md](../product-family.md).
Neither a frontend rewrite nor shared product databases are prerequisites for a coherent
operations workflow. Revisit asset identity when real fleets require manual merges or
stable identifiers beyond observed MAC/IP, retaining provenance and customer boundaries.

Implementation and setup: [network-operations.md](../network-operations.md).
