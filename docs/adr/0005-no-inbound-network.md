# 0005 — No inbound network

**Decision.** A box has no public inbound ports, including SSH. Every way in — terminal, web IDE, desktop, file transfer — is an
identity-checked tunnel the box dials out to. Infrastructure modules have tests that fail on any inbound rule.

**Why.** An open port is the most common way a cloud machine is taken over. Outbound-only tunnels put identity and multi-factor
checks in front of everything.

**Cost.** Connecting needs the tunnel client or a browser; there is no 'just SSH to the IP' fallback.
