# 0006 — gRPC inside, REST and webhooks outside

**Decision.** Components talk gRPC with mutual TLS. Integrations use a versioned REST/JSON API (documented with OpenAPI) and
signed webhooks.

**Why.** gRPC gives typed, streaming, efficient internal calls; REST and webhooks are what every other tool can already use.

**Cost.** Two API surfaces to keep in step; the REST surface is generated from the same schema.
