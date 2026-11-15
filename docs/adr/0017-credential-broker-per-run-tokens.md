# 0017 — Runs never hold a provider key: a credential broker and per-run tokens

**Decision.** An agent run is untrusted: anything the box user can read, an agent can read, and a process environment is
readable through `/proc`. So a run is never given a long-lived vendor key. It is given a **per-run token** and the address
of a **credential broker**; the broker holds the key.

1. **The token is worth one run.** It is bound to one run and one provider, capped at what the run may still spend, and
   stops working when the run ends (finished, paused at a limit, stopped, failed, or switched to a fallback model) or after
   six hours, whichever is first. It is kept only as an HMAC under a key that exists in the server's memory, so a stored
   token is not usable and a token from an earlier start is worthless.
2. **The broker is a loopback proxy.** The engine's SDK is pointed at it (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, ...). It
   checks the token, reads the provider's key from the secret store at the moment of the request, puts it in the one header
   that provider uses, and forwards through the same address checks as every other outbound request (ADR 0005). The key
   lives in a local variable for that request: never stored, logged, returned or put in an error, and an echo of it in a
   provider's answer is removed before the run sees it.
3. **Usage is counted where it is seen.** The broker sees every reply, so token counts (plain or streamed) come from the
   provider's own answer, with the model, and are recorded against the run. A cost the engine reports itself replaces the
   estimate and is marked as reported.
4. **Fail closed.** If a provider cannot be reached through the broker or a key is missing, the run waits in the queue with the reason. There is no fallback path that hands a run
   the raw key.
5. **Not decided here.** Running the broker as its own system user on a box, so even the box user cannot reach its memory,
   and relaying replies as a stream rather than whole, are the next steps.

**Update (ADR 0028).** Cloud-account providers are brokered now: Bedrock (a Signature Version 4 header computed per request),
Azure OpenAI (a key, or an Entra token) and Vertex (a service-account token), all inside the secrets service, so a run holds
only its `ozrt_` token for them too. Issuing, revoking and refusing a token are recorded in the audit chain.
