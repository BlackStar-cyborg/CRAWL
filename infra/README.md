# infra/

Everything needed to (re)build the real nodes from scratch: provisioning, configuration
management, hardening, time sync, log shipping. Empty until hosting is decided (design topic #1).

Target: a teammate who has never touched a node can rebuild it from this folder alone
(the "rebuild test").

Secrets (SSH keys, API tokens, token secrets) never go here; reference them from a password
manager or environment variables.
