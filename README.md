(LLM-written README is at [README-LLM.md](./README-LLM.md), this is mine)

# What is this

This is an implementation of identity service for Dentrado federation. It runs a minimalistic `https://` that is used to confirm the identity of the user.

# Code surface & dependency chain

As minimal as it gets, by design. Auth service isn't designed to be pretty, it's designed to be safe as it gets.

# IS compromise security

Anything on the internet be compromised, and will be compromised. To reduce the damage, a set of decisions were made:
- Primary log-in method is WebAuthn, and the server tries to store as small amount of information about the user as possible.
- All that can be done in-RAM, is done in-RAM.
- It relies on encrypted/"vaulted" database (`redb` as an unfortunate dependency) records. NONE of the keys are plaintext, NONE of the true values are plaintext. An attacker who manages to get full access to the machine and the disk doesn't get automatically information about all the accounts and all the sessions, they'll need to know (or brute-force) exact stored keys before they can get to the information behind them.
