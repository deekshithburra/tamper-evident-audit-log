# Attestation

**Full name:** Deekshith Burra
**Email address:** dixith.java07@gmail.com
**GitHub identity:** [@deekshithburra](https://github.com/deekshithburra)
**Assignment title:** Interview Assignment: Build an AI-Assisted Software Engineering System — Audit Log Service (Version 2.0)
**Date started:** 2026-08-30
**Date submitted:** 2026-09-01

---

I, Deekshith Burra, attest that this submission is my own individual work, completed on my
own machine and accounts, and that it honestly reflects my development process and use of AI.

---

## Notes on AI use

AI assistance (Claude, via Claude Code) was used throughout, as the assignment expects and
encourages. My full traceability log — what I prompted, what I accepted, what I modified,
what I rejected, and the reasoning behind each — is in
[`docs/AI_USAGE_LOG.md`](docs/AI_USAGE_LOG.md), and the development history in this
repository's commits reflects the order in which the work actually happened.

Every design decision in this system is one I made and can explain and defend: the hash
chain construction, the salted per-field Merkle commitments that make redaction possible
without breaking the chain, content-only archival, the write-path transaction semantics, the
role split, and the threat-model boundaries I chose to state rather than obscure. Where
generated code was functionally correct but weakened a security property, I rejected it; those
cases are recorded individually in the AI usage log.
