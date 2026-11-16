---
"@agent-wechat/cli": patch
"@agent-wechat/rust-crates": patch
---

Make an automatic download limit of zero disable every automatic media transfer, including link previews and voice notes. Recheck the policy before admitting previously queued downloads.

Refuse authenticated native CDN transfers with `cdn_secure_transport_unavailable` before opening a connection. The available HTTP carrier sends the authentication key without transport encryption, and a verified secure replacement is not implemented. Native CDN media uploads and downloads, including manual requests, are unavailable; cached files and separate HTTPS media paths remain available.
