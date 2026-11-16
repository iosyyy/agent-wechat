---
"@agent-wechat/rust-crates": patch
---

Include per-account MMKV configuration in open-writer detection. Refuse official-profile takeover when potentially competing processes cannot be inspected, and recheck official profiles at daemon startup and before profile writes. Document the required stopped-app and automatic-restart controls.
