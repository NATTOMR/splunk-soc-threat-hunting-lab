# ⚙️ P2 Configuration Templates

> **Status:** ⚪ **REFERENCE / EXAMPLE ONLY**  
> These files are sanitized, example configurations for the Splunk Universal Forwarder and Splunk Enterprise Indexer. They do **not** represent currently deployed settings and contain **no** private credentials, tokens, or network secrets.

---

## Configuration Files:
- [`inputs.conf.example`](inputs.conf.example): Sample Windows Event Log monitoring stanzas for `WinEventLog:Security`, `System`, `Application`, and `PowerShell/Operational`.
- [`outputs.conf.example`](outputs.conf.example): Sample Universal Forwarder destination stanza routing encrypted telemetry to the central Splunk Enterprise indexer on port `9997`.
- [`props.conf.example`](props.conf.example): Sample sourcetype parsing and timestamp formatting rules.
