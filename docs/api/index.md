---
search:
  boost: 0.5
---

# API Reference

This reference is generated from the source docstrings. It focuses on the **public** classes you
use to connect to a device and drive services.

New to the library? Read the [Python API guide](../guides/python-api.md) first — it shows the
connect → service pattern with runnable examples. This section is the detailed lookup.

- **[Connecting to a device](connection.md)** — lockdown clients, RemoteServiceDiscovery, tunneld.
- **[Lockdown services](services.md)** — the `LockdownService` base class and the most-used services.
- **[System &amp; device](system.md)** — activation, notifications, power, recovery, companion.
- **[Apps, files &amp; profiles](apps-files.md)** — house arrest, configuration and provisioning profiles.
- **[Capture, logging &amp; automation](capture.md)** — screenshots, pcap, syslog, WebInspector, WDA.
- **[Backup, symbols &amp; location](backup-symbols.md)** — backup/restore, symbol fetching, GPS simulation.
- **[Developer / DVT](dvt.md)** — the DVT provider and instruments (iOS 17+, over a tunnel).

!!! tip "Docstring coverage is a work in progress"
    Some methods are not yet documented. The generated pages reflect the current source; missing
    prose means the docstring hasn't been written yet, not that the method is private.
