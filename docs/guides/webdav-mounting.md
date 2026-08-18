---
search:
  boost: 2
---

# Mounting AFC in Finder (WebDAV)

Any AFC-backed service can be exposed as a local **WebDAV** volume, so macOS Finder (or any
WebDAV client) can browse and edit the device's filesystem read-write as if it were mounted.

A small async WebDAV server runs inside the `pymobiledevice3` process; every WebDAV request is
translated into `AfcService` calls. There is a `webdav` subcommand under each AFC-backed group:

```shell
# media AFC (/var/mobile/Media)
pymobiledevice3 afc webdav [PATH] [--mount]

# an app's container (pass --documents for Documents-only)
pymobiledevice3 apps webdav BUNDLE_ID [PATH] [--documents] [--mount]

# crash reports
pymobiledevice3 crash webdav [PATH] [--mount]
```

`PATH` defaults to the service root. Press `Ctrl-C` to unmount and stop the server.

## Mounting

With `--mount`, the volume is mounted and revealed using the host's native mechanism —
`mount_webdav` on macOS, `net use` on Windows, `gio mount` on Linux. If no such tool is
available, the server instead prints its `http://127.0.0.1:PORT` URL for you to open manually
(Finder's **Go → Connect to Server**, or your file manager's equivalent).

WebDAV is used rather than FTP because macOS Finder mounts FTP read-only; WebDAV mounts
read-write.

## Notes and limitations

- **Freshness / stale views.** A mounted WebDAV volume is a *client-cached network filesystem*.
  Changes you make through the mount are immediate, but changes made on the device out-of-band
  (an app writing to its container, say) may appear stale until the client revalidates. WebDAV has
  no live-reload mechanism, and macOS's WebDAV client caches directory listings and attributes at
  the kernel level regardless of server hints. To force a refresh, navigate out of the folder and
  back (or reopen the window).
- **Read-write** browse, read, create, edit, `mkdir`, rename/move, and delete all propagate to the
  device.
- **Finder metadata** (`.DS_Store`, AppleDouble `._*`) writes are swallowed — reported as success
  but never written to the device.
- **Permissions/ownership** cannot be changed over WebDAV (no `chmod`/`chown`); AFC exposes none.
- **Python 3.10+** is required for the WebDAV feature (the `asgiwebdav` dependency).
