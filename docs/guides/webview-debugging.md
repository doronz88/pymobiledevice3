# Debugging Safari and WebViews with Chrome DevTools or VS Code

`pymobiledevice3 webinspector cdp` bridges Apple's Web Inspector protocol to the
Chrome DevTools Protocol (CDP), so Chrome-compatible debugger clients can attach to
Safari tabs and WebViews running on a connected device. One bridge instance serves
both Chrome DevTools (per-page) and browser-level clients such as VS Code's
JavaScript debugger.

## Device prerequisites

- Enable Web Inspector on the device:
  - iOS >= 18: Settings -> Apps -> Safari -> Advanced -> Web Inspector
  - iOS < 18: Settings -> Safari -> Advanced -> Web Inspector
- Safari tabs (and `SFSafariViewController` pages) are then inspectable as-is.
- Third-party app `WKWebView`s only appear if the app makes them inspectable: on
  iOS >= 16.4 the app must set `webView.isInspectable = true`, or be a
  development/debug-signed build. Production apps that don't opt in cannot be
  inspected.
- Bare `JSContext`s opt in the same way (`jsContext.isInspectable = true`); see
  [JavaScript contexts](#javascript-contexts).

## Start the bridge

```shell
pymobiledevice3 webinspector cdp
```

The bridge listens on `127.0.0.1:9222` (see `--host`/`--port`). Keep it running for
the duration of the debugging session.

## Chrome DevTools

Open <http://127.0.0.1:9222/> in Google Chrome and pick a page. Prefer this landing
page over `chrome://inspect` — see the command's `--help` for why.

The listing keeps itself current: a tab opened, closed or navigated on the device
appears there within a couple of seconds, with no reload. Leave it open in a
background tab and it stops polling until you come back to it.

## JavaScript contexts

A process that made a bare `JSContext` inspectable is listed alongside the web pages,
named after the process hosting it (`myapp (1234): JSContext`). Such a debuggable is
JavaScriptCore's own inspector: it implements the JavaScript half of the protocol -
`Runtime`, `Debugger`, `Console`, `Heap` - and nothing else. There is no document behind
it, so it has no URL and no DOM, page, or network domains.

The landing page therefore opens them with Chrome's JavaScript-only DevTools frontend -
the one Chrome uses for Node.js - which offers Console, Sources, and Memory. They are
advertised as `"type": "node"` in `/json`.

A `JSContext` only answers the inspector while the thread hosting it services its run
loop. One whose host is blocked elsewhere is still listed (its process registered it) but
never replies; the bridge gives up on it after a while rather than hanging.

## VS Code

VS Code's built-in JavaScript debugger (js-debug) attaches through the browser-level
endpoint advertised by `/json/version`. No extension is needed.

1. Open your web project's folder in VS Code.
2. Create `.vscode/launch.json`:

    ```json
    {
        "version": "0.2.0",
        "configurations": [
            {
                "name": "Attach to iPhone WebView",
                "type": "chrome",
                "request": "attach",
                "address": "127.0.0.1",
                "port": 9222,
                "urlFilter": "*",
                "webRoot": "${workspaceFolder}"
            }
        ]
    }
    ```

3. In the Run and Debug sidebar, select **Attach to iPhone WebView** and press F5.

A child debug session appears per matching page. Editor breakpoints, stepping, the
Debug Console (evaluates on the device), Loaded Scripts, and source maps all work.

Configuration notes:

- `urlFilter` selects which pages to attach to. `"*"` attaches to every inspectable
  page; narrow it (e.g. `"*myapp.example.com*"`) to pick a specific tab.
- `webRoot` maps source-mapped URLs to workspace files so breakpoints bind to your
  original sources — point it at the folder your dev server serves from.
- Source-map warnings for third-party pages you don't control are harmless; silence
  them with `"sourceMaps": false` if they get noisy.

## Caveats

- WebKit allows a single inspector session per page: Chrome DevTools and VS Code can
  debug different tabs concurrently, but not the same tab. A page already held by
  another debugger is skipped after a short wait — detach the other client first.
- The page listing is polled, so tabs opened on the device after the attach are
  discovered (and auto-attached) within a couple of seconds.
