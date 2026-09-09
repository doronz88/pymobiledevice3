# Debugging Safari and WebViews with Chrome DevTools or VS Code

`pymobiledevice3 webinspector cdp` bridges Apple's Web Inspector protocol to the
Chrome DevTools Protocol (CDP), so Chrome-compatible debugger clients can attach to
Safari tabs and WebViews running on a connected device. One bridge instance serves
both Chrome DevTools (per-page) and browser-level clients such as VS Code's
JavaScript debugger and test automation frameworks like Playwright and Puppeteer.

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
page over `chrome://inspect` — see the command's `--help` for why. The page cannot
link to `chrome://inspect` (Chrome blocks such navigations from web pages, clicked
or not); if you want it anyway, type `chrome://inspect/#devices` into the address
bar. Chrome discovers a bridge on `localhost:9222` by itself; any other address goes
under **Configure...** next to *Discover network targets*. The page's header shows
the pymobiledevice3 version serving it.

Debuggables are grouped by the process that owns them, with its icon, name, bundle
identifier and pid as the device reports them; click a process header to fold its
group. A process that accepts Remote Automation sessions carries an **automation**
badge, and one that runs web content for another (a proxy) names the app it runs
in. A badge next to a debuggable says whether it is paused, or who is already
debugging it. Hovering a page highlights its view on the device screen, as Safari's
Develop menu does, and the filter box narrows the list to targets matching every
word typed, by title, URL, process name, bundle identifier or pid.

The listing keeps itself current: a tab opened, closed or navigated on the device
appears there within a couple of seconds, with no reload. Leave it open in a
background tab and it stops polling until you come back to it.

The device screen (toggle the device toolbar) takes the keyboard: characters type
into the focused field, held keys repeat, Cmd/Ctrl-A selects all, the arrow keys,
Home and End move the caret (Shift extends the selection, Alt moves by word,
Cmd by line), Backspace and Delete edit, Enter submits. The page's own `keydown` and
`keyup` listeners see every key, and one that calls `preventDefault()` keeps its
shortcut, as in a browser. Clipboard shortcuts (Cmd-C/V/X) are not relayed.

## JavaScript contexts

A process that made a bare `JSContext` inspectable is listed alongside the web pages,
named after the process hosting it (`myapp (1234): JSContext`). Such a debuggable is
JavaScriptCore's own inspector: it implements the JavaScript half of the protocol -
`Runtime`, `Debugger`, `Console`, `Heap` - and nothing else. There is no document behind
it, so it has no URL and no DOM, page, or network domains.

The landing page therefore opens them with Chrome's JavaScript-only DevTools frontend -
the one Chrome uses for Node.js - which offers Console, Sources, Memory and Performance
(see [Memory and Performance panels](#memory-and-performance-panels)). They are
advertised as `"type": "node"` in `/json`.

A `JSContext` only answers the inspector while the thread hosting it services its run
loop. One whose host is blocked elsewhere is still listed (its process registered it) but
never replies; the bridge gives up on it after a while rather than hanging.

Because the frontend is Node.js's, the bridge presents the Node.js inspector surface on top
of WebKit's: an uncaught exception, an unhandled rejection or a parse error is reported as
`Runtime.exceptionThrown` (WebKit reports these as console messages, which VS Code's debugger
does not render on their own); `Runtime.addBinding` exposes a page function whose calls arrive
as `Runtime.bindingCalled`; the console's `inspect()` becomes `Runtime.inspectRequested`; and
the `NodeRuntime`, `NodeWorker` and `NodeTracing` domains an editor enables on attach are
acknowledged (WebKit has none of them). A URL breakpoint set before its script exists binds and
reports `Debugger.breakpointResolved` once the script loads, as it would against Node.js.

## Memory and Performance panels

WebKit records the same three things Chrome's profiling panels read - a heap snapshot,
sampled call stacks and a log of main-thread work - in formats of its own, so the bridge
converts them on the way to the frontend.

**Memory panel.** *Take snapshot* and the *Collect garbage* button work on pages and
JSContexts alike: the snapshot is WebKit's `Heap.snapshot` reshaped into V8's, with
WebKit's class names as constructors, its property, index and variable edges as V8's
property, element and context edges, and engine internals grouped under *(system)* and
*(compiled code)* as V8's are. Object ids are WebKit's, so the console can still resolve
an object picked in the snapshot. *Allocations on timeline* records through WebKit's
`Heap.startTracking` and loads the closing snapshot; WebKit reports no live heap
statistics, so the overview strip stays flat. *Allocation sampling* has no WebKit
counterpart and is refused with a message the panel shows.

**CPU profiles.** The Sources panel's profiler and - on a JSContext - the Performance
panel record through WebKit's `ScriptProfiler`; its samples become a
Chrome call tree with 0-based locations, rooted at the outermost user frame (the frames of
WebKit's own console machinery are dropped). WebKit samples at its own fixed interval;
`Profiler.setSamplingInterval` is accepted and ignored.

**Performance panel on a page.** A recording drives WebKit's `Timeline` (plus a
`ScriptProfiler` recording for the flame chart) and delivers a Chrome trace when stopped:
each WebKit rendering frame is a main-thread task, with function calls, script
evaluations, timers, animation frames, style recalculation, layout, paint and composite
nested inside it under Chrome's names, `console.time` spans and paint-timing marks as
Chrome emits them, and screenshots when the panel's *Screenshots* box is ticked. There is
no network, GPU or compositor-thread track: WebKit records only the page's main thread.
A JSContext has no Timeline, so its Performance panel records a CPU profile only.

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
- `"targetSelection": "pick"` prompts you to choose which page to attach to instead of
  attaching to every match. The prompt appears only when two or more pages match the
  `urlFilter`; with a single match js-debug attaches to it directly, with no prompt.
  JSContexts never appear in this prompt — js-debug's picker lists only `page` targets
  (attach to a JSContext through the `node` configuration below).
- `webRoot` maps source-mapped URLs to workspace files so breakpoints bind to your
  original sources — point it at the folder your dev server serves from.
- Source-map warnings for third-party pages you don't control are harmless; silence
  them with `"sourceMaps": false` if they get noisy.

### JSContexts in VS Code

The landing page at `http://127.0.0.1:9222/` has an **Attach from VS Code** section
under every target with the configuration that attaches to exactly it; copy it into
`launch.json`. What those configurations look like, and why:

The `chrome` attach above only takes web pages; js-debug ignores the JSContexts the
bridge lists (they are advertised as `node` targets). Attach to a JSContext with a
`node` configuration pointed straight at its websocket:

```json
{
    "name": "Attach to JSContext",
    "type": "node",
    "request": "attach",
    "websocketAddress": "ws://127.0.0.1:9222/devtools/page/PID:1234:1"
}
```

The address is the `webSocketDebuggerUrl` of the target in
`http://127.0.0.1:9222/json/list` (the landing page links carry the same
`PID:<pid>:<page>` id). A plain `"port": 9222` does not work for this: js-debug then
takes the browser socket from `/json/version`, which is not a JavaScript target.

To browse rather than name one, open the landing page: every JSContext has an
**Attach from VS Code** block with exactly this config (its own `websocketAddress`),
ready to copy. js-debug's `chrome` target picker does not list JSContexts - it debugs
them through the Node path above.

A child session named "Remote Process" appears with the context's scripts; the Debug
Console evaluates in it. With **Pause new JSContexts on launch** on, a context created
while the bridge runs comes up stopped on its first statement, so a breakpoint set
before it runs is hit.

## WebStorm

WebStorm attaches through the same listing: **Run > Edit Configurations > Add >
Attach to Node.js/Chrome**, host `127.0.0.1`, port `9222`, attach to *Chrome or
Node.js > 6.3 started with --inspect*. Starting that configuration in Debug opens a
**Choose Page to Debug** list with every inspectable page and JSContext on the device;
pick one and the session attaches to it. Breakpoints and the debug console work on a
Safari page. WebStorm sends `Debugger.setSkipAllPauses` on attach, which WebKit does not
have; the bridge translates it into deactivating breakpoints and `debugger` statements.

WebStorm builds a Node-style target out of a `node` entry's `url`, so JSContexts are
listed under a `jscontext://<bundle id>/<pid>/<page>` URL (WebStorm rejects a `node`
entry with an empty URL as malformed).

## Test automation (Playwright, Puppeteer)

A Chrome-protocol automation framework attaches through the same browser-level
endpoint as VS Code, so the page runs on the real device while the test runs on your
machine. This lets a web test suite drive a `WKWebView` in a real app, rather than a
simulator or a desktop browser pretending to be one.

```javascript
const { chromium } = require('playwright');

const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
const page = browser.contexts()[0].pages()[0];

await page.goto('https://example.com/');
await page.locator('#search').fill('hello');
await page.locator('button[type=submit]').click();
await page.screenshot({ path: 'device.png' });
```

Puppeteer attaches the same way with
`puppeteer.connect({ browserURL: 'http://127.0.0.1:9222' })`.

What works: navigation and its waits (`goto`, `reload`, `waitForNavigation`,
`waitForLoadState`), reading and evaluating, every text-input API (`fill`,
`pressSequentially`, `type`, `press`, `keyboard.insertText`), clicking and hovering,
screenshots, network observation (`page.on('request')`, `page.on('response')`), and
child frames - including cross-origin ones nested several levels deep, through
`page.frames()`, `frameLocator()` and `frame.evaluate()`.

Attaching to a page that is *already open* works too: you do not have to be connected
before it loads.

### Request interception and HTTP Basic auth

Chrome's `Fetch` domain is available, translated onto WebKit's own request
interception. Arm it and every matching request pauses as `Fetch.requestPaused`,
which you answer with `Fetch.continueRequest` (optionally rewriting the URL, method,
headers or body), `Fetch.fulfillRequest` (a canned response) or `Fetch.failRequest`.
This is how Playwright's `route()` and Puppeteer's `setRequestInterception()` mock,
block or rewrite requests against a real device.

The practical use is **answering an HTTP Basic auth challenge without the on-device
credential dialog** — which otherwise needs a person to tap through it once per
Safari/WebView process, blocking any unattended run. Supply the credentials on the
request yourself:

```javascript
await page.route('**/*', (route) => {
  const headers = { ...route.request().headers(), authorization: 'Basic ' + btoa('user:pass') };
  route.continue({ headers });
});
await page.goto('https://example.com/behind-basic-auth');  // no dialog
```

One WebKit limitation to know: it surfaces no auth-challenge event of its own (the OS
dialog owns the challenge), so Playwright's reactive `httpCredentials` option — which
waits for a `401` and answers it — does not fire. Supplying the `Authorization` header
proactively on the request, as above, answers the challenge before it is ever raised.

Notes worth knowing when scripting against a device:

- The first interaction with a newly created frame takes a few seconds while the
  framework bootstraps its injected script inside that frame over USB. It is not a
  hang - give the first frame interaction a generous timeout.
- Everything is a USB round-trip, so per-call latency is far higher than against a
  local browser. Prefer a few coarse `evaluate()` calls over many fine-grained ones
  in a hot loop.
- A page whose framework replaces the global `Promise` and minifies the replacement
  (Angular with zone.js, for example) reports objects of that class without the
  `promise` subtype, because the bridge recognises built-ins by their class name.
  `await` still behaves; only code that inspects the subtype is affected.

## Attaching before a page or context runs

Safari's Develop menu can attach to every JSContext an app creates, before the
context runs its first line ("Automatically Show Web Inspector for JSContexts"), and
optionally stop it there ("Automatically Pause Connecting to JSContexts"). The bridge
offers the same through the Chrome protocol: a client that enables
`Target.setAutoAttach` with `waitForDebuggerOnStart` — VS Code, Playwright and
Puppeteer all do by default — is attached to each new debuggable before it runs.

What happens per kind of debuggable, because WebKit treats them differently:

- **JSContexts** (and service workers) are held by the app itself: it blocks the
  thread creating the context until the client has attached and released it with
  `Runtime.runIfWaitingForDebugger`, which the clients above send once their
  breakpoints are in place. So a breakpoint on the first line of a context's script
  hits. WebKit gives up on a debugger that does not release the context within ten
  seconds and lets the app continue.
- **WKWebView pages** cannot be held before they run: WebKit offers no hook for it.
  The bridge attaches the moment the device pushes the listing the page appears in
  (rather than waiting for the next periodic poll), and reports the attachment with
  `waitingForDebugger: false`. Once attached, a cross-site navigation of that page
  creates a new process, and the bridge does hold that one — WebKit's
  `Target.setPauseOnStart` — until the client's debugger state has been replayed
  into it, so breakpoints hit from the new document's first script on.

While such a client is connected, every app on the device holds each new JSContext
for it; the bridge switches this off again when the client detaches. Candidates
nobody can take — for example a page that never made it into the listing — are
declined immediately so no app waits.

### Recording a protocol trace

When something in an editor misbehaves - a step that does not land, an evaluate that never
answers - a trace of the protocol is the report that lets it be diagnosed rather than
guessed at:

```shell
pymobiledevice3 webinspector cdp --trace cdp-trace.jsonl
```

Attach the editor, reproduce the problem, stop the bridge, and attach the file. It records
every message in both directions, on both sides of the bridge (editor to bridge, and bridge
to device), one JSON line each with a timestamp. It contains page content, evaluation results
and script sources, so treat it as sensitive.

### Pause new JSContexts on launch

Safari's "Automatically Pause Connecting to JSContexts" has a bridge equivalent that
also works from the landing page, where DevTools cannot attach before a context
exists: `pymobiledevice3 webinspector cdp --pause-new-targets`, or the
**Pause new JSContexts on launch** switch at the top of `http://127.0.0.1:9222/`.
The flag only sets the switch's initial state; it can be turned on and off while the
bridge runs.

While it is on, the bridge itself accepts every JSContext an app creates, before the
context runs: it enables the debugger, lets the app continue, and WebKit stops the
context on its first statement. The context is listed with a **paused** badge; open
it and DevTools comes up in the Sources panel on that pause, with the scripts it
parsed so far. Resume from there as usual. A context nobody opens stays paused until
it is opened or the switch is turned off, which lets every held context go.

Clients that auto-attach (VS Code, Playwright) get the same held sessions, already
released, and see the pause once their debugger is enabled. Pages cannot be held
before they run; with the switch on, a page a client auto-attaches is paused on its
next statement after the client's debugger comes up, and a cross-site navigation of
an attached page pauses on the new document's first statement. Debuggables that
already existed when a client attached keep running, as in Safari.

## Caveats

- WebKit allows a single inspector session per page, so two *separate* debuggers
  cannot hold the same tab: Chrome DevTools and VS Code can debug different tabs
  concurrently, but not the same one. Opening a page from the landing page takes it
  over from whichever session of this bridge holds it (a DevTools tab left open
  elsewhere, for example), which is then disconnected. Browser-level clients (VS Code,
  Playwright) do not take pages over: a page held by another session is skipped after
  a short wait. A page held over a *different* Web Inspector connection (Safari's own
  Web Inspector, a second `pymobiledevice3`) cannot be taken; the bridge logs which
  connection holds it — detach that client first. The landing page shows who holds
  each debuggable: **attached here** for a session of this bridge (opening it takes it
  over), **held elsewhere** for another Web Inspector connection. A single client may open as many CDP
  sessions onto a page as it likes (Playwright does this when a script also opens a raw
  `newCDPSession`); those share the one underlying session.
- The page listing is polled as a fallback, so a tab the device did not announce on
  its own is still discovered (and auto-attached) within a couple of seconds.
- The manual pause button (`Debugger.pause`) cannot interrupt JavaScript that is already
  busy in a tight loop: WebKit handles inspector messages on the page's own JavaScript
  thread, so the pause lands when the script next yields. Armed while the page is idle it
  stops the next code that runs, as in Chrome.
