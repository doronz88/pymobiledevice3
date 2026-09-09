# Profiling fixtures

Real WebKit inspector payloads captured from an iOS 26.4 device through
`pymobiledevice3 webinspector cdp --trace`, used by `test_cdp_profiling.py` to check the
conversions the bridge performs for Chrome DevTools' Memory and Performance panels.

- `webkit_heap_snapshot_jscontext.json` - `Heap.snapshot` result (`snapshotData`, parsed) of a
  JSContext holding 500 `Widget` objects, a `Map`, a `FinalizationRegistry` and a few functions.
- `webkit_scriptprofiler_tracking_complete.json` - the `ScriptProfiler.trackingComplete` event
  of a `ScriptProfiler.startTracking {includeSamples: true}` recording around a recursive `fib`.
- `webkit_timeline_events_page.json` - the events of a `Timeline.start`/`stop` recording on a
  Safari page (timer, requestAnimationFrame, style recalculation, layout, paint, screenshots),
  trimmed to the interesting frames; screenshot image data is replaced by a 1x1 PNG.
