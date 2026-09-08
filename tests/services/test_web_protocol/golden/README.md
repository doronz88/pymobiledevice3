# Golden editor-flow fixtures

Each `*.jsonl` file is a recorded session between a real editor (WebStorm, VS Code) and the CDP
bridge, replayed through the current bridge by `golden_flow.replay_flat_session` so a test can
assert the editor-visible behavior a past bug broke. The device inputs are authentic; the tests
assert the current, correct output, so a regression fails without a device.

## Format

One JSON object per line, `{"dir": <direction>, "msg": <message>}`, a trimmed
`webinspector cdp --trace`:

- `editor->bridge` - a command the editor sent; replayed into the bridge in order.
- `bridge->device` - a request the bridge made; used to script the device's response by method.
- `device->bridge` - the device's reply or event; fed back in when the bridge re-issues the request.

The recorded `bridge->editor` side (the old output) is dropped: the test asserts the current
output, not the recording.

## Capturing a new one

1. `pymobiledevice3 webinspector cdp --trace /tmp/flow.jsonl`, drive the editor through the flow.
2. Drop the watchdog's `Debugger.setBreakpointsActive` requests and their `{}` replies (the replay
   auto-acknowledges them), and the `bridge->editor` lines. Keep the rest.
3. Use only public/synthetic page content - a trace carries page content and is otherwise sensitive.
4. Add a test that calls `replay_flat_session` and asserts the behavior the flow exercises.

`golden_flow` currently models the un-multiplexed JSContext path only.
