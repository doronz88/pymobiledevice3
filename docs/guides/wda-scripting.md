# WDA Scripting

`pymobiledevice3 developer wda run-script` runs a small line-based script on top
of the existing WebDriverAgent commands.

## Usage

```bash
python3 -m pymobiledevice3 developer wda run-script steps.wda
```

## Script Format

- One command per line.
- Blank lines and lines starting with `#` are ignored.
- Quote arguments with spaces.
- Commands fail fast with the script line number in the error message.

Supported commands:

- `launch <bundle_id>`
- `tap <selector> [--using <strategy>]`
- `press <button> [<button> ...]`
- `type <text>`
- `swipe <start_x> <start_y> <end_x> <end_y> [duration_seconds]`
- `wait <seconds>`
- `unlock`

The runner keeps one WDA session alive across the script. `launch` starts a new
session for the requested app. Other commands create a generic session lazily if
the script has not launched one yet.

## Example

```text
# Open Settings, then return Home
launch com.apple.Preferences
tap Settings
wait 0.5
press home
```

For selectors with spaces:

```text
launch com.apple.Preferences
tap "General" --using name
tap "VPN & Device Management" --using label
```
