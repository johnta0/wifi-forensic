# wfx-helper (Wi-Fi helper for macOS)

Since macOS Sonoma, SSID / BSSID show as `<redacted>` without location permission.
This helper requests location permission as a `.app` with an Info.plist and outputs what it reads via CoreWLAN as JSON.

## Build

```sh
helper/build.sh          # -> helper/build/WfxHelper.app (ad-hoc signed)
```

## Run

```sh
helper/wfx-helper current            # info about the connected Wi-Fi
helper/wfx-helper scan --timeout 90  # scan nearby APs
```

- On first run, a location permission dialog appears. Choose "Allow".
- To change it later: System Settings > Privacy & Security > Location Services > `WfxHelper`
- Exit codes: 0 success / 2 not authorized / 3 Wi-Fi error / 64 usage / 1 no output
- `WFX_HELPER_APP` overrides the path to the `.app`.

## Why go through `open`

If you run `Contents/MacOS/WfxHelper` directly, the terminal becomes the responsible process and location permission does not apply correctly.
Through `open` (LaunchServices), the `.app` itself becomes the responsible process. Since `open` does not return the exit code, results are passed back via the JSON file given by `--out`.

## Signing caveat

With ad-hoc signing the identity changes on every build, so each rebuild invalidates the TCC permission.
Set a stable certificate name in `WFX_SIGN_IDENTITY` when building to avoid this.
