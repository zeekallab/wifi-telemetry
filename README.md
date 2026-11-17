# Wi-Fi telemetry

Standalone Zeek 9.0+ package for **raw radiotap/802.11 captures**. Observes all
network names and reports wireless activity independently of drone detection.
Written in Zeek; no Spicy compiler or additional analyzer plugin is required.

### v0.2.0 — 2026-11-17

Adds captured-frequency `band`, observed network `ssids` on device summaries,
and optional MAC OUI vendor hints. SSID is also logged on network/finding records.
Unknown frequency or vendor information remains absent.

## Optional IEEE vendor hints

Vendor enrichment is **disabled by default**. The administrator must supply the
original, full [IEEE MA-L CSV](https://standards-oui.ieee.org/oui/oui.csv) as a
local file and explicitly enable its Input Framework stream in policy:

```zeek
@load /path/to/wifi-telemetry/scripts
redef WiFiTelemetry::oui_csv = "/path/to/ieee-oui.csv";
```

No registry is bundled or downloaded by the package. Merely placing a CSV beside
the scripts does not enable it. Without a configured, valid file or a matching
assignment, `mac`/`bssid` remain available and the vendor-hint field is omitted
(JSON) or unset (TSV). Vendor fields contain organization hints, never a substitute
for the MAC or proof of device identity. Locally administered MACs receive no hint.

The Input Framework reads the original quoted CSV directly; no conversion or
Spicy component is required. It loads once per process, asynchronously. Early
records can omit hints until the complete file has been validated; later network
and device snapshots can include them. Findings reflect the lookup available at
emission and are not rewritten. A short offline replay can finish before loading.
See [loading behavior and limits](docs/TELEMETRY.md#optional-ieee-csv-input).
Corelight Asset Management and known-entity integration are deferred.

| Log | Contents |
|---|---|
| `wifi.log` | BSSID/network names, advertised privacy/RSN/WPA information, channel/frequency/signal when present, management/data counts, disconnect reasons and authentication/association status codes |
| `wifi_devices.log` | Observed unicast MACs, transmitted/received frame types and counts, BSSID references, probe network names, transmitter signal when available |
| `wifi_findings.log` | Deauthentication and disassociation bursts, supporting frame counts, claimed transmitter/receiver addresses, reasons and thresholds |

Network names and MAC addresses are observations that can be spoofed. A
Tello-looking name does not establish drone identity. EAPOL key-frame observations
are context; they do not establish password cracking, a complete handshake,
successful authentication, or takeover.

## Load and replay

Install with the Zeek package manager:

```sh
zkg install https://github.com/zeekallab/wifi-telemetry
```

Load installed packages with `@load packages`. For a local checkout, load the
package from local policy or your custom bundle entry script:

```zeek
@load /path/to/wifi-telemetry/scripts
```

Replay from a separate output directory:

```sh
zeek -r /path/to/wireless.pcap /path/to/wifi-telemetry/scripts LogAscii::use_json=T
```

The repository contains `zkg.meta` for packaging. For Corelight, add it to your
normal custom package/bundle workflow and validate on a test sensor before rollout.
No sensor installation or configuration change is performed by this project.

The input must include radiotap and 802.11 headers. A normal Ethernet mirror,
decapsulated IP feed, or bare 802.11 capture without radiotap does not supply the
supported input. Encrypted Wi-Fi payloads are not decrypted. See
[scope, log fields and limits](docs/TELEMETRY.md).

## Logging and findings

Networks and devices produce an initial `observation`, traffic-driven `update`
records at most once per minute, and a `final` record on inactivity/shutdown
only if further activity remains unreported. **Telemetry counts are cumulative
for the current tracked entity lifetime**, including the first record; do not
sum repeated snapshots. Inactivity expiry defaults to five minutes.

Each finding type triggers promptly at **20 distinct, unprotected, non-retry
disconnect frames in a 10-second bucket per BSSID**. Types are counted separately;
repeated findings of the same type are limited to once per minute per BSSID.
No beacon or particular SSID is required. Findings describe suspicious patterns,
not confirmed malicious intent or successful disruption.

```zeek
redef WiFiTelemetry::log_interval = 60secs;
redef WiFiTelemetry::minimum_disconnect_frames = 20;
redef WiFiTelemetry::burst_interval = 10secs;
redef WiFiTelemetry::finding_interval = 60secs;
```

## Migrate from the drone detector

Load this standalone package to obtain the Wi-Fi logs described here. The
[drone detector](https://github.com/zeekallab/drone-detector) is maintained
separately and has its own wireless inventory and Remote ID features. Publishing
this package does not change that repository's loading defaults or Wi-Fi output.
If using both packages, configure the drone detector's wireless behavior through
its documented options; loading this package does not disable its wireless logs.

**Migration from the original drone Wi-Fi module:** this standalone package
writes separate Wi-Fi logs. Update dashboards/searches to the new logs and names:

| Previous | Current |
|---|---|
| `DroneWiFi::minimum_deauth_frames` | `WiFiTelemetry::minimum_disconnect_frames` (applies separately to both disconnect types) |
| `DroneWiFi::burst_interval` | `WiFiTelemetry::burst_interval` |
| `DroneWiFi::max_networks`, `max_recent_frames` | Same names under `WiFiTelemetry::` |
| `DroneWiFi::watched_ssid` | Removed; all SSIDs and unknown SSIDs are eligible |
| `wireless_bssid`, `wireless_ssid` | `bssid`, `ssid` in Wi-Fi logs |
| `wireless_deauth_frames`, `wireless_eapol_key_frames` | Cumulative `deauth_frames`, `eapol_key_frames` in `wifi.log` |
| Wireless `manipulation_detection` | `finding` in `wifi_findings.log` |
| `wireless_peak_burst` | Threshold-time `frame_count` in `wifi_findings.log`; not a lifetime peak |
| `wireless_tracking_limited` | `tracking_limited` in Wi-Fi logs |

Load the main drone package separately when its validated protocol detection is
also wanted. Its flight telemetry and control findings remain independent.

## Verification

```sh
python3 tests/test_wifi.py
```

See [validation results](validation/RESULTS.md) for tested behavior and limits.
Generated [example network](examples/wifi.json), [device](examples/wifi_devices.json)
and [finding](examples/wifi_findings.json) records show the actual output schema.

Examples above use the default without vendor enrichment. The
[CSV-enabled network example](examples/wifi-with-vendor.json) uses an explicitly
configured synthetic organization for demonstration, not a real vendor claim.
