# v0.2.0 validation — 2026-11-17

Tested offline using Zeek 9.0.1 and generated packet captures. No live sensor
installation, network traffic injection or production performance testing.

## Standalone tests

`python3 tests/test_wifi.py`: **49 tests pass**, with additional packet variations
inside several tests. Coverage includes:

- Optional Input Framework ingestion of the full original 40,512-row IEEE CSV;
  absent hints without explicit opt-in even when a CSV is present. Quoted CSV,
  Unicode, multiline, BOM/header ordering, duplicate organizations, local MACs,
  invalid/missing files and capacity limits. Invalid input never publishes a
  partial mapping. Offline CSV tests gate packet processing until loading ends;
  production policy remains asynchronous.
- Frequency-derived bands and device network-name context; probe names remain
  separate from observed network names.
- Ordinary/Tello names without manufacturer or drone classification; unknown
  SSIDs; beacon/probe-response metadata; hidden and binary names; name changes.
- Network/device separation, wildcard probes, referenced BSSIDs, frame types,
  locally administered MACs, and exclusion of multicast/zero device identities.
- Frequency, advertised channel and signed signal extraction; extended radiotap
  presence-word alignment; transmitter signal is not attributed to the receiver.
- Authentication/association status and disconnect reasons; advertised privacy,
  RSN and WPA vendor-element presence.
- Deauthentication/disassociation bursts for any SSID or without a preceding
  beacon; per-BSSID/type thresholds and finding suppression; fixed time buckets.
- Negatives: under-threshold/slow traffic, retries, protected/fragmented bodies,
  duplicates, malformed headers/IEs, bad-FCS flags, and handshakes alone.
- EAPOL key parsing for plain/QoS/HT-control/padded frames, truncation and invalid
  descriptors; correct to/from-DS BSSID extraction and WDS exclusion.
- Cumulative telemetry, minute-limited updates, inactivity expiry, reappearance,
  conditional final flush, capacity flags/warnings and invalid configuration.
- Two independent copies loaded in either order produce one set of handlers.
- Ethernet input does not create Wi-Fi telemetry.

## Independence

This is a separate package and repository. Its scripts do not load the drone
detector, extend `drone.log`, or use SSID/OUI hints to establish drone identity.
Loading two independent copies in either order was tested, with and without
CSV enrichment, and produces one set of handlers and findings.

Earlier development also tested separation against a local drone-detector
snapshot. Those checks are historical context, not validation of the public
drone detector's newer wireless modules. This release changes only this package.

## Remaining limits

Real wireless captures, live Corelight deployment, throughput/memory behavior,
cross-worker capture distribution and broad wireless device compatibility remain
unvalidated. No Spicy compiler/plugin is required or tested. Fixed buckets,
capture loss, encrypted/unsupported bodies, duplicates, bounded state and worker
distribution constrain coverage and counts. See [parser and field documentation](../docs/TELEMETRY.md).

Third-party drone fixture credit: [kresoin](https://github.com/kresoin) and
[University of Victoria ISOT](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/).
No third-party capture binaries are redistributed.
