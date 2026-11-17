# Telemetry, interpretation and limits

## Enrichment fields — v0.2.0

The working copy adds optional `band` on network, device and finding records,
derived only from the latest captured frequency: 2400–2499 MHz → `2.4 GHz`,
5000–5924 MHz → `5 GHz`, 5925–7124 MHz → `6 GHz`, and 57000–70999 MHz → `60 GHz`.
The label is not a regulatory authorization or a Wi-Fi generation. Recognized
band boundaries do not validate that an individual supplied frequency is a valid
channel center. Unknown/missing captured frequency does not produce a guessed
band from an advertised channel. Finding records also retain `frequency_mhz`.

Device `ssids` contains the bounded union of names observed on referenced BSSIDs
within available tracking state. Probe-request names remain in `probe_ssids` and
are not promoted to known network names. References do not prove association.
Later name observations may enrich a device's final snapshot without changing
its own packet `last_seen`. Name context can be absent when the BSSID state has
expired or an advertisement was not observed.

Network/finding fields `bssid_oui` and `bssid_oui_vendor_hint`, and device fields
`mac_oui` and `mac_oui_vendor_hint`, support globally administered unicast /24
prefixes only. Unknown vendors omit the hint; local MACs omit both fields. Local
bits are never cleared to invent a manufacturer match. Longer MA-M/MA-S
assignments are not resolved. Vendor hints have no role in drone classification.

## Optional IEEE CSV input

`WiFiTelemetry::oui_csv` defaults to an empty string: no CSV stream is created.
An administrator enables enrichment by loading this package and redefining that
option to the local path of the original full IEEE `oui.csv` (MA-L registry).
The expected header is `Registry,Assignment,Organization Name,Organization Address`;
column order may vary. Quoted commas, escaped quotes, multiline fields, UTF-8,
BOM and CRLF are supported. Organization addresses are parsed but not retained.
Only global unicast six-digit MA-L prefixes enter the lookup; other registry
types are skipped. Duplicate organization names are deduplicated; distinct names
for one prefix are sorted and joined with ` | ` rather than choosing one.

The stream is named `wifi-ieee-oui`, uses `Input::READER_RAW` and `Input::MANUAL`,
and reads once at startup. The raw reader supplies lines to the CSV parser;
comma-separated ASCII parsing alone would mishandle quoted IEEE records.
The entire mapping is staged and published only after successful end-of-data.
Missing, unreadable, malformed or oversized input leaves vendor enrichment
unavailable and reports a warning; Wi-Fi telemetry continues. File paths
containing pipe or NUL characters are rejected, preventing command-source input.

Loading is asynchronous and does not pause packet processing. Before completion,
vendor fields are absent. Network/device emissions refresh available vendor
context; findings are not backfilled. `WiFiTelemetry::oui_load_finished(success)`
announces readiness or failure. For deterministic offline replay, a separate
policy may call `suspend_processing()` in `zeek_init` and `continue_processing()`
on that event, as the CSV regression tests do. Only gate when `oui_csv` is set,
and handle both success and failure. That replay policy is not enabled by default.

The file must be readable by each worker that loads the package; mappings are
worker-local. Updating the file does not trigger a refresh. Restart/reload the
policy through the administrator's usual process to load a new snapshot. The
package neither fetches the registry nor accesses Corelight Asset Management or
known-entity databases. Those integrations are deferred.

CSV limits are redefinable: `oui_max_entries=65536` unique prefixes,
`oui_max_record_bytes=65536` bytes per logical record, and
`oui_max_input_bytes=16777216` input bytes, plus 16 organizations per prefix.
These bounds include headroom over the 40,512-row, 3,876,374-byte IEEE snapshot
validated during development. Runtime memory is larger than CSV size and has
not been benchmarked. The snapshot is excluded from the source packages.

## Input and parser

Version 0.2.0 supports packet input containing a radiotap header followed by an
802.11 frame. It uses Zeek's `raw_packet` event and does not replace Zeek's built-in
wireless/IP packet analyzers. The raw handler is opt-in by loading this package;
it adds per-packet processing cost. It does not require Spicy. An expanded
decoder could later use a packet analyzer while retaining these logs and policy.

Radiotap decoding covers the prefix through antenna signal: extended presence
words, TSFT alignment, flags, rate, channel/frequency, FHSS and signed dBm signal.
Only frequency and signal are logged. Later radio fields are skipped using the
declared header length. Headers over 4096 bytes or with more than eight presence
words are rejected. Frames marked bad-FCS are ignored; a declared FCS trailer is
removed. The script does not calculate or independently verify an FCS checksum.

Management and three-address data frames use their defined address layouts.
QoS/HT-control offsets and radiotap data padding are considered for EAPOL
inspection. Protected and fragmented payloads are counted as observed frames,
but their bodies are not decoded or used for burst findings. A-MSDU aggregates,
four-address WDS/mesh data, encrypted payload decoding, and bare 802.11 input
without radiotap are outside coverage. Known control frame layouts supply device
references only; they do not create a guessed BSSID/network.

Before accepting a beacon/probe-response identity, the complete information
element list must fit in the captured frame. SSIDs over 32 bytes, duplicate SSID
elements and malformed/truncated elements are rejected. At most 256 IEs per
frame are inspected. Empty and all-zero SSIDs are tracked as hidden observations.
Network names may contain binary bytes; Zeek's log writer handles escaping.

## Log lifecycle and common fields

| Field | Meaning |
|---|---|
| `ts` | Record emission time |
| `event_type` | `observation`, `update`, or conditional `final` (telemetry logs) |
| `first_seen`, `last_seen` | First/latest packet time for this tracked lifetime; finding records instead describe the current burst bucket |
| `tracking_limited` | A bounded collection or capacity limit omitted information |

Telemetry counters accumulate from `first_seen` until inactivity expiry resets
the state. Sets are bounded historical observations during that lifetime.
The optional `ssid` is the latest non-hidden network name, while `ssids` retains
the bounded name history. A later hidden beacon does not erase an earlier name.
Signals/frequency are the latest observed measurements, not averages.

Updates occur on subsequent matching traffic once the interval has elapsed;
there is no periodic emission of unchanged records. Expiry and shutdown flush
only dirty state, so a one-packet entity gets one observation without a duplicate
final. A final timestamp is flush time, while `last_seen` remains the last packet
time. Expiry is driven by Zeek's timer processing and may lag the configured
inactivity interval. Long-running active entities retain their original
`first_seen`; expired entities start a new lifetime if seen again.

Use the latest snapshot per entity/lifetime for totals, or differences between
successive snapshots for interval changes. Do not sum cumulative snapshot counts.
Packet retries/duplicate capture observations remain in telemetry counts, while
findings use separately filtered/deduplicated evidence. Retries on EAPOL frames
also remain in the EAPOL observation count.

## Network log: `wifi.log`

| Fields | Meaning |
|---|---|
| `bssid_oui`, `bssid_oui_vendor_hint` | Global /24 prefix; optional administrator-supplied organization hint |
| `band` | Label derived from captured frequency when recognized |
| `bssid` | Observed unicast BSSID from management/data address layout |
| `ssid`, `ssids`, `hidden_ssid_observed` | Latest disclosed name, observed names and whether hidden advertisements were seen |
| `advertised_privacy` | Latest beacon/probe-response capability privacy bit, when observed |
| `rsn_observed`, `wpa_vendor_ie_observed` | Whether corresponding advertisement elements were seen; no negotiated cipher/security claim |
| `advertised_channels` | Observed DS-parameter advertised channel numbers |
| `frequency_mhz` | Latest captured frequency from radiotap, when supplied |
| `signal_dbm` | Latest signal of a frame claiming the BSSID as transmitter, when supplied |
| `frames`, `management_frames`, `data_frames` | Cumulative accepted observations attributed to the BSSID; control frames excluded |
| `beacon_frames`, `probe_response_frames`, `authentication_frames` | Cumulative frame-subtype observations |
| `association_request_frames`, `association_response_frames` | Include reassociation requests/responses respectively |
| `deauth_frames`, `disassoc_frames` | Raw accepted subtype counts, including retry/protected observations; distinct finding evidence is separate |
| `eapol_key_frames` | Complete unencrypted EAPOL key-frame observations with a supported version/descriptor and minimum length |
| `retry_frames`, `protected_frames` | Observed frame-control flags |
| `reason_codes` | Decoded reason numbers from unprotected, unfragmented disconnect frames |
| `status_codes` | Decoded authentication and association/reassociation response statuses |
| `management_subtypes` | Observed management types, such as beacon, authentication or deauthentication |

Wildcard/broadcast BSSIDs never become network records. A valid unicast BSSID can
be observed without any known SSID. Probe SSIDs are requests and do not establish
that the named network exists. Status code zero is only an observed protocol
status, not proof that the device completed a connection or was authorized.

DS channel advertisements and captured frequency are recorded independently;
they may disagree. RSN/WPA element presence does not establish WPA version,
negotiated cipher, PMF enforcement, encryption strength, or rogue-AP status.
Deauthentication/disassociation headers do not authenticate their claimed sender.

## Device log: `wifi_devices.log`

| Fields | Meaning |
|---|---|
| `mac_oui`, `mac_oui_vendor_hint` | Global /24 prefix; optional administrator-supplied organization hint |
| `ssids`, `band` | Referenced network names when known; captured-frequency band |
| `mac` | Observed unicast transmitter/receiver MAC; zero/group addresses excluded |
| `locally_administered` | MAC local-administration bit; may be randomized or manually configured |
| `observed_roles` | Roles inferred only from header positions: BSSID/peer transmitter/receiver or probe-request transmitter |
| `bssids` | Referenced BSSIDs, not a list of confirmed associations |
| `probe_ssids` | Bounded, non-hidden names requested in probe frames |
| `tx_frame_types`, `rx_frame_types` | Observed transmit/receive frame types; numeric fallback names for other subtypes |
| `tx_frames`, `rx_frames` | Cumulative observations using the link-layer transmitter/receiver addresses |
| `frequency_mhz` | Latest observed radio frequency for traffic referencing this MAC |
| `signal_dbm` | Latest signal when this MAC was the observed transmitter |

MACs are not stable physical device identities and may be spoofed or randomized.
Transmitter/receiver positions are not necessarily end-to-end source/destination
addresses. A received-frame observation does not prove actual reception. The
signal of a transmitting AP is never assigned to its client just because that
client appears in the receiver field. The optional OUI organization hint does not identify a physical device or
establish its manufacturer/model with certainty.

## Finding log: `wifi_findings.log`

The initial supported patterns are `deauthentication_burst` and
`disassociation_burst`. Each uses its own state and suppression clock per BSSID.
Twenty deauths cannot be synthesized by combining ten deauths with ten disassocs,
or by combining different networks.

| Field | Meaning |
|---|---|
| `bssid`, optional `ssid` | Observed network reference; no beacon prerequisite |
| `bssid_oui`, `bssid_oui_vendor_hint` | Global /24 prefix; organization hint if ready at emission |
| `frequency_mhz`, `band` | Captured frequency and recognized band when present |
| `finding` | Qualified disconnect pattern |
| `evidence` | `distinct-unprotected-non-retry-disconnect-frames` |
| `frame_count` | Distinct evidence count at the moment the record was emitted |
| `threshold`, `window` | Configured minimum and bucket duration |
| `observed_transmitters`, `observed_receivers` | Bounded sets of claimed addresses in qualifying evidence; receiver set can include broadcast |
| `reason_codes` | Observed disconnect reasons in the current burst bucket |

Only unprotected, non-retry, unfragmented disconnects with a unicast transmitter
and unicast BSSID qualify. The deduplication identity is subtype, the three
address fields and sequence/fragment control. Repeated copies count once per
bucket. Reason codes do not distinguish otherwise identical frame identities.
Each bucket begins at the first eligible frame, and resets after its configured
duration. This is a fixed bucket, not a rolling/sliding window: a burst straddling
a boundary can be missed. A new bucket does not reset the finding suppression
clock. Findings emit when current evidence qualifies; there is no unconditional
final finding or delayed replay of a rate-suppressed finding.

A finding indicates a burst of disconnect messages. It does not establish
malicious intent, sender attribution, successful disconnection, handshake
harvesting, password cracking, or drone activity. Routine handshakes never trigger
these findings. No key material or handshake payloads are logged.

## Capacity and configuration

All intervals and capacities must be positive. `max_recent_frames` must be at
least `minimum_disconnect_frames`, or startup fails with an explanation.

| Option | Default | Scope |
|---|---:|---|
| `log_interval` | 60 seconds | Each network/device |
| `state_timeout` | 5 minutes | Inactivity expiry per network/device |
| `burst_interval` | 10 seconds | Each disconnect type/BSSID |
| `minimum_disconnect_frames` | 20 | Each disconnect type/BSSID |
| `finding_interval` | 60 seconds | Each finding type/BSSID |
| `max_networks` | 1024 | Active BSSID states |
| `max_devices` | 4096 | Active MAC states |
| `max_values` | 64 | Each bounded name/address/reason/status/channel set |
| `max_recent_frames` | 1024 | Distinct fingerprints per disconnect type/BSSID/bucket |

Options are redefinable under `WiFiTelemetry::`. Reaching a bounded set limit
marks its entity `tracking_limited`. Reaching network/device capacity stops
admitting new entities until space becomes available, emits one reporter warning,
and marks subsequent telemetry/findings incomplete through a process-wide sticky
flag. No log can enumerate all omitted entities. Fingerprint capacity can hide
additional qualifying disconnects until the bucket resets. Bounded state is not
a guarantee of a suitable memory/CPU footprint for any particular feed.

State and counters are worker-local. Splitting a BSSID's packets across cluster
workers may undercount bursts. Cluster video identity sharing in the separate
drone package does not aggregate Wi-Fi state. There is no wireless-to-drone
identity correlation in this version.

## Source and validation

This package extracts and generalizes the author's optional drone-detector Wi-Fi
module; SSID matching and drone log dependencies were removed. Earlier wireless
research used the [University of Victoria ISOT dataset](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/),
credited to Z. Chen, I. Traoré, M. Mamun and S. Saad (FPS 2024).
No third-party PCAP binaries are included. Historical capture results belong to
the previous detector and do not validate this new parser or its broader scope.
See [current validation](../validation/RESULTS.md).
