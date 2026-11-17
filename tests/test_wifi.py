#!/usr/bin/env python3
"""Offline packet replays: Wi-Fi metadata, finding evidence, and negative cases."""
import json
import csv
import io
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ZEEK = os.environ.get('ZEEK', 'zeek')
AP = bytes.fromhex('60601f58eccc')
STA = bytes.fromhex('5e9d58266748')
OTHER = bytes.fromhex('001122334455')
BROADCAST = b'\xff' * 6
RADIO = b'\0\0\x08\0\0\0\0\0'


def management(subtype, body=b'', seq=0, flags=0, src=AP, dst=BROADCAST, bssid=AP, radio=RADIO):
    return radio + bytes([subtype << 4, flags]) + b'\0\0' + dst + src + bssid + struct.pack('<H', seq << 4) + body


def beacon(ssid=b'ordinary-wifi', subtype=8, seq=0, extra=b'', radio=RADIO):
    return management(subtype, b'\0' * 10 + b'\x11\0' + bytes([0, len(ssid)]) + ssid + extra, seq=seq, radio=radio)


def disconnect(seq, subtype=12, flags=0, reason=7, **kw):
    return management(subtype, struct.pack('<H', reason), seq=seq, flags=flags, **kw)


def eapol(seq=0, qos=False, flags=2, descriptor=2, radio=RADIO, pad=False):
    header = bytes([0x88 if qos else 8, flags]) + b'\0\0' + STA + AP + AP + struct.pack('<H', seq << 4)
    if qos:
        header += b'\0\0'
        if flags & 128:
            header += b'\0' * 4
    if pad:
        header += b'\0' * (-len(header) % 4)
    return radio + header + bytes.fromhex('aaaa03000000888e') + b'\x02\x03\0\x5f' + bytes([descriptor]) + b'\0' * 94


def ipv4_checksum(header):
    total = sum(struct.unpack('!10H', header))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


def gre(frame, key=None, mhz=None, dbm=None, dst='10.254.200.1', proto=0x8200, checksum=False,
        sequence=False, vlans=0, frag_offset=0, more_fragments=False, version=0):
    """Ethernet [802.1Q] / IPv4 / GRE / raw 802.11, as the capture-side forwarder sends it."""
    if mhz is not None or dbm is not None:
        key = ((mhz or 0) << 16) | ((dbm or 0) & 0xffff)
    flags, options = version, b''
    if checksum:
        flags |= 0x8000
        options += b'\0\0\0\0'
    if key is not None:
        flags |= 0x2000
        options += struct.pack('!I', key)
    if sequence:
        flags |= 0x1000
        options += struct.pack('!I', 7)
    payload = struct.pack('!HH', flags, proto) + options + frame
    fragment = (0x2000 if more_fragments else 0) | frag_offset
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, fragment, 64, 47, 0,
                         bytes([192, 168, 249, 13]), bytes(int(x) for x in dst.split('.')))
    header = header[:10] + struct.pack('!H', ipv4_checksum(header)) + header[12:]
    tags = b''.join(struct.pack('!HH', 0x8100, 100 + i) for i in range(vlans))
    return bytes.fromhex('dca632d54f7f') + bytes.fromhex('e81cba6a4931') + tags + b'\x08\x00' + header + payload


def capture(frames, times=None, linktype=127):
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    for i, frame in enumerate(frames):
        t = times[i] if times is not None else i * .01
        data += struct.pack('<IIII', 1700000000 + int(t), round((t % 1) * 1e6), len(frame), len(frame)) + frame
    return data


def ieee_csv(rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(['Registry', 'Assignment', 'Organization Name', 'Organization Address'])
    writer.writerows(rows)
    return output.getvalue()


def run(frames, settings='', times=None, scripts=None, allow_warning=False, linktype=127,
        input_csv=None, enable_oui=True, wait_for_input=False):
    with tempfile.TemporaryDirectory(prefix='wifi-telemetry-') as folder:
        folder = Path(folder)
        (folder / 'input.pcap').write_bytes(capture(frames, times, linktype))
        if input_csv is not None:
            data = input_csv.read_bytes() if isinstance(input_csv, Path) else input_csv
            (folder / 'oui.csv').write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
            if enable_oui:
                settings += '\nredef WiFiTelemetry::oui_csv="oui.csv";\n'
                wait_for_input = True
        if wait_for_input:
            # Input is asynchronous. Gate only these offline tests, not live policy.
            settings += '''
event zeek_init() &priority=-100 { suspend_processing(); }
event WiFiTelemetry::oui_load_finished(success: bool) { continue_processing(); }
'''
        loads = []
        for i, path in enumerate(scripts or [ROOT / 'scripts']):
            name = f'package{i}' + ('' if Path(path).is_dir() else '.zeek')
            (folder / name).symlink_to(path, target_is_directory=Path(path).is_dir())
            loads.append(f'@load ./{name}\n')
        (folder / 'test.zeek').write_text(''.join(loads) + 'redef LogAscii::use_json=T;\n' + settings)
        result = subprocess.run([ZEEK, '-r', 'input.pcap', 'test.zeek'], cwd=folder, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        logs = {p.stem: [json.loads(line) for line in p.read_text().splitlines()] for p in folder.glob('*.log')}
        if wait_for_input and 'reporter' in logs:
            logs['reporter'] = [r for r in logs['reporter'] if not (
                r['level'] == 'Reporter::INFO' and r['message'] in ('processing suspended', 'processing continued'))]
        if not allow_warning:
            assert not logs.get('reporter'), logs.get('reporter')
        return logs


def final_network(logs):
    return logs['wifi'][-1]


class WiFiTests(unittest.TestCase):
    def test_ordinary_network(self):
        logs = run([beacon(), beacon(seq=1)])
        row = final_network(logs)
        self.assertEqual(row['ssid'], 'ordinary-wifi')
        self.assertEqual(row['beacon_frames'], 2)
        self.assertEqual(row['management_subtypes'], ['beacon'])
        self.assertEqual([r['event_type'] for r in logs['wifi']], ['observation', 'final'])
        self.assertEqual(logs['wifi_devices'][-1]['tx_frames'], 2)
        self.assertEqual(logs['wifi_devices'][-1]['tx_frame_types'], ['beacon'])
        self.assertFalse(logs.get('wifi_findings'))
        self.assertNotIn('drone', logs)

    def test_tello_name_alone_has_no_drone_identity(self):
        logs = run([beacon(b'TELLO-58ECCC')])
        self.assertEqual(final_network(logs)['ssid'], 'TELLO-58ECCC')
        self.assertNotIn('likely_manufacturer', final_network(logs))
        self.assertNotIn('drone', logs)
        self.assertFalse(logs.get('wifi_findings'))

    def test_bursts_all_ssids_and_no_beacon(self):
        for ssid in (b'ordinary-wifi', b'TELLO-58ECCC', None):
            with self.subTest(ssid=ssid):
                frames = ([beacon(ssid)] if ssid else []) + [disconnect(i) for i in range(25)]
                logs = run(frames)
                finding = logs['wifi_findings'][0]
                self.assertEqual(len(logs['wifi_findings']), 1)
                self.assertEqual(finding['finding'], 'deauthentication_burst')
                self.assertEqual(finding['frame_count'], 20)
                self.assertEqual(final_network(logs)['deauth_frames'], 25)
                self.assertEqual(finding['reason_codes'], [7])
                self.assertNotIn('drone', logs)
                self.assertNotIn('uid', finding)
                if ssid is None:
                    self.assertNotIn('ssid', finding)

    def test_disassociation(self):
        logs = run([disconnect(i, subtype=10, reason=8) for i in range(23)])
        self.assertEqual(logs['wifi_findings'][0]['finding'], 'disassociation_burst')
        self.assertEqual(final_network(logs)['disassoc_frames'], 23)
        self.assertEqual(final_network(logs)['reason_codes'], [8])

    def test_negative_burst_cases(self):
        cases = [
            [disconnect(i) for i in range(19)],
            [disconnect(i, flags=8) for i in range(40)],
            [disconnect(i, flags=64) for i in range(40)],
            [disconnect(i, flags=4) for i in range(40)],
            [disconnect(1)] * 40,
            [eapol(i) for i in range(40)],
            [disconnect(i, bssid=BROADCAST) for i in range(40)],
            [disconnect(i, src=BROADCAST) for i in range(40)],
        ]
        for frames in cases:
            with self.subTest(first=frames[0].hex(), length=len(frames)):
                self.assertFalse(run(frames).get('wifi_findings'))

    def test_slow_disconnects(self):
        self.assertFalse(run([disconnect(i) for i in range(40)], times=list(range(40))).get('wifi_findings'))

    def test_independent_disconnect_types(self):
        logs = run([disconnect(i) for i in range(10)] + [disconnect(i, subtype=10) for i in range(10)])
        self.assertFalse(logs.get('wifi_findings'))

    def test_per_bssid_threshold(self):
        logs = run([disconnect(i) for i in range(10)] + [disconnect(i, bssid=OTHER, src=OTHER) for i in range(10)])
        self.assertFalse(logs.get('wifi_findings'))

    def test_finding_rate_limit_and_telemetry_flush(self):
        frames = [beacon()] + [disconnect(i) for i in range(25)] + [eapol()] + [disconnect(i + 100) for i in range(25)]
        times = [0] + [1 + i * .01 for i in range(25)] + [30] + [62 + i * .01 for i in range(25)]
        logs = run(frames, times=times)
        findings = logs['wifi_findings']
        self.assertEqual(len(findings), 2)
        self.assertGreaterEqual(findings[1]['ts'] - findings[0]['ts'], 60)
        self.assertEqual(final_network(logs)['deauth_frames'], 50)
        self.assertEqual(final_network(logs)['eapol_key_frames'], 1)
        self.assertEqual([r['event_type'] for r in logs['wifi']], ['observation', 'update', 'final'])

    def test_new_finding_type_is_prompt(self):
        logs = run([disconnect(i) for i in range(20)] + [disconnect(i, subtype=10) for i in range(20)])
        self.assertEqual(len(logs['wifi_findings']), 2)

    def test_bad_fcs(self):
        bad_radio = bytes.fromhex('000009000200000040')
        logs = run([disconnect(i, radio=bad_radio) for i in range(40)])
        self.assertFalse(logs.get('wifi'))
        self.assertFalse(logs.get('wifi_findings'))

    def test_fcs_trailer_removed(self):
        radio = bytes.fromhex('000009000200000010')
        logs = run([beacon(radio=radio) + b'\xff' * 4])
        self.assertEqual(final_network(logs)['ssid'], 'ordinary-wifi')

    def test_radiotap_channel_signal(self):
        radio = bytes.fromhex('00000f002e00000000026c09a000d6')
        logs = run([beacon(radio=radio, extra=b'\x03\x01\x01')])
        row = final_network(logs)
        self.assertEqual(row['frequency_mhz'], 2412)
        self.assertEqual(row['signal_dbm'], -42)
        self.assertEqual(row['advertised_channels'], [1])
        self.assertEqual(logs['wifi_devices'][0]['signal_dbm'], -42)

    def test_receiver_has_no_transmitter_signal(self):
        radio = bytes.fromhex('0000090020000000d6')
        logs = run([management(11, b'\0' * 6, dst=STA, radio=radio)])
        receivers = [d for d in logs['wifi_devices'] if d['mac'] == '5e:9d:58:26:67:48']
        self.assertTrue(receivers)
        self.assertNotIn('signal_dbm', receivers[0])

    def test_extended_radiotap_bitmap_alignment(self):
        radio = struct.pack('<BBHII', 0, 0, 25, 0x80000021, 0) + b'\0' * 12 + b'\xd6'
        row = final_network(run([beacon(radio=radio)]))
        self.assertEqual(row['signal_dbm'], -42)

    def test_security_and_hidden_ssid(self):
        logs = run([beacon(b'', extra=b'\x30\x02\x01\0\xdd\x04\0\x50\xf2\x01'), beacon(b'revealed')])
        row = final_network(logs)
        self.assertTrue(row['hidden_ssid_observed'])
        self.assertTrue(row['rsn_observed'])
        self.assertTrue(row['wpa_vendor_ie_observed'])
        self.assertTrue(row['advertised_privacy'])
        self.assertEqual(row['ssid'], 'revealed')

    def test_all_zero_hidden_ssid(self):
        row = final_network(run([beacon(b'\0' * 5)]))
        self.assertTrue(row['hidden_ssid_observed'])
        self.assertNotIn('ssid', row)

    def test_ssid_changes_are_observations(self):
        row = final_network(run([beacon(b'one'), beacon(b'two'), beacon(b'')]))
        self.assertEqual(set(row['ssids']), {'one', 'two'})
        self.assertEqual(row['ssid'], 'two')

    def test_binary_ssid_preserved_in_json(self):
        row = final_network(run([beacon(b'lab\0\xff')]))
        self.assertTrue(row['ssid'].startswith('lab'))

    def test_probe_requests_devices_without_fake_network(self):
        logs = run([management(4, b'\0\x04home', src=STA, bssid=BROADCAST)])
        self.assertFalse(logs.get('wifi'))
        self.assertEqual(logs['wifi_devices'][0]['probe_ssids'], ['home'])
        self.assertEqual(logs['wifi_devices'][0]['bssids'], [])
        self.assertTrue(logs['wifi_devices'][0]['locally_administered'])
        self.assertEqual(logs['wifi_devices'][0]['tx_frame_types'], ['probe-request'])

    def test_wildcard_probe(self):
        logs = run([management(4, b'\0\0', src=STA, bssid=BROADCAST)])
        self.assertEqual(logs['wifi_devices'][0]['probe_ssids'], [])

    def test_probe_response_and_management_statuses(self):
        logs = run([beacon(subtype=5), management(11, struct.pack('<HHH', 0, 2, 13), dst=STA),
                    management(1, struct.pack('<HHH', 0, 17, 1), dst=STA),
                    management(0, b'\0' * 4, src=STA, dst=AP)])
        row = final_network(logs)
        self.assertEqual(row['probe_response_frames'], 1)
        self.assertEqual(row['authentication_frames'], 1)
        self.assertEqual(row['association_request_frames'], 1)
        self.assertEqual(row['association_response_frames'], 1)
        self.assertEqual(set(row['status_codes']), {13, 17})

    def test_eapol_plain_qos_padding_and_ht(self):
        padded = bytes.fromhex('000009000200000020')
        for frame in [eapol(), eapol(qos=True), eapol(qos=True, flags=130), eapol(qos=True, radio=padded, pad=True)]:
            with self.subTest(frame=frame.hex()):
                self.assertEqual(final_network(run([frame]))['eapol_key_frames'], 1)

    def test_eapol_truncated_protected_and_invalid_descriptor(self):
        for frame in [eapol()[:-1], eapol(flags=66), eapol(descriptor=0)]:
            self.assertEqual(final_network(run([frame]))['eapol_key_frames'], 0)

    def test_malformed_ies_never_set_identity(self):
        for frame in [beacon(extra=b'\x03\x02\x01'), beacon(extra=b'\0\x01x'), beacon(b'x' * 33)]:
            self.assertFalse(run([frame]).get('wifi'))

    def test_short_headers_and_malformed_radiotap(self):
        for frame in [RADIO + b'\xc0\0', b'\0' * 7, b'\0\0\xff\xff' + b'\0' * 20,
                      struct.pack('<BBHI', 0, 0, 8, 0x80000000) + b'\0' * 24,
                      management(12), management(11, b'\0')]:
            self.assertFalse(run([frame]).get('wifi_findings'))

    def test_control_frames(self):
        rts = RADIO + b'\xb4\0\0\0' + STA + AP
        ack = RADIO + b'\xd4\0\0\0' + AP
        logs = run([rts, ack])
        self.assertFalse(logs.get('wifi'))
        self.assertEqual({d['mac'] for d in logs['wifi_devices']}, {'60:60:1f:58:ec:cc', '5e:9d:58:26:67:48'})

    def test_capacity_bounds_flag_incomplete_telemetry(self):
        logs = run([beacon(b'a'), beacon(b'b')], 'redef WiFiTelemetry::max_values=1;\n')
        self.assertTrue(final_network(logs)['tracking_limited'])
        self.assertEqual(final_network(logs)['ssids'], ['a'])
        logs = run([beacon(), management(11, b'\0' * 6, dst=STA)],
                   'redef WiFiTelemetry::max_devices=1;\n', allow_warning=True)
        self.assertEqual(len({d['mac'] for d in logs['wifi_devices']}), 1)
        self.assertTrue(final_network(logs)['tracking_limited'])
        self.assertEqual(len(logs['reporter']), 1)

    def test_fingerprint_capacity(self):
        logs = run([disconnect(i) for i in range(30)], 'redef WiFiTelemetry::max_recent_frames=20;\n')
        self.assertTrue(final_network(logs)['tracking_limited'])
        self.assertEqual(len(logs['wifi_findings']), 1)

    def test_inactivity_flush_and_reappearance(self):
        logs = run([beacon(b'a'), beacon(b'b'), beacon(b'c')], times=[0, 1, 500])
        rows = logs['wifi']
        self.assertEqual([r['event_type'] for r in rows], ['observation', 'final', 'observation'])
        self.assertEqual(rows[1]['beacon_frames'], 2)
        self.assertEqual(rows[2]['beacon_frames'], 1)

    def test_no_duplicate_final_without_new_activity(self):
        self.assertEqual(len(run([beacon()])['wifi']), 1)

    def test_ethernet_does_not_become_wifi(self):
        frame = BROADCAST + AP + b'\x08\x06' + b'\0' * 46
        logs = run([frame], linktype=1)
        self.assertFalse(logs.get('wifi'))
        self.assertFalse(logs.get('wifi_devices'))

    def test_independent_copy_guard(self):
        with tempfile.TemporaryDirectory(prefix='wifi-copy-') as folder:
            copy = Path(folder) / 'copy.zeek'
            copy.write_text((ROOT / 'scripts/main.zeek').read_text().replace(
                '@load ./oui\n', (ROOT / 'scripts/oui.zeek').read_text() + '\n'))
            for scripts in ([ROOT / 'scripts', copy], [copy, ROOT / 'scripts']):
                for data in (None, ieee_csv([['MA-L', '60601F', 'Example organization', '']])):
                    logs = run([beacon()] + [disconnect(i) for i in range(25)],
                               scripts=scripts, input_csv=data)
                    self.assertEqual(final_network(logs)['deauth_frames'], 25)
                    self.assertEqual(len(logs['wifi_findings']), 1)
                    if data is not None:
                        self.assertEqual(logs['wifi_findings'][0]['bssid_oui_vendor_hint'],
                                         'Example organization')

    def test_invalid_configuration_fails_clearly(self):
        for settings in ('redef WiFiTelemetry::log_interval=0secs;\n',
                         'redef WiFiTelemetry::max_recent_frames=19;\n'):
            with self.assertRaisesRegex(AssertionError, 'positive intervals/capacities required'):
                run([beacon()], settings)

    def test_data_bssid_mapping_and_wds_exclusion(self):
        original = eapol()
        tods = original[:9] + b'\x01' + original[10:12] + AP + STA + OTHER + original[30:]
        for packet in (original, tods):
            row = final_network(run([packet]))
            self.assertEqual(row['bssid'], '60:60:1f:58:ec:cc')
            self.assertEqual(row['eapol_key_frames'], 1)
        self.assertFalse(run([eapol(flags=3)]).get('wifi'))

    def test_band_from_capture_frequency(self):
        for frequency, band in [(2412, '2.4 GHz'), (2484, '2.4 GHz'), (5180, '5 GHz'),
                                (5825, '5 GHz'), (5935, '6 GHz'), (5955, '6 GHz'),
                                (7115, '6 GHz'), (58320, '60 GHz')]:
            with self.subTest(frequency=frequency):
                radio = struct.pack('<BBHIHH', 0, 0, 12, 8, frequency, 0)
                logs = run([beacon(radio=radio)] + [disconnect(i, radio=radio) for i in range(20)])
                self.assertEqual(final_network(logs)['band'], band)
                self.assertEqual(logs['wifi_devices'][-1]['band'], band)
                self.assertEqual(logs['wifi_findings'][0]['band'], band)
                self.assertEqual(logs['wifi_findings'][0]['frequency_mhz'], frequency)

    def test_band_missing_or_unrecognized_is_not_guessed(self):
        logs = run([beacon(extra=b'\x03\x01\x01')])
        self.assertNotIn('band', final_network(logs))
        self.assertNotIn('band', logs['wifi_devices'][0])
        known = struct.pack('<BBHIHH', 0, 0, 12, 8, 2412, 0)
        unknown = struct.pack('<BBHIHH', 0, 0, 12, 8, 900, 0)
        logs = run([beacon(radio=known), beacon(radio=unknown)])
        self.assertNotIn('band', final_network(logs))
        self.assertNotIn('band', logs['wifi_devices'][-1])

    def test_oui_hints_use_configured_data_only(self):
        data = ieee_csv([['MA-L', '60601F', 'Example organization', 'Test address']])
        logs = run([beacon()] + [disconnect(i) for i in range(20)], input_csv=data)
        self.assertEqual(final_network(logs)['bssid_oui'], '60:60:1f')
        self.assertEqual(final_network(logs)['bssid_oui_vendor_hint'], 'Example organization')
        self.assertEqual(logs['wifi_devices'][-1]['mac_oui_vendor_hint'], 'Example organization')
        self.assertEqual(logs['wifi_findings'][0]['bssid_oui_vendor_hint'], 'Example organization')
        self.assertNotIn('drone', logs)
        unknown = run([beacon()])
        self.assertNotIn('bssid_oui_vendor_hint', final_network(unknown))
        self.assertNotIn('mac_oui_vendor_hint', unknown['wifi_devices'][0])

    def test_local_mac_oui_is_never_normalized_to_a_vendor(self):
        local = bytes.fromhex('02000c010203')
        packet = management(8, b'\0' * 12 + b'\0\x03lab', src=local, bssid=local)
        data = ieee_csv([['MA-L', '00000C', 'Example Cisco hint', ''], ['MA-L', '02000C', 'Must not use', '']])
        logs = run([packet], input_csv=data)
        self.assertNotIn('bssid_oui', final_network(logs))
        self.assertNotIn('bssid_oui_vendor_hint', final_network(logs))
        device = logs['wifi_devices'][0]
        self.assertTrue(device['locally_administered'])
        self.assertNotIn('mac_oui', device)
        self.assertNotIn('mac_oui_vendor_hint', device)

    def test_device_ssid_context_and_probe_separation(self):
        logs = run([beacon(b'Lab-WiFi'), eapol()])
        self.assertEqual(logs['wifi_devices'][0]['ssids'], ['Lab-WiFi'])
        receivers = [r for r in logs['wifi_devices'] if r['mac'] == '5e:9d:58:26:67:48']
        self.assertEqual(receivers[-1]['ssids'], ['Lab-WiFi'])
        unknown = run([eapol()])
        self.assertTrue(all('ssids' not in d for d in unknown['wifi_devices']))
        probe = run([management(4, b'\0\x03lab', src=STA, bssid=BROADCAST)])
        self.assertEqual(probe['wifi_devices'][0]['probe_ssids'], ['lab'])
        self.assertNotIn('ssids', probe['wifi_devices'][0])

    def test_later_ssid_context_can_enrich_a_device_final(self):
        logs = run([eapol(), beacon(b'learned-later')])
        receiver = [r for r in logs['wifi_devices'] if r['mac'] == '5e:9d:58:26:67:48']
        self.assertNotIn('ssids', receiver[0])
        self.assertEqual(receiver[-1]['ssids'], ['learned-later'])
        self.assertEqual(receiver[-1]['event_type'], 'final')

    def test_csv_present_without_manual_opt_in_is_not_loaded(self):
        data = ieee_csv([['MA-L', '60601F', 'Do not load automatically', '']])
        logs = run([beacon()], input_csv=data, enable_oui=False)
        self.assertNotIn('bssid_oui_vendor_hint', final_network(logs))
        self.assertNotIn('mac_oui_vendor_hint', logs['wifi_devices'][0])

    def test_csv_quotes_commas_unicode_multiline_and_literal_backslashes(self):
        names = ['Example, Inc.', 'A "quoted" organization', 'München / 東京',
                 'Two\nlines', r'Literal\x41', '-', '(empty)']
        for name in names:
            with self.subTest(name=name):
                data = ieee_csv([['MA-L', '60601F', name, 'Address, with "quotes"\nand newline']])
                logs = run([beacon()], input_csv=data)
                self.assertEqual(final_network(logs)['bssid_oui_vendor_hint'], name)

    def test_csv_bom_header_order_case_and_duplicate_organizations(self):
        data = '\ufeffOrganization Name,Registry,Organization Address,Assignment\r\nZulu,MA-L,,60601f\r\nAlpha,MA-L,,60601F\r\nZulu,MA-L,,60601F\r\n'
        logs = run([beacon()], input_csv=data)
        self.assertEqual(final_network(logs)['bssid_oui_vendor_hint'], 'Alpha | Zulu')

    def test_csv_other_assignment_types_are_not_oui_guesses(self):
        data = ieee_csv([['MA-M', '60601F0', 'Not a /24 assignment', '']])
        logs = run([beacon()], input_csv=data)
        self.assertNotIn('bssid_oui_vendor_hint', final_network(logs))

    def test_csv_invalid_file_never_publishes_a_partial_mapping(self):
        valid = ieee_csv([['MA-L', '60601F', 'Must remain unpublished', '']])
        cases = [valid + 'MA-L,001122,"unterminated\n',
                 valid + 'MA-L,invalid,Broken,\r\n',
                 valid + 'MA-L,001122,Unescaped "quote",\r\n',
                 valid + 'MA-L,001122,Too few fields\r\n',
                 'Assignment,Organization Name\n60601F,Wrong header\n', '']
        for data in cases:
            with self.subTest(data=data[-40:]):
                logs = run([beacon()], input_csv=data, allow_warning=True)
                self.assertNotIn('bssid_oui_vendor_hint', final_network(logs))
                self.assertTrue(logs.get('reporter'))

    def test_csv_capacity_limits_disable_enrichment_without_stopping_wifi(self):
        data = ieee_csv([['MA-L', '60601F', 'First', ''], ['MA-L', '001122', 'Second', '']])
        for settings in ['redef WiFiTelemetry::oui_max_entries=1;\n',
                         'redef WiFiTelemetry::oui_max_record_bytes=20;\n',
                         'redef WiFiTelemetry::oui_max_input_bytes=20;\n']:
            logs = run([beacon()], settings, input_csv=data, allow_warning=True)
            self.assertEqual(final_network(logs)['ssid'], 'ordinary-wifi')
            self.assertNotIn('bssid_oui_vendor_hint', final_network(logs))
            self.assertTrue(logs.get('reporter'))

    def test_csv_file_errors_and_command_sources_do_not_enable_hints(self):
        for path in ['missing-oui.csv', 'never-execute|']:
            logs = run([beacon()], f'redef WiFiTelemetry::oui_csv="{path}";\n',
                       wait_for_input=True, allow_warning=True)
            self.assertNotIn('bssid_oui_vendor_hint', final_network(logs))
            self.assertTrue(logs.get('reporter'))

    def test_gre_input_with_key(self):
        frames = [gre(beacon(b'Forwarded-WiFi', radio=b''), mhz=2437, dbm=-77)]
        frames += [gre(disconnect(i, radio=b''), mhz=2437, dbm=-77) for i in range(25)]
        logs = run(frames, linktype=1)
        row = final_network(logs)
        self.assertEqual(row['ssid'], 'Forwarded-WiFi')
        self.assertEqual(row['frequency_mhz'], 2437)
        self.assertEqual(row['band'], '2.4 GHz')
        self.assertEqual(row['signal_dbm'], -77)
        self.assertEqual(row['deauth_frames'], 25)
        finding = logs['wifi_findings'][0]
        self.assertEqual(finding['finding'], 'deauthentication_burst')
        self.assertEqual(finding['frequency_mhz'], 2437)
        self.assertEqual(logs['wifi_devices'][0]['signal_dbm'], -77)

    def test_gre_matches_radiotap_results(self):
        radio = struct.pack('<BBHIHHb', 0, 0, 13, 0x28, 5745, 0, -60)
        frames = [beacon(b'same'), eapol()] + [disconnect(i) for i in range(21)]
        native = run([radio + f[len(RADIO):] for f in frames])
        forwarded = run([gre(f[len(RADIO):], mhz=5745, dbm=-60) for f in frames], linktype=1)
        drop = {'ts', 'first_seen', 'last_seen'}

        def normalized(rows):
            # Zeek set iteration order isn't defined, so compare sets as sorted lists.
            return sorted((json.dumps({k: sorted(v, key=str) if isinstance(v, list) else v
                                       for k, v in r.items() if k not in drop}, sort_keys=True)
                           for r in rows))
        for log in ('wifi', 'wifi_devices', 'wifi_findings'):
            with self.subTest(log=log):
                self.assertTrue(native[log])
                self.assertEqual(normalized(native[log]), normalized(forwarded[log]))

    def test_gre_without_key_has_no_radio_metadata(self):
        row = final_network(run([gre(beacon(radio=b''))], linktype=1))
        self.assertEqual(row['ssid'], 'ordinary-wifi')
        for field in ('frequency_mhz', 'band', 'signal_dbm'):
            self.assertNotIn(field, row)

    def test_gre_key_zero_halves_are_unknown(self):
        row = final_network(run([gre(beacon(radio=b''), mhz=0, dbm=-50)], linktype=1))
        self.assertNotIn('frequency_mhz', row)
        self.assertEqual(row['signal_dbm'], -50)
        row = final_network(run([gre(beacon(radio=b''), mhz=5180, dbm=0)], linktype=1))
        self.assertEqual(row['band'], '5 GHz')
        self.assertNotIn('signal_dbm', row)

    def test_gre_optional_fields_and_vlans(self):
        for kw in ({'checksum': True}, {'sequence': True}, {'checksum': True, 'sequence': True},
                   {'vlans': 1}, {'vlans': 2}, {'more_fragments': True}):
            with self.subTest(**kw):
                row = final_network(run([gre(beacon(radio=b''), mhz=2412, dbm=-40, **kw)], linktype=1))
                self.assertEqual(row['ssid'], 'ordinary-wifi')
                self.assertEqual(row['frequency_mhz'], 2412)
                self.assertEqual(row['signal_dbm'], -40)

    def test_gre_ignored_inputs(self):
        cases = {
            'other decoy': gre(beacon(radio=b''), dst='10.254.200.2'),
            'other GRE protocol': gre(beacon(radio=b''), proto=0x6558),
            'later fragment': gre(beacon(radio=b''), frag_offset=185),
            'GRE version 1': gre(beacon(radio=b''), version=1),
            'truncated': gre(b'\x80'),
        }
        for name, packet in cases.items():
            with self.subTest(case=name):
                logs = run([packet], linktype=1)
                self.assertFalse(logs.get('wifi'))
                self.assertFalse(logs.get('wifi_devices'))

    def test_gre_input_can_be_disabled_or_redirected(self):
        packet = gre(beacon(radio=b''), dst='10.1.2.3')
        self.assertFalse(run([packet], linktype=1).get('wifi'))
        logs = run([packet], 'redef WiFiTelemetry::gre_decoys += { 10.1.2.3 };\n', linktype=1)
        self.assertEqual(final_network(logs)['ssid'], 'ordinary-wifi')
        logs = run([gre(beacon(radio=b''))], 'redef WiFiTelemetry::gre_input = F;\n', linktype=1)
        self.assertFalse(logs.get('wifi'))

    def test_gre_and_ordinary_lan_traffic(self):
        arp = BROADCAST + AP + b'\x08\x06' + b'\0' * 46
        logs = run([arp, gre(beacon(radio=b'')), arp], linktype=1)
        self.assertEqual(len(logs['wifi']), 1)
        self.assertEqual(final_network(logs)['beacon_frames'], 1)

    def test_randomized_devices_counted_per_network(self):
        other_local = bytes.fromhex('1a2b3c4d5e6f')
        tods = eapol()[:9] + b'\x01' + eapol()[10:12] + AP + other_local + AP + eapol()[30:]
        logs = run([beacon(), eapol(), eapol(seq=1), tods])
        row = final_network(logs)
        self.assertEqual(row['randomized_devices'], 2)
        self.assertEqual(run([beacon()])['wifi'][-1]['randomized_devices'], 0)

    def test_randomized_device_records_can_be_suppressed(self):
        settings = 'redef WiFiTelemetry::log_randomized_devices = F;\n'
        logs = run([beacon(), eapol(), management(4, b'\0\x04home', src=STA, bssid=BROADCAST)], settings)
        self.assertEqual({d['mac'] for d in logs['wifi_devices']}, {'60:60:1f:58:ec:cc'})
        self.assertEqual(final_network(logs)['randomized_devices'], 1)

    def test_randomized_count_capacity(self):
        locals_ = [bytes([0x02, 0, 0, 0, 0, i]) for i in range(5)]
        frames = [beacon()] + [management(11, b'\0' * 6, dst=m) for m in locals_]
        row = final_network(run(frames, 'redef WiFiTelemetry::max_randomized_per_network = 3;\n'))
        self.assertEqual(row['randomized_devices'], 3)
        self.assertTrue(row['tracking_limited'])

    def test_control_only_devices_can_be_suppressed(self):
        settings = 'redef WiFiTelemetry::log_control_only_devices = F;\n'
        rts = RADIO + b'\xb4\0\0\0' + STA + AP
        ack = RADIO + b'\xd4\0\0\0' + AP
        self.assertFalse(run([rts, ack], settings).get('wifi_devices'))
        logs = run([beacon(), rts, ack], settings)
        self.assertEqual({d['mac'] for d in logs['wifi_devices']}, {'60:60:1f:58:ec:cc'})
        self.assertIn('control-subtype-13', logs['wifi_devices'][-1]['rx_frame_types'])

    def test_device_interval_is_independent(self):
        times = [0, 30, 70, 130]
        frames = [beacon(seq=i) for i in range(4)]
        logs = run(frames, 'redef WiFiTelemetry::device_log_interval = 120secs;\n', times=times)
        # Networks update at 70 s and 130 s (60 s interval); the device only at 130 s (120 s).
        self.assertEqual([r['event_type'] for r in logs['wifi']], ['observation', 'update', 'update'])
        self.assertEqual([r['event_type'] for r in logs['wifi_devices']], ['observation', 'update'])

    def test_new_options_validated(self):
        for settings in ('redef WiFiTelemetry::device_log_interval=0secs;\n',
                         'redef WiFiTelemetry::max_randomized_per_network=0;\n'):
            with self.assertRaisesRegex(AssertionError, 'positive intervals/capacities required'):
                run([beacon()], settings)

    @unittest.skipUnless((ROOT.parent / 'downloads/oui-review-2026-11-17/ieee-oui.csv').exists(),
                         'Optional official IEEE CSV is not included in the package')
    def test_full_official_ieee_csv_via_input_framework(self):
        path = ROOT.parent / 'downloads/oui-review-2026-11-17/ieee-oui.csv'
        with path.open(newline='', encoding='utf-8-sig') as source:
            names = sorted({r['Organization Name'] for r in csv.DictReader(source) if r['Assignment'] == '60601F'})
        logs = run([beacon()] + [disconnect(i) for i in range(20)], input_csv=path)
        self.assertEqual(final_network(logs)['bssid_oui_vendor_hint'], ' | '.join(names))
        self.assertEqual(logs['wifi_findings'][0]['bssid_oui_vendor_hint'], ' | '.join(names))


if __name__ == '__main__':
    unittest.main(verbosity=2)
