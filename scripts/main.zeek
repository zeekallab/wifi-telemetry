# Standalone raw radiotap/802.11 telemetry. No drone-detector dependency.
# The guarded compatibility copy in drone-detector/scripts/wifi.zeek is generated
# from this file by tools/sync_compat.py. Keep policy out of the drone namespace.
@ifndef (WiFiTelemetry::NETWORK_LOG)
@load ./oui
module WiFiTelemetry;

export {
    redef enum Log::ID += { NETWORK_LOG, DEVICE_LOG, FINDING_LOG };
    const log_interval = 60secs &redef;
    const state_timeout = 5min &redef;
    const burst_interval = 10secs &redef;
    const minimum_disconnect_frames: count = 20 &redef;
    const finding_interval = 60secs &redef;
    const max_networks: count = 1024 &redef;
    const max_devices: count = 4096 &redef;
    const max_values: count = 64 &redef;
    const max_recent_frames: count = 1024 &redef;

    type NetworkInfo: record {
        ts: time &log;
        event_type: string &log;
        first_seen: time &log;
        last_seen: time &log;
        bssid: string &log;
        bssid_oui: string &log &optional;
        bssid_oui_vendor_hint: string &log &optional;
        ssid: string &log &optional;
        ssids: set[string] &log;
        hidden_ssid_observed: bool &log &default=F;
        advertised_privacy: bool &log &optional;
        rsn_observed: bool &log &default=F;
        wpa_vendor_ie_observed: bool &log &default=F;
        advertised_channels: set[count] &log;
        frequency_mhz: count &log &optional;
        band: string &log &optional;
        signal_dbm: int &log &optional;
        frames: count &log &default=0;
        management_frames: count &log &default=0;
        data_frames: count &log &default=0;
        beacon_frames: count &log &default=0;
        probe_response_frames: count &log &default=0;
        authentication_frames: count &log &default=0;
        association_request_frames: count &log &default=0;
        association_response_frames: count &log &default=0;
        deauth_frames: count &log &default=0;
        disassoc_frames: count &log &default=0;
        eapol_key_frames: count &log &default=0;
        retry_frames: count &log &default=0;
        protected_frames: count &log &default=0;
        reason_codes: set[count] &log;
        status_codes: set[count] &log;
        management_subtypes: set[string] &log;
        tracking_limited: bool &log &default=F;
    };
    type DeviceInfo: record {
        ts: time &log;
        event_type: string &log;
        first_seen: time &log;
        last_seen: time &log;
        mac: string &log;
        mac_oui: string &log &optional;
        mac_oui_vendor_hint: string &log &optional;
        locally_administered: bool &log;
        observed_roles: set[string] &log;
        bssids: set[string] &log;
        ssids: set[string] &log &optional;
        probe_ssids: set[string] &log;
        tx_frame_types: set[string] &log;
        rx_frame_types: set[string] &log;
        tx_frames: count &log &default=0;
        rx_frames: count &log &default=0;
        frequency_mhz: count &log &optional;
        band: string &log &optional;
        signal_dbm: int &log &optional;
        tracking_limited: bool &log &default=F;
    };
    type FindingInfo: record {
        ts: time &log;
        first_seen: time &log;
        last_seen: time &log;
        bssid: string &log;
        bssid_oui: string &log &optional;
        bssid_oui_vendor_hint: string &log &optional;
        ssid: string &log &optional;
        frequency_mhz: count &log &optional;
        band: string &log &optional;
        finding: string &log;
        evidence: string &log;
        frame_count: count &log;
        threshold: count &log;
        window: interval &log;
        observed_transmitters: set[string] &log;
        observed_receivers: set[string] &log;
        reason_codes: set[count] &log;
        tracking_limited: bool &log;
    };
}

type Radio: record {
    offset: count;
    flags: count &default=0;
    frequency: count &optional;
    signal: int &optional;
};
type Tags: record {
    valid: bool &default=T;
    ssid: string &optional;
    hidden: bool &default=F;
    privacy: bool &optional;
    rsn: bool &default=F;
    wpa: bool &default=F;
    channel: count &optional;
};
type Burst: record {
    start: time &optional;
    frames: count &default=0;
    seen: set[string] &default=set();
    transmitters: set[string] &default=set();
    receivers: set[string] &default=set();
    reasons: set[count] &default=set();
    limited: bool &default=F;
    last_finding: time &optional;
};
type Network: record {
    info: NetworkInfo;
    dirty: bool &default=T;
    last_log: time &optional;
    deauth: Burst &default=Burst();
    disassoc: Burst &default=Burst();
};
type Device: record {
    info: DeviceInfo;
    dirty: bool &default=T;
    last_log: time &optional;
};
global emit_network: function(n: Network, final: bool);
global emit_device: function(d: Device, final: bool);
function expire_network(t: table[string] of Network, key: string): interval
    { emit_network(t[key],T); return 0secs; }
function expire_device(t: table[string] of Device, key: string): interval
    { emit_device(t[key],T); return 0secs; }
global networks: table[string] of Network &write_expire=state_timeout &expire_func=expire_network;
global devices: table[string] of Device &write_expire=state_timeout &expire_func=expire_device;
global capacity_limited = F;
global capacity_warning = F;

function capacity_hit()
    {
    capacity_limited=T;
    if ( ! capacity_warning )
        {
        Reporter::warning("WiFiTelemetry: state capacity reached; some networks/devices are omitted");
        capacity_warning=T;
        }
    }
function byte(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+1]); }
function le16(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+2],T); }
function mac(data: string): string
    { return fmt("%02x:%02x:%02x:%02x:%02x:%02x",byte(data,0),byte(data,1),byte(data,2),byte(data,3),byte(data,4),byte(data,5)); }
function unicast(data: string): bool
    { return |data| == 6 && byte(data,0)%2 == 0 && data != "\x00\x00\x00\x00\x00\x00"; }

# Classify captured frequency, not an ambiguous channel number or an SSID claim.
# This is a band label, not a statement about local regulatory authorization.
function frequency_band(frequency: count): string
    {
    if ( frequency >= 2400 && frequency < 2500 ) return "2.4 GHz";
    if ( frequency >= 5000 && frequency < 5925 ) return "5 GHz";
    if ( frequency >= 5925 && frequency < 7125 ) return "6 GHz";
    if ( frequency >= 57000 && frequency < 71000 ) return "60 GHz";
    return "";
    }

function global_oui(address: string): string
    {
    # The first byte's multicast and local-administration bits must both be zero.
    if ( |address| != 17 || to_count(address[:2],16)%4 != 0 ) return "";
    return address[:8];
    }

# Decode the radiotap prefix through dBm antenna signal, respecting extended
# presence words and each field's alignment. Unknown later fields are skipped
# via the declared radiotap length, never guessed.
function radio(raw: string): Radio
    {
    local r=Radio($offset=0);
    if ( |raw| < 8 || raw[0:2] != "\x00\x00" ) return r;
    local size=le16(raw,2);
    if ( size < 8 || size > 4096 || size > |raw| ) return r;
    local present=bytestring_to_count(raw[4:8],T);
    local bitmap=present; local cursor: count=8; local words: count=1;
    while ( bitmap >= 2147483648 )
        {
        if ( cursor+4 > size || words >= 8 ) return r;
        bitmap=bytestring_to_count(raw[cursor:cursor+4],T); cursor+=4; ++words;
        }
    local bit: count=0; local mask: count=1;
    while ( bit <= 5 )
        {
        if ( (present/mask)%2 == 1 )
            {
            local alignment: count=1; local length: count=1;
            if ( bit == 0 ) { alignment=8; length=8; }
            else if ( bit == 3 ) { alignment=2; length=4; }
            else if ( bit == 4 ) { alignment=2; length=2; }
            cursor+=(alignment-cursor%alignment)%alignment;
            if ( cursor+length > size ) return r;
            if ( bit == 1 ) r$flags=byte(raw,cursor);
            else if ( bit == 3 ) r$frequency=le16(raw,cursor);
            else if ( bit == 5 )
                {
                local b=byte(raw,cursor);
                r$signal=to_int(fmt("%d",b))-(b >= 128 ? 256 : 0);
                }
            cursor+=length;
            }
        ++bit; mask=mask*2;
        }
    r$offset=size;
    return r;
    }

# All IEs must fit before any identity/security metadata is accepted. The
# privacy bit and the presence of RSN/WPA IEs are claims, not negotiated security.
function tags(data: string, start: count): Tags
    {
    local t=Tags(); local i=start; local count_tags: count=0;
    while ( i < |data| )
        {
        if ( i+2 > |data| || count_tags >= 256 ) { t$valid=F; return t; }
        local tag=byte(data,i); local size=byte(data,i+1); i+=2; ++count_tags;
        if ( i+size > |data| ) { t$valid=F; return t; }
        if ( tag == 0 )
            {
            if ( size > 32 || t?$ssid ) { t$valid=F; return t; }
            t$ssid=data[i:i+size];
            t$hidden=size == 0 || t$ssid == /^\x00+$/;
            }
        else if ( tag == 3 && size == 1 ) t$channel=byte(data,i);
        else if ( tag == 48 && size >= 2 ) t$rsn=T;
        else if ( tag == 221 && size >= 4 && data[i:i+4] == "\x00\x50\xf2\x01" ) t$wpa=T;
        i+=size;
        }
    return t;
    }

function emit_network(n: Network, final: bool)
    {
    if ( ! final && n?$last_log && network_time()-n$last_log < log_interval ) return;
    if ( n$info?$bssid_oui )
        {
        local hint=oui_vendor_hint(n$info$bssid_oui);
        if ( hint != "" && (! n$info?$bssid_oui_vendor_hint || n$info$bssid_oui_vendor_hint != hint) )
            { n$info$bssid_oui_vendor_hint=hint; n$dirty=T; }
        }
    if ( ! n$dirty ) return;
    n$info$ts=network_time();
    n$info$event_type=final ? "final" : (n?$last_log ? "update" : "observation");
    n$info$tracking_limited=n$info$tracking_limited || capacity_limited;
    Log::write(NETWORK_LOG,n$info); n$last_log=network_time(); n$dirty=F;
    }

function device_network_names(d: Device)
    {
    for ( bs in d$info$bssids )
        {
        if ( bs !in networks ) next;
        if ( networks[bs]$info$tracking_limited && ! d$info$tracking_limited )
            { d$info$tracking_limited=T; d$dirty=T; }
        for ( name in networks[bs]$info$ssids )
            {
            if ( d$info?$ssids && name in d$info$ssids ) next;
            if ( ! d$info?$ssids ) d$info$ssids=set();
            if ( |d$info$ssids| < max_values ) { add d$info$ssids[name]; d$dirty=T; }
            else if ( ! d$info$tracking_limited ) { d$info$tracking_limited=T; d$dirty=T; }
            }
        }
    }

function emit_device(d: Device, final: bool)
    {
    if ( ! final && d?$last_log && network_time()-d$last_log < log_interval ) return;
    device_network_names(d);
    if ( d$info?$mac_oui )
        {
        local hint=oui_vendor_hint(d$info$mac_oui);
        if ( hint != "" && (! d$info?$mac_oui_vendor_hint || d$info$mac_oui_vendor_hint != hint) )
            { d$info$mac_oui_vendor_hint=hint; d$dirty=T; }
        }
    if ( ! d$dirty ) return;
    d$info$ts=network_time();
    d$info$event_type=final ? "final" : (d?$last_log ? "update" : "observation");
    d$info$tracking_limited=d$info$tracking_limited || capacity_limited;
    Log::write(DEVICE_LOG,d$info); d$last_log=network_time(); d$dirty=F;
    }

function frame_name(kind: count, subtype: count): string
    {
    if ( kind == 0 )
        {
        if ( subtype == 0 ) return "association-request";
        if ( subtype == 1 ) return "association-response";
        if ( subtype == 2 ) return "reassociation-request";
        if ( subtype == 3 ) return "reassociation-response";
        if ( subtype == 4 ) return "probe-request";
        if ( subtype == 5 ) return "probe-response";
        if ( subtype == 8 ) return "beacon";
        if ( subtype == 10 ) return "disassociation";
        if ( subtype == 11 ) return "authentication";
        if ( subtype == 12 ) return "deauthentication";
        return fmt("management-subtype-%d",subtype);
        }
    if ( kind == 1 ) return fmt("control-subtype-%d",subtype);
    return fmt("data-subtype-%d",subtype);
    }

function observe_device(address: string, tx: bool, bs: string, role: string, frame_type: string, probe: Tags, r: Radio)
    {
    if ( ! unicast(address) ) return;
    local key=mac(address);
    if ( key !in devices )
        {
        if ( |devices| >= max_devices ) { capacity_hit(); return; }
        devices[key]=Device($info=DeviceInfo($ts=network_time(),$event_type="observation",
            $first_seen=network_time(),$last_seen=network_time(),$mac=key,$locally_administered=(byte(address,0)/2)%2 == 1,
            $observed_roles=set(),$bssids=set(),$probe_ssids=set(),$tx_frame_types=set(),$rx_frame_types=set()));
        local oui=global_oui(key);
        if ( oui != "" )
            {
            devices[key]$info$mac_oui=oui;
            }
        }
    local d=devices[key]; d$dirty=T; d$info$last_seen=network_time();
    if ( tx ) { ++d$info$tx_frames; add d$info$tx_frame_types[frame_type]; }
    else { ++d$info$rx_frames; add d$info$rx_frame_types[frame_type]; }
    if ( role != "" ) add d$info$observed_roles[role];
    if ( bs != "" )
        {
        if ( |d$info$bssids| < max_values || bs in d$info$bssids ) add d$info$bssids[bs];
        else d$info$tracking_limited=T;
        }
    if ( tx && probe?$ssid && ! probe$hidden )
        {
        if ( |d$info$probe_ssids| < max_values || probe$ssid in d$info$probe_ssids ) add d$info$probe_ssids[probe$ssid];
        else d$info$tracking_limited=T;
        }
    # Radiotap signal measures the transmitter only, never the receiver.
    if ( tx && r?$signal ) d$info$signal_dbm=r$signal;
    if ( r?$frequency )
        {
        d$info$frequency_mhz=r$frequency;
        local band=frequency_band(r$frequency);
        if ( band != "" ) d$info$band=band; else delete d$info$band;
        }
    emit_device(d,F); devices[key]=d;
    }

function disconnect(n: Network, data: string, disassoc: bool)
    {
    local b=disassoc ? n$disassoc : n$deauth;
    if ( ! b?$start || network_time()-b$start >= burst_interval )
        {
        local fresh=Burst($start=network_time());
        if ( b?$last_finding ) fresh$last_finding=b$last_finding;
        b=fresh;
        }
    local key=data[0:1]+data[4:24];
    if ( key !in b$seen )
        {
        if ( |b$seen| >= max_recent_frames ) b$limited=T;
        else
            {
            add b$seen[key]; ++b$frames;
            local source=mac(data[10:16]); local destination=mac(data[4:10]);
            if ( |b$transmitters| < max_values || source in b$transmitters ) add b$transmitters[source]; else b$limited=T;
            if ( |b$receivers| < max_values || destination in b$receivers ) add b$receivers[destination]; else b$limited=T;
            local reason=le16(data,24);
            if ( |b$reasons| < max_values || reason in b$reasons ) add b$reasons[reason]; else b$limited=T;
            if ( b$frames >= minimum_disconnect_frames &&
                 (! b?$last_finding || network_time()-b$last_finding >= finding_interval) )
                {
                local info=FindingInfo($ts=network_time(),$first_seen=b$start,$last_seen=network_time(),
                    $bssid=n$info$bssid,$finding=disassoc ? "disassociation_burst" : "deauthentication_burst",
                    $evidence="distinct-unprotected-non-retry-disconnect-frames",
                    $frame_count=b$frames,$threshold=minimum_disconnect_frames,$window=burst_interval,
                    $observed_transmitters=copy(b$transmitters),$observed_receivers=copy(b$receivers),
                    $reason_codes=copy(b$reasons),$tracking_limited=b$limited || n$info$tracking_limited || capacity_limited);
                if ( n$info?$ssid ) info$ssid=n$info$ssid;
                if ( n$info?$bssid_oui ) info$bssid_oui=n$info$bssid_oui;
                if ( n$info?$bssid_oui )
                    {
                    local hint=oui_vendor_hint(n$info$bssid_oui);
                    if ( hint != "" ) info$bssid_oui_vendor_hint=hint;
                    }
                if ( n$info?$frequency_mhz ) info$frequency_mhz=n$info$frequency_mhz;
                if ( n$info?$band ) info$band=n$info$band;
                Log::write(FINDING_LOG,info); b$last_finding=network_time();
                }
            }
        }
    if ( b$limited ) n$info$tracking_limited=T;
    if ( disassoc ) n$disassoc=b; else n$deauth=b;
    }

event zeek_init() &priority=5
    {
    if ( log_interval <= 0secs || state_timeout <= 0secs || burst_interval <= 0secs || finding_interval <= 0secs ||
         minimum_disconnect_frames == 0 || max_networks == 0 || max_devices == 0 || max_values == 0 ||
         max_recent_frames < minimum_disconnect_frames )
        Reporter::fatal("WiFiTelemetry: positive intervals/capacities required; max_recent_frames must cover minimum_disconnect_frames");
    Log::create_stream(NETWORK_LOG,[$columns=NetworkInfo,$path="wifi"]);
    Log::create_stream(DEVICE_LOG,[$columns=DeviceInfo,$path="wifi_devices"]);
    Log::create_stream(FINDING_LOG,[$columns=FindingInfo,$path="wifi_findings"]);
    }

event raw_packet(p: raw_pkt_hdr)
    {
    if ( p$l2$encap == LINK_ETHERNET ) return;
    local raw=get_current_packet()$data;
    local r=radio(raw);
    if ( r$offset == 0 || (r$flags/64)%2 == 1 ) return; # Bad FCS.
    local data=raw[r$offset:];
    if ( (r$flags/16)%2 == 1 )
        { if ( |data| < 4 ) return; data=data[:|data|-4]; }
    if ( |data| < 2 || byte(data,0)%4 != 0 ) return;
    local fc=byte(data,0); local flags=byte(data,1);
    local kind=(fc/4)%4; local subtype=fc/16;
    local frame_type=frame_name(kind,subtype);
    # Control frames have no reliable BSSID. Only decode defined address layouts.
    if ( kind == 1 )
        {
        if ( subtype in set(12,13) && |data| >= 10 )
            observe_device(data[4:10],F,"","",frame_type,Tags(),r);
        else if ( subtype in set(8,9,10,11,14,15) && |data| >= 16 )
            {
            observe_device(data[10:16],T,"","",frame_type,Tags(),r);
            observe_device(data[4:10],F,"","",frame_type,Tags(),r);
            }
        return;
        }
    if ( kind !in set(0,2) || |data| < 24 ) return;
    local protected=(flags/64)%2 == 1;
    local retry=(flags/8)%2 == 1;
    local fragmented=(flags/4)%2 == 1 || le16(data,22)%16 != 0;
    local ds=flags%4;
    if ( kind == 0 && ds != 0 ) return;
    if ( kind == 2 && ds == 3 ) return; # WDS/mesh needs separate address handling.
    local address=kind == 2 && ds == 1 ? data[4:10] :
                  (kind == 2 && ds == 2 ? data[10:16] : data[16:22]);
    local bs=unicast(address) ? mac(address) : "";
    local t=Tags(); local probe=Tags();
    if ( kind == 0 && ! protected && ! fragmented )
        {
        if ( subtype in set(5,8) )
            {
            if ( |data| < 36 || data[10:16] != data[16:22] ) return;
            t=tags(data,36); if ( ! t$valid ) return;
            t$privacy=(le16(data,34)/16)%2 == 1;
            }
        else if ( subtype == 4 ) { probe=tags(data,24); if ( ! probe$valid ) return; }
        else if ( subtype in set(10,12) && |data| < 26 ) return;
        else if ( subtype in set(1,3,11) && |data| < 30 ) return;
        else if ( subtype == 0 && |data| < 28 ) return;
        else if ( subtype == 2 && |data| < 34 ) return;
        }
    local tx_role=""; local rx_role="";
    if ( bs != "" )
        {
        tx_role=data[10:16] == address ? "bssid-transmitter" : "peer-transmitter";
        rx_role=data[4:10] == address ? "bssid-receiver" : "peer-receiver";
        }
    if ( kind == 0 && subtype == 4 ) tx_role="probe-request-transmitter";
    if ( bs == "" )
        {
        observe_device(data[10:16],T,bs,tx_role,frame_type,probe,r);
        observe_device(data[4:10],F,bs,rx_role,frame_type,Tags(),r);
        return; # Wildcard probes still have device telemetry.
        }
    if ( bs !in networks )
        {
        if ( |networks| >= max_networks )
            {
            capacity_hit();
            observe_device(data[10:16],T,bs,tx_role,frame_type,probe,r);
            observe_device(data[4:10],F,bs,rx_role,frame_type,Tags(),r);
            return;
            }
        networks[bs]=Network($info=NetworkInfo($ts=network_time(),$event_type="observation",
            $first_seen=network_time(),$last_seen=network_time(),$bssid=bs,$ssids=set(),
            $advertised_channels=set(),$reason_codes=set(),$status_codes=set(),$management_subtypes=set()));
        local oui=global_oui(bs);
        if ( oui != "" )
            {
            networks[bs]$info$bssid_oui=oui;
            }
        }
    local n=networks[bs]; local info=n$info;
    n$dirty=T; info$last_seen=network_time(); ++info$frames;
    if ( r?$frequency )
        {
        info$frequency_mhz=r$frequency;
        local band=frequency_band(r$frequency);
        if ( band != "" ) info$band=band; else delete info$band;
        }
    if ( r?$signal && data[10:16] == address ) info$signal_dbm=r$signal;
    if ( retry ) ++info$retry_frames;
    if ( protected ) ++info$protected_frames;
    if ( t?$ssid )
        {
        if ( t$hidden ) info$hidden_ssid_observed=T;
        else
            {
            info$ssid=t$ssid;
            if ( |info$ssids| < max_values || t$ssid in info$ssids ) add info$ssids[t$ssid];
            else info$tracking_limited=T;
            }
        }
    if ( t?$privacy ) info$advertised_privacy=t$privacy;
    if ( t$rsn ) info$rsn_observed=T;
    if ( t$wpa ) info$wpa_vendor_ie_observed=T;
    if ( t?$channel )
        {
        if ( |info$advertised_channels| < max_values || t$channel in info$advertised_channels ) add info$advertised_channels[t$channel];
        else info$tracking_limited=T;
        }
    if ( kind == 0 )
        {
        ++info$management_frames;
        if ( subtype == 8 ) ++info$beacon_frames;
        else if ( subtype == 5 ) ++info$probe_response_frames;
        else if ( subtype == 11 ) ++info$authentication_frames;
        else if ( subtype in set(0,2) ) ++info$association_request_frames;
        else if ( subtype in set(1,3) ) ++info$association_response_frames;
        else if ( subtype == 12 ) ++info$deauth_frames;
        else if ( subtype == 10 ) ++info$disassoc_frames;
        add info$management_subtypes[frame_type];
        if ( ! protected && ! fragmented )
            {
            if ( subtype in set(10,12) )
                {
                local reason=le16(data,24);
                if ( |info$reason_codes| < max_values || reason in info$reason_codes ) add info$reason_codes[reason];
                else info$tracking_limited=T;
                if ( ! retry && unicast(data[10:16]) ) disconnect(n,data,subtype == 10);
                }
            else if ( subtype in set(1,3,11) )
                {
                local status=le16(data,subtype == 11 ? 28 : 26);
                if ( |info$status_codes| < max_values || status in info$status_codes ) add info$status_codes[status];
                else info$tracking_limited=T;
                }
            }
        }
    else
        {
        ++info$data_frames;
        if ( ! protected && ! fragmented && subtype%8 < 4 )
            {
            local header: count=24; local supported=T;
            if ( subtype >= 8 )
                {
                if ( |data| < 26 || (byte(data,24)/128)%2 == 1 ) supported=F;
                header+=2;
                if ( flags >= 128 ) header+=4;
                }
            if ( (r$flags/32)%2 == 1 ) header+=(4-header%4)%4;
            if ( supported && |data| >= header+12 && data[header:header+8] == "\xaa\xaa\x03\x00\x00\x00\x88\x8e" )
                {
                local e=header+8; local length=bytestring_to_count(data[e+2:e+4]);
                if ( byte(data,e) in set(1,2,3) && byte(data,e+1) == 3 && length >= 95 &&
                     |data| >= e+4+length && byte(data,e+4) in set(2,254) ) ++info$eapol_key_frames;
                }
            }
        }
    emit_network(n,F); networks[bs]=n;
    # Learn advertised network names before emitting the first device snapshot.
    observe_device(data[10:16],T,bs,tx_role,frame_type,probe,r);
    observe_device(data[4:10],F,bs,rx_role,frame_type,Tags(),r);
    }

event zeek_done()
    {
    for ( bs in networks ) emit_network(networks[bs],T);
    for ( address in devices ) emit_device(devices[address],T);
    }
@endif
