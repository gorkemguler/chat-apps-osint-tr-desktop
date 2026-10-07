
"""Windows için WhatsApp aramalarında karşı taraf üstverisini yakalar. Kullanım için README.md dosyasına bakın."""

import argparse
import collections
import datetime
import html as html_mod
import ipaddress
import json
import os
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser

try:
    import frida
except ImportError:
    # Rapor oluşturma/görüntüleme Frida gerektirmez. Yakalama başlatıldığında
    # bağımlılığı ayrıca kontrol ediyoruz.
    frida = None

PROCESS = "WhatsApp.Root.exe"

AGENT = r"""
'use strict';

var VOIP = 'WhatsAppNative.Voip.dll';

// RVA tables are per-build. WhatsApp Desktop auto-updates and every offset
// shifts when it does, so hooking a build we have no table for plants inline
// trampolines at wrong addresses and crashes WhatsApp on the next call. Keyed
// by the loaded module's byte size (a cheap, reliable build fingerprint).
// Resolved from the self-labeling assert macro + .pdata; see resolve_rva.py.
// KEY = PE SizeOfImage (in-memory mapped size = Frida module.size), NOT the
// on-disk file size — the two differ by section padding.
var BUILDS = {
  12525568: {   // WhatsAppDesktop 2.2631.102.0  (SizeOfImage 0xBF2000)
    wa_call_set_field_stat_numeric:                       0x68600,
    wa_call_set_field_stat_str:                           0x68900,
    parse_endpoint_address:                              0x2853B0,
    platform_to_cstr:                                    0x20C1E0,
    wa_transport_get_peer_public_addr_str:               0x415270,
    wa_call_participant_get_peer_test_bucket_id_list_str: 0x20A4A0,
    wa_call_participant_get_peer_test_bucket_str:        0x20A450,
    wa_call_participant_get_multi_device_info_count:     0x20A890,
    wa_call_participant_get_active_device_info_const:    0x20A7B0,
    wa_call_participant_get_audio_level:                 0x20B8A0,
    wa_call_participant_get_offer_msg:                   0x20AB80,
  },
  12619776: {   // WhatsAppDesktop 2.2632.100.0  (SizeOfImage 0xC09000)
    wa_call_set_field_stat_numeric:                       0x64D70,
    wa_call_set_field_stat_str:                           0x65070,
    parse_endpoint_address:                              0x285390,
    platform_to_cstr:                                    0x20BD90,
    wa_transport_get_peer_public_addr_str:               0x42D200,
    wa_call_participant_get_peer_test_bucket_id_list_str: 0x20A050,
    wa_call_participant_get_peer_test_bucket_str:        0x20A000,
    wa_call_participant_get_multi_device_info_count:     0x20A440,
    wa_call_participant_get_active_device_info_const:    0x20A360,
    wa_call_participant_get_audio_level:                 0x20B450,
    wa_call_participant_get_offer_msg:                   0x20A730,
  },
  12709888: {   // WhatsAppDesktop 2.2636.100.0  (SizeOfImage 0xC1F000)
    wa_call_set_field_stat_numeric:                       0x65730,
    wa_call_set_field_stat_str:                           0x659E0,
    parse_endpoint_address:                              0x28BFF0,
    platform_to_cstr:                                    0x212170,
    wa_transport_get_peer_public_addr_str:               0x4335B0,
    wa_call_participant_get_peer_test_bucket_id_list_str: 0x210370,
    wa_call_participant_get_peer_test_bucket_str:        0x210320,
    wa_call_participant_get_multi_device_info_count:     0x210760,
    wa_call_participant_get_active_device_info_const:    0x210680,
    wa_call_participant_get_audio_level:                 0x211830,
    wa_call_participant_get_offer_msg:                   0x210A50,
  },
  12722176: {   // WhatsAppDesktop 2.2637.100.0  (SizeOfImage 0xC22000)
    wa_call_set_field_stat_numeric:                       0x65770,
    wa_call_set_field_stat_str:                           0x65A20,
    parse_endpoint_address:                              0x28F400,
    platform_to_cstr:                                    0x2148C0,
    wa_transport_get_peer_public_addr_str:               0x437AE0,
    wa_call_participant_get_peer_test_bucket_id_list_str: 0x212AC0,
    wa_call_participant_get_peer_test_bucket_str:        0x212A70,
    wa_call_participant_get_multi_device_info_count:     0x212EB0,
    wa_call_participant_get_active_device_info_const:    0x212DD0,
    wa_call_participant_get_audio_level:                 0x213F80,
    wa_call_participant_get_offer_msg:                   0x2131A0,
  },
};
var RVA = null;   // selected at runtime from BUILDS by module size

var PLATFORM = ['unknown','android','iphone','wp','ios_tablet','kaios','windows',
  'portal','mac_os_electron','windows_electron','wearm','macos','capi','ipad',
  'smba','smbi','web'];

var OFF_PLATFORM = 0x58;

function emit(ev, data) { data = data || {}; data.event = ev; data.ts = Date.now(); send(data); }

function cstr(p) {
  try { return (p === null || p.isNull()) ? null : p.readUtf8String(); }
  catch (e) { return null; }
}

function moduleBase(name) {
  var lower = name.toLowerCase();
  try {
    if (typeof Module.findBaseAddress === 'function') {
      var b = Module.findBaseAddress(name);
      if (b) return b;
    }
  } catch (e) {}
  try {
    if (typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(name);
      if (m) return m.base;
    }
  } catch (e) {}
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (String(mods[i].name).toLowerCase() === lower) return mods[i].base;
    }
  } catch (e) {}
  return null;
}

function moduleSize(name) {
  var lower = name.toLowerCase();
  try {
    if (typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(name);
      if (m && m.size) return m.size;
    }
  } catch (e) {}
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (String(mods[i].name).toLowerCase() === lower) return mods[i].size;
    }
  } catch (e) {}
  return null;
}

// Like moduleBase/moduleSize but returns the whole module, so we also get its
// on-disk .path — needed to auto-resolve an unknown build (see start()).
function moduleObj(name) {
  var lower = name.toLowerCase();
  try {
    if (typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(name);
      if (m) return m;
    }
  } catch (e) {}
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (String(mods[i].name).toLowerCase() === lower) return mods[i];
    }
  } catch (e) {}
  return null;
}

// Decide where THIS build's RVA table comes from, then hook.
//   - Known build  -> use the inline BUILDS cache (fast, offline, no deps).
//   - Unknown build -> NOT a dead end any more: ask the Python side to derive
//     the offsets straight from the DLL on disk (resolve_rva.py's method) and
//     hook once they arrive. WhatsApp auto-updates constantly, so this is what
//     keeps the tool working across versions without a hand-added BUILDS entry.
// We only stay unhooked — the original fail-safe — if that resolution ALSO
// fails, so a stale offset is never planted and WhatsApp never crashes.
function start() {
  var mod = moduleObj(VOIP);
  if (mod === null) { emit('error', { message: VOIP + ' yüklenmedi' }); return; }
  var base = mod.base, size = mod.size;

  if (BUILDS[size]) { RVA = BUILDS[size]; installHooks(base, size, 'cache'); return; }

  emit('need_rva', { path: mod.path, size: size });
  recv('rva_table', function (msg) {
    if (!msg || !msg.rva) {
      emit('error', {
        message: 'Bilinmeyen ' + VOIP + ' sürümü (boyut=' + size + '); otomatik RVA çözümleme ' +
                 'başarısız' + (msg && msg.reason ? ' (' + msg.reason + ')' : '') +
                 '. WhatsApp uygulamasının çökmemesi için kancalar kurulmadı. ' +
                 'Bu DLL üzerinde resolve_rva.py dosyasını çalıştırıp BUILDS[' + size + '] kaydı ekleyin.',
        module_size: size
      });
      return;
    }
    RVA = msg.rva;
    BUILDS[size] = msg.rva;   // cache for the rest of this session
    installHooks(base, size, 'auto-resolved');
  });
}

function installHooks(base, size, rva_source) {
  function at(n) { return base.add(RVA[n]); }
  var hooked = [];

  try {
    Interceptor.attach(at('wa_call_set_field_stat_numeric'), {
      onEnter: function (args) {
        var name = cstr(args[1]);
        if (!name) return;
        var v = null;
        try { v = this.context.rsp.add(0x38).readDouble(); } catch (e) {}
        emit('field_stat', { name: name, field_id: args[2].toInt32(), value: v });
      }
    });
    hooked.push('field_stat_numeric');
  } catch (e) { emit('hook_error', { fn: 'field_stat_numeric', err: String(e) }); }

  try {
    Interceptor.attach(at('wa_call_set_field_stat_str'), {
      onEnter: function (args) {
        var name = cstr(args[1]);
        if (!name) return;
        emit('field_stat_str', { name: name, field_id: args[2].toInt32(), value: cstr(args[3]) });
      }
    });
    hooked.push('field_stat_str');
  } catch (e) { emit('hook_error', { fn: 'field_stat_str', err: String(e) }); }

  try {
    var seenEp = {};
    Interceptor.attach(at('parse_endpoint_address'), {
      onEnter: function (args) { this.out = args[1]; },
      onLeave: function (ret) {
        if (ret.toInt32() === 0 || this.out.isNull()) return;
        try {
          var o = this.out;
          var v4 = o.add(0x18).readU8() !== 0, v6 = o.add(0x19).readU8() !== 0;
          var rec = {};
          if (v4) {
            var b = new Uint8Array(o.readByteArray(4));
            rec.ipv4 = b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3];
            rec.ipv4_port = o.add(0x14).readU16();
          }
          if (v6) {
            var c = new Uint8Array(o.add(4).readByteArray(16)), parts = [];
            for (var k = 0; k < 16; k += 2) parts.push(((c[k] << 8) | c[k+1]).toString(16));
            rec.ipv6 = '[' + parts.join(':') + ']';
            rec.ipv6_port = o.add(0x16).readU16();
          }
          var key = (rec.ipv4 || rec.ipv6) + ':' + (rec.ipv4_port || rec.ipv6_port);
          if (seenEp[key]) return;
          seenEp[key] = 1;
          emit('endpoint', rec);
        } catch (e) {}
      }
    });
    hooked.push('parse_endpoint_address');
  } catch (e) { emit('hook_error', { fn: 'parse_endpoint_address', err: String(e) }); }

  try {
    var lastPlat = null;
    Interceptor.attach(at('wa_call_participant_get_active_device_info_const'), {
      onLeave: function (ret) {
        if (ret.isNull()) return;
        try {
          var p = ret.add(OFF_PLATFORM).readU32();
          if (p === 0 || p === lastPlat) return;
          lastPlat = p;
          emit('peer_platform', {
            platform_id: p,
            platform: (p < PLATFORM.length) ? PLATFORM[p] : 'out_of_range'
          });
        } catch (e) {}
      }
    });
    hooked.push('peer_platform');
  } catch (e) {}

  function scalar(fnName, evName, field) {
    try {
      var lastByCtx = {};
      Interceptor.attach(at(fnName), {
        onEnter: function (args) { this.ctx = args[0].toString(); },
        onLeave: function (ret) {
          var v; try { v = ret.toInt32(); } catch (e) { return; }
          if (lastByCtx[this.ctx] === v) return;
          lastByCtx[this.ctx] = v;
          var rec = { ctx: this.ctx }; rec[field] = v;
          emit(evName, rec);
        }
      });
      hooked.push(evName);
    } catch (e) {}
  }
  scalar('wa_call_participant_get_multi_device_info_count', 'peer_device_count', 'device_count');
  scalar('wa_call_participant_get_audio_level', 'peer_audio_level', 'level');

  try {
    Interceptor.attach(at('wa_transport_get_peer_public_addr_str'), {
      onEnter: function (args) { this.buf = args[1]; },
      onLeave: function () {
        var s = cstr(this.buf);
        if (s) emit('peer_public_addr', { addr: s });
      }
    });
    hooked.push('peer_public_addr');
  } catch (e) {}

  ['wa_call_participant_get_peer_test_bucket_id_list_str',
   'wa_call_participant_get_peer_test_bucket_str'].forEach(function (n) {
    try {
      var last = null;
      Interceptor.attach(at(n), {
        onLeave: function (ret) {
          var s = cstr(ret);
          if (!s || s === last) return;
          last = s;
          emit('peer_test_bucket', { fn: n, value: s });
        }
      });
      hooked.push(n);
    } catch (e) {}
  });

  try {
    var lastOffer = null;
    Interceptor.attach(at('wa_call_participant_get_offer_msg'), {
      onLeave: function (ret) {
        if (ret.isNull()) return;
        try {
          var b = new Uint8Array(ret.readByteArray(192)), runs = [], cur = '';
          for (var i = 0; i < b.length; i++) {
            var c = b[i];
            if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
            else { if (cur.length >= 8) runs.push(cur); cur = ''; }
          }
          if (cur.length >= 8) runs.push(cur);
          var key = runs.join('|');
          if (!runs.length || key === lastOffer) return;
          lastOffer = key;
          emit('peer_offer_msg', { strings: runs });
        } catch (e) {}
      }
    });
    hooked.push('peer_offer_msg');
  } catch (e) {}

  emit('hook_ready', { module: VOIP, base: base.toString(), module_size: size,
                       rva_source: rva_source, hooked: hooked });
}

if (moduleBase(VOIP) !== null) start();
else {
  var iv = setInterval(function () {
    if (moduleBase(VOIP) !== null) { clearInterval(iv); start(); }
  }, 250);
  emit('waiting', { message: VOIP + ' henüz yüklenmedi' });
}
"""

META_V4 = [
    ("31.13.0.0", 16), ("157.240.0.0", 16), ("185.60.216.0", 22),
    ("179.60.192.0", 22), ("129.134.0.0", 16), ("66.220.144.0", 20),
    ("69.63.176.0", 20), ("69.171.224.0", 19), ("74.119.76.0", 22),
    ("102.132.96.0", 20), ("103.4.96.0", 22), ("173.252.64.0", 18),
    ("204.15.20.0", 22), ("163.70.128.0", 17), ("57.144.0.0", 14),
]

NETWORK_MEDIUM = {
    0: "unclassified (connected, but type could not be determined)",
    1: "cellular",
    2: "not cellular (Wi-Fi, or Ethernet on a desktop peer)",
    3: "no active network resolved when the stanza was composed",
}

def ip_to_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        parts = [int(x) for x in parts]
    except ValueError:
        return None
    if any(p < 0 or p > 255 for p in parts):
        return None
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def is_meta(ip):
    if not ip:
        return False
    if ":" in ip:
        return ip.lstrip("[").lower().startswith("2a03:2880")
    value = ip_to_int(ip)
    if value is None:
        return False
    for net, bits in META_V4:
        base = ip_to_int(net)
        mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if (value & mask) == (base & mask):
            return True
    return False

def addr_class(ip):
    if not ip:
        return "unknown"
    if ":" in ip:
        return "ipv6"
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return "unknown"
    if len(parts) != 4:
        return "unknown"
    if parts[0] == 10 or (parts[0] == 172 and 16 <= parts[1] <= 31) \
            or (parts[0] == 192 and parts[1] == 168):
        return "private (RFC1918)"
    if parts[0] == 100 and 64 <= parts[1] <= 127:
        return "carrier-grade NAT (RFC6598)"
    if parts[0] == 127:
        return "loopback"
    return "public"

def num_list(text):
    if not text:
        return None
    try:
        return [float(x) for x in str(text).split(",") if x != ""]
    except ValueError:
        return None


def geolocate_ip(ip):
    """Resolve a public IP via the keyless HTTPS ipwho.is endpoint.

    Return the existing report geolocation fields, or a dict with an 'error'
    key if the address is non-public or the lookup fails. Never raises.
    """
    if not ip:
        return None
    ip = str(ip).strip().strip("[]")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {"query": ip, "error": "invalid IP address"}
    if not address.is_global:
        return {"query": ip, "error": "reserved / non-routable address"}
    ip = str(address)
    url = "https://ipwho.is/%s" % urllib.parse.quote(ip, safe="")
    try:
        with urllib.request.urlopen(url, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"query": ip, "error": "lookup failed: %s" % exc}
    if not isinstance(data, dict) or data.get("success") is not True:
        message = data.get("message") if isinstance(data, dict) else None
        return {"query": ip, "error": message or "lookup unsuccessful"}

    connection = data.get("connection")
    if not isinstance(connection, dict):
        connection = {}
    timezone = data.get("timezone")
    if not isinstance(timezone, dict):
        timezone = {}
    asn = connection.get("asn")
    if asn not in (None, ""):
        asn = str(asn)
        if not asn.upper().startswith("AS"):
            asn = "AS" + asn
    else:
        asn = None
    return {
        "status": "success",
        "query": ip,
        "country": data.get("country"),
        "countryCode": data.get("country_code"),
        "regionName": data.get("region"),
        "city": data.get("city"),
        "zip": data.get("postal"),
        "lat": data.get("latitude"),
        "lon": data.get("longitude"),
        "timezone": timezone.get("id"),
        "isp": connection.get("isp"),
        "org": connection.get("org"),
        "as": asn,
    }

def build_report(events, geo_lookup=True):
    numeric, strings = {}, {}
    for e in events:
        if e.get("event") == "field_stat":
            numeric[e["name"]] = e.get("value")
        elif e.get("event") == "field_stat_str":
            strings[e["name"]] = e.get("value")

    stamps = [e["ts"] for e in events if "ts" in e]
    duration_ms = (max(stamps) - min(stamps)) if stamps else 0

    def get(name):
        return numeric.get(name)

    contexts = collections.defaultdict(dict)
    for e in events:
        ctx = e.get("ctx")
        if not ctx:
            continue
        entry = contexts[ctx]
        entry["events"] = entry.get("events", 0) + 1
        if e.get("event") == "peer_device_count":
            entry["device_count"] = e.get("device_count")
    peer_ctx = None
    for ctx, entry in contexts.items():
        if entry.get("device_count"):
            peer_ctx = ctx

    relays, peer_side, seen = [], [], set()
    for e in events:
        if e.get("event") != "endpoint":
            continue
        for ip, port in ((e.get("ipv4"), e.get("ipv4_port")),
                         (e.get("ipv6"), e.get("ipv6_port"))):
            if not ip or (ip, port) in seen:
                continue
            seen.add((ip, port))
            row = {"ip": ip, "port": port, "address_class": addr_class(ip.strip("[]"))}
            (relays if is_meta(ip) else peer_side).append(row)

    public_eps = [e for e in peer_side if e["address_class"] == "public"]
    private_eps = [e for e in peer_side
                   if "private" in e["address_class"] or "carrier" in e["address_class"]]

    our_rtt = num_list(strings.get("relay_measured_c2r_rtt_list"))
    peer_rtt = num_list(strings.get("relay_measured_max_peer_c2r_rtt_list"))
    servers = [s.strip() for s in (strings.get("call_relay_servers") or "").split(",") if s.strip()]

    latency, degenerate = [], None
    if our_rtt and peer_rtt and len(our_rtt) == len(peer_rtt):

        degenerate = (len(set(peer_rtt)) == 1) or any(v < 0 for v in peer_rtt)
        for i, (ours, theirs) in enumerate(zip(our_rtt, peer_rtt)):
            delta = theirs - ours
            latency.append({
                "relay": servers[i] if i < len(servers) else None,
                "our_rtt_ms": ours, "peer_rtt_ms": theirs, "delta_ms": delta,

                "_note": ("peer is closer to this relay than we are"
                          if delta < 0 else
                          "peer is farther from this relay than we are"),
            })

    levels = [(e["ts"], e.get("level")) for e in events
              if e.get("event") == "peer_audio_level"
              and (peer_ctx is None or e.get("ctx") == peer_ctx)]
    speech = None
    if levels:
        t0 = levels[0][0]
        vals = [v for _, v in levels if v is not None]
        loud = [v for v in vals if v > 0]
        speech = {
            "samples": len(levels),
            "approx_interval_ms": round((levels[-1][0] - t0) / max(1, len(levels) - 1)),
            "max_level": max(vals) if vals else None,
            "mean_level_while_speaking": round(sum(loud) / len(loud), 1) if loud else None,
            "silent_samples": len(vals) - len(loud),
            "series": [{"t_ms": t - t0, "level": v} for t, v in levels],
            "_note": "speech energy sampled by the client; zeros are silence",
        }

    platform = strings.get("call_peer_platform")
    for e in events:
        if e.get("event") == "peer_platform" and not platform:
            platform = e.get("platform")

    device_count = None
    for e in events:
        if e.get("event") == "peer_device_count" and e.get("device_count"):
            device_count = e.get("device_count")

    call_ids = []
    for e in events:
        if e.get("event") == "peer_offer_msg":
            call_ids.extend(e.get("strings") or [])

    medium_peer, medium_self = get("peer_call_network"), get("call_network")

    geo_ip, geo_source = None, None
    if public_eps:
        geo_ip = public_eps[0]["ip"]
        geo_source = "public_endpoint (unmasked)"
    elif strings.get("call_peer_ip_str"):
        geo_ip = strings.get("call_peer_ip_str")
        geo_source = "telemetry (masked /24)"
    geolocation = None
    if geo_ip and geo_lookup:
        geolocation = geolocate_ip(geo_ip)
        if isinstance(geolocation, dict):
            geolocation["source"] = geo_source

    return {
        "capture": {
            "events": len(events),
            "duration_s": round(duration_ms / 1000.0, 1),
            "numeric_fields": len(numeric),
            "string_fields": len(strings),
        },
        "peer": {
            "identity": {
                "platform": platform,
                "app_version": strings.get("call_peer_app_version"),
                "device_class": strings.get("device_class"),
                "hardware_year_class": get("peer_year_class_2016"),
                "linked_device_count": device_count,
                "_note": "platform from the 17-entry platform_to_cstr enum; "
                         "device count from multi_device_info_count",
            },
            "network": {
                "public_endpoints": [
                    dict(e, _note="server-reflexive candidate from call signalling "
                                  "— full address and port, not masked")
                    for e in public_eps],
                "private_endpoints": [
                    dict(e, _note="host candidate from the peer's own LAN or carrier "
                                  "NAT; delivered even when the two sides are on "
                                  "different networks")
                    for e in private_eps],
                "telemetry_view": {
                    "peer_public_ip_masked": strings.get("call_peer_ip_str"),
                    "peer_lan_prefix_masked": strings.get("peer_local_ip_prefix"),
                    "_note": "the telemetry path masks the peer address to /24 while "
                             "the signalling path above does not",
                },
                "geolocation": geolocation,
                "medium": {
                    "peer": medium_peer,
                    "peer_meaning": NETWORK_MEDIUM.get(int(medium_peer)) if medium_peer is not None else None,
                    "self": medium_self,
                    "self_meaning": NETWORK_MEDIUM.get(int(medium_self)) if medium_self is not None else None,
                },
                "nat": {
                    "symmetric": bool(get("is_in_sym_nat")) if get("is_in_sym_nat") is not None else None,
                    "ipv6_capable": bool(get("is_ipv6_capable")) if get("is_ipv6_capable") is not None else None,
                    "p2p_disabled": bool(get("call_p2p_disabled")) if get("call_p2p_disabled") is not None else None,
                    "_note": "p2p_disabled is the desktop equivalent of Android's "
                             "disallowAllP2P(). False means 'Protect IP address in "
                             "calls' was not in effect. Media going over a relay does "
                             "not imply the address was protected — candidates are "
                             "still exchanged either way.",
                },
            },
            "relays": {
                "servers": servers,
                "observed_candidates": [
                    dict(r, _note="Meta infrastructure — the relay, not the peer")
                    for r in relays],
                "latency": latency,
                "latency_usable": (None if degenerate is None else not degenerate),
                "latency_spread_ms": (round(max(peer_rtt) - min(peer_rtt), 1)
                                      if peer_rtt and not degenerate else None),
                "_note": "identical or negative peer values are placeholders; no "
                         "location inference can be drawn from them. A mixed "
                         "profile (closer to some relays, farther from others) "
                         "is more discriminating than a uniform one.",
            },
            "behaviour": {
                "speech_activity": speech,
                "silence_ms": get("dtx_rx_duration_t"),
                "silence_ratio_pct": (round(100.0 * get("dtx_rx_duration_t") / duration_ms, 1)
                                      if get("dtx_rx_duration_t") and duration_ms else None),
                "_note": "dtx_rx_duration_t is how long the peer transmitted nothing",
            },
            "fingerprint": {
                "frame_length_ms": get("avg_rx_frame_length_ms"),
                "decode_time_ms": get("avg_decode_t"),
                "jitter_buffer_ms": get("jb_avg_delay"),
                "uplink_bwe_bps": get("call_rx_avg_bwe"),
                "_note": "rx-side values describe what the peer produced",
            },
            "correlation": {
                "abtest_bucket": strings.get("call_peer_test_bucket"),
                "abtest_id_list": strings.get("call_peer_test_bucket_id_list"),
                "call_ids": call_ids,
                "_note": "the bucket id was identical across three calls to the same "
                         "device, so it links calls over a short window. It tracks the "
                         "DEVICE: another device on the same account gave a different "
                         "platform, version and LAN address.",
            },
        },
        "self": {
            "public_ip": strings.get("call_self_ip_str"),
            "lan_prefix": strings.get("local_ip_prefix"),
            "reflexive_ip": strings.get("signaling_reflexive_ip_self"),
            "_note": "included so peer values can be told apart from ours",
        },
        "participant_contexts": [
            {"ctx": ctx,
             "role": "peer" if ctx == peer_ctx else ("self" if peer_ctx else "unknown"),
             "device_count": entry.get("device_count"),
             "events": entry.get("events")}
            for ctx, entry in contexts.items()],
        "caveats": [
            "No JID or phone number exists on this layer — confirmed across three "
            "runs; the VoIP layer works with a call id instead.",
            "No location data in call signalling; relay latency is the only "
            "geographic proxy and it is not always a real measurement.",
            "battery_low is present in telemetry but which side it belongs to was "
            "never established.",
            "WAM hooks did not fire during calls, so the messaging surface is not "
            "covered here.",
        ],
    }

I18N = {
    "en": {
        "app.title": "WhatsApp Peer Capture",
        "app.subtitle": "Metadata observed from the other side of the call",
        "app.generated": "generated",
        "app.lang": "Language",
        "footer": "wa_peer.py - authorized research capture - data reflects a single call",
        "stat.events": "events", "stat.duration": "duration (s)",
        "stat.numeric": "numeric fields", "stat.strings": "string fields",
        "hl.public": "Peer public endpoint (unmasked, from call signalling)",
        "hl.telemetry": "Peer public IP (telemetry, masked to /24)",
        "hl.none_label": "Peer address", "hl.none_value": "not captured this run",
        "sec.identity": "Peer identity", "sec.mediumnat": "Network medium & NAT",
        "sec.public": "Public endpoints (unmasked)",
        "sec.private": "Private / host endpoints",
        "sec.telemetry": "Telemetry view (masked)",
        "sec.geo": "IP geolocation", "sec.map": "Location map",
        "sec.behaviour": "Behaviour", "sec.relays": "Relay servers",
        "sec.speech": "Speech activity", "sec.fingerprint": "RX fingerprint",
        "sec.correlation": "Correlation", "sec.self": "Our side (self)",
        "sec.callids": "Call IDs", "sec.caveats": "Caveats",
        "lbl.platform": "Platform", "lbl.appver": "App version",
        "lbl.devclass": "Device class", "lbl.hwyear": "Hardware year class",
        "lbl.linked": "Linked device count",
        "lbl.peer_medium": "Peer network medium",
        "lbl.self_medium": "Self network medium",
        "lbl.sym_nat": "Symmetric NAT", "lbl.ipv6": "IPv6 capable",
        "lbl.p2p": "P2P disabled (IP protected)",
        "lbl.pub_masked": "Peer public IP (masked /24)",
        "lbl.lan_masked": "Peer LAN prefix (masked)",
        "lbl.geo_source": "Source", "lbl.geo_ip": "IP", "lbl.city": "City",
        "lbl.region": "Region", "lbl.country": "Country",
        "lbl.zip": "Postal code", "lbl.coords": "Coordinates",
        "lbl.tz": "Timezone", "lbl.isp": "ISP", "lbl.org": "Organization",
        "lbl.asn": "AS / network",
        "lbl.silence_ms": "Silence (ms)", "lbl.silence_ratio": "Silence ratio (%)",
        "lbl.samples": "Samples", "lbl.interval": "Sample interval (ms)",
        "lbl.max_level": "Max level",
        "lbl.mean_level": "Mean level while speaking",
        "lbl.silent_samples": "Silent samples",
        "lbl.frame_len": "Avg frame length (ms)",
        "lbl.decode_t": "Avg decode time (ms)",
        "lbl.jitter": "Jitter buffer (ms)", "lbl.uplink": "Uplink BWE (bps)",
        "lbl.ab_bucket": "A/B test bucket", "lbl.ab_list": "A/B test id list",
        "lbl.pub_ip": "Public IP", "lbl.lan_prefix": "LAN prefix",
        "lbl.reflexive": "Reflexive IP", "lbl.servers": "servers",
        "th.ip": "IP", "th.port": "Port", "th.class": "Class",
        "th.relay": "Relay", "th.our_rtt": "Our RTT",
        "th.peer_rtt": "Peer RTT", "th.delta": "delta ms",
        "empty.none": "none captured", "empty.nodata": "no data captured",
        "empty.no_latency": "no usable latency samples",
        "empty.no_speech": "no speech-energy samples", "empty.none2": "none",
        "map.nogeo": "No location: no routable public IP was captured this run.",
        "map.error": "Location lookup failed or was skipped (--no-geo).",
        "map.offline": "Map tiles need an internet connection.",
        "value.medium0": "unclassified (connected, but type could not be determined)",
        "value.medium1": "cellular",
        "value.medium2": "not cellular (Wi-Fi, or Ethernet on a desktop peer)",
        "value.medium3": "no active network resolved when the stanza was composed",
        "value.class_unknown": "unknown", "value.class_ipv6": "ipv6",
        "value.class_private": "private (RFC1918)",
        "value.class_nat": "carrier-grade NAT (RFC6598)",
        "value.class_loopback": "loopback", "value.class_public": "public",
        "value.geo_public": "public_endpoint (unmasked)",
        "value.geo_telemetry": "telemetry (masked /24)",
        "value.true": "True", "value.false": "False",
        "error.invalid_ip": "invalid IP address",
        "error.reserved": "reserved / non-routable address",
        "error.lookup_failed": "lookup failed",
        "error.lookup_unsuccessful": "lookup unsuccessful",
        "cav.0": "No JID or phone number exists on this layer - confirmed across three runs; the VoIP layer works with a call id instead.",
        "cav.1": "No location data in call signalling; relay latency is the only geographic proxy and it is not always a real measurement.",
        "cav.2": "battery_low is present in telemetry but which side it belongs to was never established.",
        "cav.3": "WAM hooks did not fire during calls, so the messaging surface is not covered here.",
    },
    "tr": {
        "app.title": "WhatsApp Karşı Taraf Verisi Yakalama",
        "app.subtitle": "Aramanın karşı tarafından gözlemlenen üstveri",
        "app.generated": "oluşturuldu",
        "app.lang": "Dil",
        "footer": "wa_peer.py - yetkili araştırma kaydı - veriler tek bir aramayı yansıtır",
        "stat.events": "olay", "stat.duration": "süre (sn)",
        "stat.numeric": "sayısal alan", "stat.strings": "metin alanı",
        "hl.public": "Karşı tarafın genel uç noktası (maskesiz, arama sinyalleşmesinden)",
        "hl.telemetry": "Karşı tarafın genel IP adresi (telemetri, /24 maskeli)",
        "hl.none_label": "Karşı taraf adresi",
        "hl.none_value": "bu çalışmada yakalanmadı",
        "sec.identity": "Karşı tarafın kimliği", "sec.mediumnat": "Ağ türü ve NAT",
        "sec.public": "Genel uç noktalar (maskesiz)",
        "sec.private": "Özel / yerel uç noktalar",
        "sec.telemetry": "Telemetri görünümü (maskeli)",
        "sec.geo": "IP coğrafi konumu", "sec.map": "Konum haritası",
        "sec.behaviour": "Davranış", "sec.relays": "Aktarma sunucuları",
        "sec.speech": "Konuşma etkinliği", "sec.fingerprint": "Alım parmak izi",
        "sec.correlation": "İlişkilendirme", "sec.self": "Bizim taraf",
        "sec.callids": "Arama kimlikleri", "sec.caveats": "Sınırlamalar",
        "lbl.platform": "Platform", "lbl.appver": "Uygulama sürümü",
        "lbl.devclass": "Cihaz sınıfı", "lbl.hwyear": "Donanım yılı sınıfı",
        "lbl.linked": "Bağlı cihaz sayısı",
        "lbl.peer_medium": "Karşı tarafın ağ türü",
        "lbl.self_medium": "Bizim ağ türümüz",
        "lbl.sym_nat": "Simetrik NAT", "lbl.ipv6": "IPv6 destekli",
        "lbl.p2p": "P2P kapalı (IP korunuyor)",
        "lbl.pub_masked": "Karşı tarafın genel IP adresi (maskeli /24)",
        "lbl.lan_masked": "Karşı tarafın yerel ağ öneki (maskeli)",
        "lbl.geo_source": "Kaynak", "lbl.geo_ip": "IP", "lbl.city": "Şehir",
        "lbl.region": "Bölge", "lbl.country": "Ülke",
        "lbl.zip": "Posta kodu", "lbl.coords": "Koordinatlar",
        "lbl.tz": "Saat dilimi", "lbl.isp": "İnternet sağlayıcısı",
        "lbl.org": "Kuruluş", "lbl.asn": "AS / ağ",
        "lbl.silence_ms": "Sessizlik (ms)", "lbl.silence_ratio": "Sessizlik oranı (%)",
        "lbl.samples": "Örnek sayısı", "lbl.interval": "Örnek aralığı (ms)",
        "lbl.max_level": "En yüksek seviye",
        "lbl.mean_level": "Konuşurken ortalama seviye",
        "lbl.silent_samples": "Sessiz örnekler",
        "lbl.frame_len": "Ort. çerçeve uzunluğu (ms)",
        "lbl.decode_t": "Ort. çözme süresi (ms)",
        "lbl.jitter": "Jitter tamponu (ms)", "lbl.uplink": "Yukarı yönlü BWE (bps)",
        "lbl.ab_bucket": "A/B test grubu", "lbl.ab_list": "A/B test kimliği listesi",
        "lbl.pub_ip": "Genel IP", "lbl.lan_prefix": "Yerel ağ öneki",
        "lbl.reflexive": "Yansıtıcı IP", "lbl.servers": "sunucular",
        "th.ip": "IP", "th.port": "Port", "th.class": "Sınıf",
        "th.relay": "Aktarma", "th.our_rtt": "Bizim RTT",
        "th.peer_rtt": "Karşı tarafın RTT değeri", "th.delta": "fark (ms)",
        "empty.none": "yakalanmadı", "empty.nodata": "veri yakalanmadı",
        "empty.no_latency": "kullanılabilir gecikme örneği yok",
        "empty.no_speech": "konuşma enerjisi örneği yok", "empty.none2": "yok",
        "map.nogeo": "Konum yok: bu çalışmada yönlendirilebilir genel IP yakalanmadı.",
        "map.error": "Konum sorgusu başarısız oldu veya atlandı (--no-geo).",
        "map.offline": "Harita döşemeleri için internet bağlantısı gerekir.",
        "value.medium0": "sınıflandırılmamış (bağlı, ancak ağ türü belirlenemedi)",
        "value.medium1": "hücresel ağ",
        "value.medium2": "hücresel olmayan ağ (Wi-Fi veya masaüstünde Ethernet)",
        "value.medium3": "mesaj oluşturulurken etkin ağ belirlenemedi",
        "value.class_unknown": "bilinmiyor", "value.class_ipv6": "IPv6",
        "value.class_private": "özel (RFC1918)",
        "value.class_nat": "operatör düzeyinde NAT (RFC6598)",
        "value.class_loopback": "yerel döngü", "value.class_public": "genel",
        "value.geo_public": "genel uç nokta (maskesiz)",
        "value.geo_telemetry": "telemetri (maskeli /24)",
        "value.true": "Evet", "value.false": "Hayır",
        "error.invalid_ip": "geçersiz IP adresi",
        "error.reserved": "ayrılmış / yönlendirilemeyen adres",
        "error.lookup_failed": "sorgu başarısız",
        "error.lookup_unsuccessful": "sorgu sonuçlanmadı",
        "cav.0": "Bu katmanda JID veya telefon numarası yok; üç çalışmada doğrulandı. VoIP katmanı bunun yerine arama kimliği kullanır.",
        "cav.1": "Arama sinyalleşmesinde konum verisi yok. Aktarma gecikmesi tek coğrafi göstergedir ve her zaman gerçek bir ölçüm değildir.",
        "cav.2": "Telemetride battery_low bulunuyor, ancak hangi tarafa ait olduğu belirlenemedi.",
        "cav.3": "Aramalar sırasında WAM kancaları tetiklenmedi; bu nedenle mesajlaşma katmanı burada kapsanmıyor.",
    },
    "ru": {
        "app.title": "WhatsApp: перехват данных собеседника",
        "app.subtitle": "Метаданные, наблюдаемые со стороны собеседника вызова",
        "app.generated": "создано",
        "app.lang": "Язык",
        "footer": "wa_peer.py - авторизованный исследовательский захват - данные отражают один вызов",
        "stat.events": "события", "stat.duration": "длительность (с)",
        "stat.numeric": "числовые поля", "stat.strings": "строковые поля",
        "hl.public": "Публичная точка собеседника (без маски, из сигнализации вызова)",
        "hl.telemetry": "Публичный IP собеседника (телеметрия, маска /24)",
        "hl.none_label": "Адрес собеседника",
        "hl.none_value": "в этом запуске не захвачен",
        "sec.identity": "Идентификация собеседника", "sec.mediumnat": "Сетевая среда и NAT",
        "sec.public": "Публичные точки (без маски)",
        "sec.private": "Частные / хостовые точки",
        "sec.telemetry": "Телеметрия (с маской)",
        "sec.geo": "Геолокация по IP", "sec.map": "Карта местоположения",
        "sec.behaviour": "Поведение", "sec.relays": "Ретрансляторы",
        "sec.speech": "Речевая активность", "sec.fingerprint": "Отпечаток приёма",
        "sec.correlation": "Корреляция", "sec.self": "Наша сторона (self)",
        "sec.callids": "Идентификаторы вызова", "sec.caveats": "Оговорки",
        "lbl.platform": "Платформа", "lbl.appver": "Версия приложения",
        "lbl.devclass": "Класс устройства", "lbl.hwyear": "Год класса оборудования",
        "lbl.linked": "Число связанных устройств",
        "lbl.peer_medium": "Сетевая среда собеседника",
        "lbl.self_medium": "Наша сетевая среда",
        "lbl.sym_nat": "Симметричный NAT", "lbl.ipv6": "Поддержка IPv6",
        "lbl.p2p": "P2P отключён (IP защищён)",
        "lbl.pub_masked": "Публичный IP собеседника (маска /24)",
        "lbl.lan_masked": "Префикс LAN собеседника (с маской)",
        "lbl.geo_source": "Источник", "lbl.geo_ip": "IP", "lbl.city": "Город",
        "lbl.region": "Регион", "lbl.country": "Страна",
        "lbl.zip": "Почтовый индекс", "lbl.coords": "Координаты",
        "lbl.tz": "Часовой пояс", "lbl.isp": "Провайдер",
        "lbl.org": "Организация", "lbl.asn": "AS / сеть",
        "lbl.silence_ms": "Тишина (мс)", "lbl.silence_ratio": "Доля тишины (%)",
        "lbl.samples": "Отсчёты", "lbl.interval": "Интервал отсчётов (мс)",
        "lbl.max_level": "Макс. уровень",
        "lbl.mean_level": "Средний уровень при речи",
        "lbl.silent_samples": "Тихие отсчёты",
        "lbl.frame_len": "Сред. длина кадра (мс)",
        "lbl.decode_t": "Сред. время декодирования (мс)",
        "lbl.jitter": "Буфер джиттера (мс)", "lbl.uplink": "Восходящий BWE (бит/с)",
        "lbl.ab_bucket": "Группа A/B-теста", "lbl.ab_list": "Список ID A/B-теста",
        "lbl.pub_ip": "Публичный IP", "lbl.lan_prefix": "Префикс LAN",
        "lbl.reflexive": "Рефлексивный IP", "lbl.servers": "серверы",
        "th.ip": "IP", "th.port": "Порт", "th.class": "Класс",
        "th.relay": "Ретранслятор", "th.our_rtt": "Наш RTT",
        "th.peer_rtt": "RTT собеседника", "th.delta": "разн. мс",
        "empty.none": "не захвачено", "empty.nodata": "данные не захвачены",
        "empty.no_latency": "нет пригодных отсчётов задержки",
        "empty.no_speech": "нет отсчётов энергии речи", "empty.none2": "нет",
        "map.nogeo": "Нет местоположения: маршрутизируемый публичный IP в этом запуске не захвачен.",
        "map.error": "Запрос местоположения не удался или пропущен (--no-geo).",
        "map.offline": "Для плиток карты нужно интернет-соединение.",
        "cav.0": "На этом уровне нет JID или номера телефона - подтверждено в трёх запусках; уровень VoIP использует идентификатор вызова.",
        "cav.1": "В сигнализации вызова нет данных о местоположении; задержка ретранслятора - единственный географический ориентир и не всегда реальное измерение.",
        "cav.2": "В телеметрии присутствует battery_low, но к какой стороне он относится, установить не удалось.",
        "cav.3": "Хуки WAM не срабатывали во время вызовов, поэтому уровень обмена сообщениями здесь не охвачен.",
    },
    "ar": {
        "app.title": "التقاط بيانات الطرف الآخر في واتساب",
        "app.subtitle": "بيانات وصفية مرصودة من الطرف الآخر في المكالمة",
        "app.generated": "تم الإنشاء",
        "app.lang": "اللغة",
        "footer": "wa_peer.py - التقاط بحثي مصرّح به - تعكس البيانات مكالمة واحدة",
        "stat.events": "أحداث", "stat.duration": "المدة (ث)",
        "stat.numeric": "حقول رقمية", "stat.strings": "حقول نصية",
        "hl.public": "نقطة الطرف الآخر العامة (غير مقنّعة، من إشارات المكالمة)",
        "hl.telemetry": "عنوان IP العام للطرف الآخر (قياس عن بعد، مقنّع إلى /24)",
        "hl.none_label": "عنوان الطرف الآخر",
        "hl.none_value": "لم يُلتقط في هذه الجلسة",
        "sec.identity": "هوية الطرف الآخر", "sec.mediumnat": "وسط الشبكة و NAT",
        "sec.public": "النقاط العامة (غير مقنّعة)",
        "sec.private": "النقاط الخاصة / المضيفة",
        "sec.telemetry": "عرض القياس عن بعد (مقنّع)",
        "sec.geo": "تحديد الموقع عبر IP", "sec.map": "خريطة الموقع",
        "sec.behaviour": "السلوك", "sec.relays": "خوادم الترحيل",
        "sec.speech": "نشاط الكلام", "sec.fingerprint": "بصمة الاستقبال",
        "sec.correlation": "الربط", "sec.self": "جانبنا (self)",
        "sec.callids": "معرّفات المكالمة", "sec.caveats": "ملاحظات تحذيرية",
        "lbl.platform": "المنصة", "lbl.appver": "إصدار التطبيق",
        "lbl.devclass": "فئة الجهاز", "lbl.hwyear": "فئة سنة العتاد",
        "lbl.linked": "عدد الأجهزة المرتبطة",
        "lbl.peer_medium": "وسط شبكة الطرف الآخر",
        "lbl.self_medium": "وسط شبكتنا",
        "lbl.sym_nat": "NAT متماثل", "lbl.ipv6": "يدعم IPv6",
        "lbl.p2p": "P2P معطّل (IP محمي)",
        "lbl.pub_masked": "IP العام للطرف الآخر (مقنّع /24)",
        "lbl.lan_masked": "بادئة الشبكة المحلية للطرف الآخر (مقنّعة)",
        "lbl.geo_source": "المصدر", "lbl.geo_ip": "IP", "lbl.city": "المدينة",
        "lbl.region": "المنطقة", "lbl.country": "الدولة",
        "lbl.zip": "الرمز البريدي", "lbl.coords": "الإحداثيات",
        "lbl.tz": "المنطقة الزمنية", "lbl.isp": "مزوّد الخدمة",
        "lbl.org": "المؤسسة", "lbl.asn": "AS / الشبكة",
        "lbl.silence_ms": "الصمت (مللي ثانية)", "lbl.silence_ratio": "نسبة الصمت (%)",
        "lbl.samples": "العيّنات", "lbl.interval": "فاصل العيّنة (مللي ثانية)",
        "lbl.max_level": "أعلى مستوى",
        "lbl.mean_level": "متوسط المستوى أثناء الكلام",
        "lbl.silent_samples": "عيّنات صامتة",
        "lbl.frame_len": "متوسط طول الإطار (مللي ثانية)",
        "lbl.decode_t": "متوسط زمن فك الترميز (مللي ثانية)",
        "lbl.jitter": "مخزّن الارتعاش (مللي ثانية)", "lbl.uplink": "BWE الصاعد (بت/ث)",
        "lbl.ab_bucket": "مجموعة اختبار A/B", "lbl.ab_list": "قائمة معرّفات اختبار A/B",
        "lbl.pub_ip": "IP العام", "lbl.lan_prefix": "بادئة الشبكة المحلية",
        "lbl.reflexive": "IP الانعكاسي", "lbl.servers": "الخوادم",
        "th.ip": "IP", "th.port": "المنفذ", "th.class": "الفئة",
        "th.relay": "الترحيل", "th.our_rtt": "RTT لدينا",
        "th.peer_rtt": "RTT للطرف الآخر", "th.delta": "الفرق مللي ثانية",
        "empty.none": "لم يُلتقط شيء", "empty.nodata": "لم تُلتقط بيانات",
        "empty.no_latency": "لا توجد عيّنات زمن استجابة صالحة",
        "empty.no_speech": "لا توجد عيّنات طاقة كلام", "empty.none2": "لا شيء",
        "map.nogeo": "لا يوجد موقع: لم يُلتقط عنوان IP عام قابل للتوجيه في هذه الجلسة.",
        "map.error": "فشل البحث عن الموقع أو تم تخطيه (--no-geo).",
        "map.offline": "بلاطات الخريطة تحتاج إلى اتصال بالإنترنت.",
        "cav.0": "لا يوجد JID أو رقم هاتف في هذه الطبقة - تأكّد عبر ثلاث جلسات؛ تستخدم طبقة VoIP معرّف مكالمة بدلاً من ذلك.",
        "cav.1": "لا توجد بيانات موقع في إشارات المكالمة؛ زمن استجابة الترحيل هو المؤشر الجغرافي الوحيد وليس دائماً قياساً حقيقياً.",
        "cav.2": "يوجد battery_low في القياس عن بعد لكن لم يُحدَّد الطرف الذي يخصّه.",
        "cav.3": "لم تُفعَّل خطافات WAM أثناء المكالمات، لذا لا تُغطّى طبقة المراسلة هنا.",
    },
    "zh": {
        "app.title": "WhatsApp 对端数据捕获",
        "app.subtitle": "从通话另一端观察到的元数据",
        "app.generated": "生成于",
        "app.lang": "语言",
        "footer": "wa_peer.py - 授权研究性捕获 - 数据反映单次通话",
        "stat.events": "事件", "stat.duration": "时长（秒）",
        "stat.numeric": "数值字段", "stat.strings": "字符串字段",
        "hl.public": "对端公网端点（未掩码，来自通话信令）",
        "hl.telemetry": "对端公网 IP（遥测，掩码至 /24）",
        "hl.none_label": "对端地址",
        "hl.none_value": "本次运行未捕获",
        "sec.identity": "对端身份", "sec.mediumnat": "网络介质与 NAT",
        "sec.public": "公网端点（未掩码）",
        "sec.private": "私有 / 主机端点",
        "sec.telemetry": "遥测视图（掩码）",
        "sec.geo": "IP 地理定位", "sec.map": "位置地图",
        "sec.behaviour": "行为", "sec.relays": "中继服务器",
        "sec.speech": "语音活动", "sec.fingerprint": "接收端指纹",
        "sec.correlation": "关联", "sec.self": "我方（self）",
        "sec.callids": "通话 ID", "sec.caveats": "注意事项",
        "lbl.platform": "平台", "lbl.appver": "应用版本",
        "lbl.devclass": "设备等级", "lbl.hwyear": "硬件年份等级",
        "lbl.linked": "关联设备数",
        "lbl.peer_medium": "对端网络介质",
        "lbl.self_medium": "我方网络介质",
        "lbl.sym_nat": "对称 NAT", "lbl.ipv6": "支持 IPv6",
        "lbl.p2p": "P2P 已禁用（IP 受保护）",
        "lbl.pub_masked": "对端公网 IP（掩码 /24）",
        "lbl.lan_masked": "对端局域网前缀（掩码）",
        "lbl.geo_source": "来源", "lbl.geo_ip": "IP", "lbl.city": "城市",
        "lbl.region": "地区", "lbl.country": "国家",
        "lbl.zip": "邮政编码", "lbl.coords": "坐标",
        "lbl.tz": "时区", "lbl.isp": "运营商",
        "lbl.org": "组织", "lbl.asn": "AS / 网络",
        "lbl.silence_ms": "静音（毫秒）", "lbl.silence_ratio": "静音比例（%）",
        "lbl.samples": "采样数", "lbl.interval": "采样间隔（毫秒）",
        "lbl.max_level": "最大电平",
        "lbl.mean_level": "讲话时平均电平",
        "lbl.silent_samples": "静音采样",
        "lbl.frame_len": "平均帧长（毫秒）",
        "lbl.decode_t": "平均解码时间（毫秒）",
        "lbl.jitter": "抖动缓冲（毫秒）", "lbl.uplink": "上行 BWE（比特/秒）",
        "lbl.ab_bucket": "A/B 测试分组", "lbl.ab_list": "A/B 测试 ID 列表",
        "lbl.pub_ip": "公网 IP", "lbl.lan_prefix": "局域网前缀",
        "lbl.reflexive": "反射 IP", "lbl.servers": "服务器",
        "th.ip": "IP", "th.port": "端口", "th.class": "类别",
        "th.relay": "中继", "th.our_rtt": "我方 RTT",
        "th.peer_rtt": "对端 RTT", "th.delta": "差值 毫秒",
        "empty.none": "未捕获", "empty.nodata": "未捕获数据",
        "empty.no_latency": "无可用延迟采样",
        "empty.no_speech": "无语音能量采样", "empty.none2": "无",
        "map.nogeo": "无位置：本次运行未捕获可路由的公网 IP。",
        "map.error": "位置查询失败或已跳过（--no-geo）。",
        "map.offline": "地图瓦片需要互联网连接。",
        "cav.0": "此层不存在 JID 或电话号码 - 经三次运行确认；VoIP 层改用通话 ID。",
        "cav.1": "通话信令中无位置数据；中继延迟是唯一的地理代理指标，且并非总是真实测量值。",
        "cav.2": "遥测中存在 battery_low，但始终无法确定其归属于哪一方。",
        "cav.3": "通话期间 WAM 挂钩未触发，因此此处不涵盖消息传递层。",
    },
}


def _t_tr(key):
    return I18N["tr"].get(key, key)


_UI_MEDIUM_KEYS = {
    NETWORK_MEDIUM[0]: "value.medium0",
    NETWORK_MEDIUM[1]: "value.medium1",
    NETWORK_MEDIUM[2]: "value.medium2",
    NETWORK_MEDIUM[3]: "value.medium3",
}
_UI_ADDRESS_KEYS = {
    "unknown": "value.class_unknown",
    "ipv6": "value.class_ipv6",
    "private (RFC1918)": "value.class_private",
    "carrier-grade NAT (RFC6598)": "value.class_nat",
    "loopback": "value.class_loopback",
    "public": "value.class_public",
}
_UI_GEO_SOURCE_KEYS = {
    "public_endpoint (unmasked)": "value.geo_public",
    "telemetry (masked /24)": "value.geo_telemetry",
}
_UI_BOOLEAN_KEYS = {True: "value.true", False: "value.false"}
UI_FIELD_VALUE_KEYS = {
    "lbl.peer_medium": _UI_MEDIUM_KEYS,
    "lbl.self_medium": _UI_MEDIUM_KEYS,
    "address_class": _UI_ADDRESS_KEYS,
    "lbl.geo_source": _UI_GEO_SOURCE_KEYS,
    "lbl.sym_nat": _UI_BOOLEAN_KEYS,
    "lbl.ipv6": _UI_BOOLEAN_KEYS,
    "lbl.p2p": _UI_BOOLEAN_KEYS,
}


def _ui_value(value, field=None):
    field_keys = UI_FIELD_VALUE_KEYS.get(field)
    key = (field_keys.get(value) if field_keys is not None
           and isinstance(value, (str, bool)) else None)
    if key:
        return '<span class="v" data-i18n-value="%s">%s</span>' % (
            key, _esc(_t_tr(key)))
    return '<span class="v">%s</span>' % _esc(value)


def _esc(v):
    if v is None or v == "":
        return "&mdash;"
    return html_mod.escape(str(v))


def _script_json(value):
    """Encode JSON safely inside an HTML script element."""
    return (json.dumps(value, ensure_ascii=True)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace(chr(0x2028), "\\u2028")
            .replace(chr(0x2029), "\\u2029"))


def _geo_error_ui(error):
    if not isinstance(error, str):
        return _esc(error)
    if error == "invalid IP address":
        key, detail = "error.invalid_ip", ""
    elif error == "reserved / non-routable address":
        key, detail = "error.reserved", ""
    elif error == "lookup unsuccessful":
        key, detail = "error.lookup_unsuccessful", ""
    elif error.startswith("lookup failed: "):
        key, detail = "error.lookup_failed", error[len("lookup failed"):]
    else:
        return _esc(error)
    return '<span data-i18n-value="%s">%s</span>%s' % (
        key, _esc(_t_tr(key)), _esc(detail))


def _rows(pairs):
    """pairs: list of (i18n_key, value). Skips rows whose value is None/''.

    Turkish text is the no-JS fallback; the client-side switcher applies the
    selected language after the page loads.
    """
    out = []
    for key, value in pairs:
        if value is None or value == "":
            continue
        out.append(
            '<div class="row"><span class="k" data-i18n="%s">%s</span>'
            '%s</div>'
            % (key, _esc(_t_tr(key)), _ui_value(value, key)))
    return out and "".join(out) or (
        '<div class="empty" data-i18n="empty.nodata">%s</div>'
        % _esc(_t_tr("empty.nodata")))


def render_html(report):
    peer = report.get("peer", {})
    ident = peer.get("identity", {})
    net = peer.get("network", {})
    relays = peer.get("relays", {})
    behaviour = peer.get("behaviour", {})
    fp = peer.get("fingerprint", {})
    corr = peer.get("correlation", {})
    selfd = report.get("self", {})
    cap = report.get("capture", {})

    public_eps = net.get("public_endpoints", []) or []
    private_eps = net.get("private_endpoints", []) or []
    tele = net.get("telemetry_view", {}) or {}
    medium = net.get("medium", {}) or {}
    nat = net.get("nat", {}) or {}
    geo = net.get("geolocation") or {}

    headline_ip, headline_key = None, None
    if public_eps:
        headline_ip = "%s:%s" % (public_eps[0].get("ip"), public_eps[0].get("port"))
        headline_key = "hl.public"
    elif tele.get("peer_public_ip_masked"):
        headline_ip = tele.get("peer_public_ip_masked")
        headline_key = "hl.telemetry"

    if headline_ip:
        headline_block = (
            '<div class="headline"><div class="hl-label" data-i18n="%s">%s</div>'
            '<div class="hl-ip">%s</div></div>'
            % (headline_key, _esc(_t_tr(headline_key)), _esc(headline_ip)))
    else:
        headline_block = (
            '<div class="headline none">'
            '<div class="hl-label" data-i18n="hl.none_label">%s</div>'
            '<div class="hl-ip" data-i18n="hl.none_value">%s</div></div>'
            % (_esc(_t_tr("hl.none_label")), _esc(_t_tr("hl.none_value"))))

    def ep_table(eps):
        if not eps:
            return ('<div class="empty" data-i18n="empty.none">%s</div>'
                    % _esc(_t_tr("empty.none")))
        body = "".join(
            '<tr><td class="mono">%s</td><td class="mono">%s</td><td>%s</td></tr>'
            % (_esc(e.get("ip")), _esc(e.get("port")),
               _ui_value(e.get("address_class"), "address_class"))
            for e in eps)
        return ('<table><thead><tr>'
                '<th data-i18n="th.ip">%s</th>'
                '<th data-i18n="th.port">%s</th>'
                '<th data-i18n="th.class">%s</th>'
                '</tr></thead><tbody>%s</tbody></table>'
                % (_esc(_t_tr("th.ip")), _esc(_t_tr("th.port")),
                   _esc(_t_tr("th.class")), body))

    latency = relays.get("latency", []) or []
    if latency:
        lat_body = "".join(
            '<tr><td class="mono">%s</td><td>%s</td><td>%s</td>'
            '<td class="%s">%s</td></tr>' % (
                _esc(l.get("relay")), _esc(l.get("our_rtt_ms")),
                _esc(l.get("peer_rtt_ms")),
                "neg" if (l.get("delta_ms") or 0) < 0 else "pos",
                _esc(l.get("delta_ms")))
            for l in latency)
        lat_html = ('<table><thead><tr>'
                    '<th data-i18n="th.relay">%s</th>'
                    '<th data-i18n="th.our_rtt">%s</th>'
                    '<th data-i18n="th.peer_rtt">%s</th>'
                    '<th data-i18n="th.delta">%s</th>'
                    '</tr></thead><tbody>%s</tbody></table>'
                    % (_esc(_t_tr("th.relay")), _esc(_t_tr("th.our_rtt")),
                       _esc(_t_tr("th.peer_rtt")), _esc(_t_tr("th.delta")), lat_body))
    else:
        lat_html = ('<div class="empty" data-i18n="empty.no_latency">%s</div>'
                    % _esc(_t_tr("empty.no_latency")))

    speech = behaviour.get("speech_activity")
    if speech:
        speech_html = _rows([
            ("lbl.samples", speech.get("samples")),
            ("lbl.interval", speech.get("approx_interval_ms")),
            ("lbl.max_level", speech.get("max_level")),
            ("lbl.mean_level", speech.get("mean_level_while_speaking")),
            ("lbl.silent_samples", speech.get("silent_samples")),
        ])
    else:
        speech_html = ('<div class="empty" data-i18n="empty.no_speech">%s</div>'
                       % _esc(_t_tr("empty.no_speech")))

    call_ids = corr.get("call_ids") or []
    call_ids_html = ("".join('<span class="chip">%s</span>' % _esc(c) for c in call_ids)
                     if call_ids else
                     '<div class="empty" data-i18n="empty.none2">%s</div>'
                     % _esc(_t_tr("empty.none2")))

    if geo and not geo.get("error"):
        coords = None
        if geo.get("lat") is not None and geo.get("lon") is not None:
            coords = "%s, %s" % (geo.get("lat"), geo.get("lon"))
        geo_html = _rows([
            ("lbl.geo_source", geo.get("source")),
            ("lbl.geo_ip", geo.get("query")),
            ("lbl.city", geo.get("city")),
            ("lbl.region", geo.get("regionName")),
            ("lbl.country", "%s (%s)" % (geo.get("country"), geo.get("countryCode"))
             if geo.get("country") else None),
            ("lbl.zip", geo.get("zip")),
            ("lbl.coords", coords),
            ("lbl.tz", geo.get("timezone")),
            ("lbl.isp", geo.get("isp")),
            ("lbl.org", geo.get("org")),
            ("lbl.asn", geo.get("as")),
        ])
    elif geo and geo.get("error"):
        geo_html = ('<div class="empty">%s &mdash; %s</div>'
                    % (_esc(geo.get("query")), _geo_error_ui(geo.get("error"))))
    else:
        geo_html = ('<div class="empty" data-i18n="map.nogeo">%s</div>'
                    % _esc(_t_tr("map.nogeo")))

    if geo and not geo.get("error") and geo.get("lat") is not None \
            and geo.get("lon") is not None:
        label_bits = [b for b in (geo.get("city"), geo.get("country")) if b]
        label = ", ".join(label_bits) or geo.get("query") or ""
        if geo.get("query"):
            label = ("%s (%s)" % (label, geo.get("query"))).strip()
        map_cfg = {"state": "ok", "lat": geo.get("lat"), "lon": geo.get("lon"),
                   "label": label}
    elif geo and geo.get("error"):
        map_cfg = {"state": "error"}
    else:
        map_cfg = {"state": "nogeo"}

    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    caveats = report.get("caveats", []) or []
    caveats_html = "".join(
        '<li data-i18n="cav.%d">%s</li>' % (
            i, _esc(I18N["tr"].get("cav.%d" % i, c)))
        for i, c in enumerate(caveats))

    return HTML_TEMPLATE % {
        "i18n_json": _script_json(I18N),
        "map_config": _script_json(map_cfg),
        "leaflet_css": ('<link rel="stylesheet" '
                        'href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" '
                        'integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" '
                        'crossorigin="">'
                        if map_cfg["state"] == "ok" else ""),
        "leaflet_js": ('<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" '
                       'integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" '
                       'crossorigin=""></script>'
                       if map_cfg["state"] == "ok" else ""),
        "generated": _esc(generated),
        "events": _esc(cap.get("events")),
        "duration": _esc(cap.get("duration_s")),
        "numeric": _esc(cap.get("numeric_fields")),
        "strings": _esc(cap.get("string_fields")),
        "headline": headline_block,
        "identity": _rows([
            ("lbl.platform", ident.get("platform")),
            ("lbl.appver", ident.get("app_version")),
            ("lbl.devclass", ident.get("device_class")),
            ("lbl.hwyear", ident.get("hardware_year_class")),
            ("lbl.linked", ident.get("linked_device_count")),
        ]),
        "public_eps": ep_table(public_eps),
        "private_eps": ep_table(private_eps),
        "telemetry": _rows([
            ("lbl.pub_masked", tele.get("peer_public_ip_masked")),
            ("lbl.lan_masked", tele.get("peer_lan_prefix_masked")),
        ]),
        "geo": geo_html,
        "medium_nat": _rows([
            ("lbl.peer_medium", medium.get("peer_meaning")),
            ("lbl.self_medium", medium.get("self_meaning")),
            ("lbl.sym_nat", nat.get("symmetric")),
            ("lbl.ipv6", nat.get("ipv6_capable")),
            ("lbl.p2p", nat.get("p2p_disabled")),
        ]),
        "servers": (", ".join(relays.get("servers", []))
                    if relays.get("servers") else None) or "&mdash;",
        "latency": lat_html,
        "speech": speech_html,
        "behaviour": _rows([
            ("lbl.silence_ms", behaviour.get("silence_ms")),
            ("lbl.silence_ratio", behaviour.get("silence_ratio_pct")),
        ]),
        "fingerprint": _rows([
            ("lbl.frame_len", fp.get("frame_length_ms")),
            ("lbl.decode_t", fp.get("decode_time_ms")),
            ("lbl.jitter", fp.get("jitter_buffer_ms")),
            ("lbl.uplink", fp.get("uplink_bwe_bps")),
        ]),
        "correlation": _rows([
            ("lbl.ab_bucket", corr.get("abtest_bucket")),
            ("lbl.ab_list", corr.get("abtest_id_list")),
        ]),
        "call_ids": call_ids_html,
        "self": _rows([
            ("lbl.pub_ip", selfd.get("public_ip")),
            ("lbl.lan_prefix", selfd.get("lan_prefix")),
            ("lbl.reflexive", selfd.get("reflexive_ip")),
        ]),
        "caveats": caveats_html,
    }


HTML_TEMPLATE = """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WhatsApp Karşı Taraf Verisi Yakalama</title>
%(leaflet_css)s
<style>
  :root{
    --bg:#0b0e13; --panel:#151b24; --panel2:#1b2330; --border:#28313d;
    --text:#e7edf5; --muted:#8b97a7; --accent:#25d366; --accent2:#34b7f1;
    --neg:#3fb950; --pos:#d29922;
    --shadow:0 1px 0 rgba(255,255,255,.03),0 8px 24px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box}
  html,body{scroll-behavior:smooth}
  body{margin:0;background:
      radial-gradient(1200px 600px at 80%% -10%%,rgba(52,183,241,.10),transparent 60%%),
      radial-gradient(900px 500px at -10%% 10%%,rgba(37,211,102,.10),transparent 55%%),
      var(--bg);
    color:var(--text);min-height:100vh;
    font:15px/1.55 "Segoe UI",Roboto,Helvetica,Arial,"Noto Sans Arabic",
      "Microsoft YaHei","PingFang SC",sans-serif;
    padding:28px 16px}
  .wrap{max-width:1040px;margin:0 auto}
  .topbar{display:flex;align-items:center;justify-content:space-between;
    gap:16px;flex-wrap:wrap;margin-bottom:6px}
  .brand{display:flex;align-items:center;gap:13px}
  .logo{width:42px;height:42px;border-radius:12px;flex:none;
    background:linear-gradient(135deg,var(--accent),var(--accent2));
    display:flex;align-items:center;justify-content:center;box-shadow:var(--shadow)}
  h1{font-size:22px;margin:0;font-weight:650;letter-spacing:.2px}
  .sub{color:var(--muted);font-size:13px;margin:3px 0 0}
  .langbox{display:flex;align-items:center;gap:8px}
  .langbox label{color:var(--muted);font-size:12px;text-transform:uppercase;
    letter-spacing:.06em}
  select#lang{background:var(--panel2);color:var(--text);
    border:1px solid var(--border);border-radius:9px;padding:8px 12px;
    font-size:14px;cursor:pointer;outline:none}
  select#lang:hover{border-color:var(--accent2)}
  .stat-row{display:flex;gap:14px;flex-wrap:wrap;margin:22px 0}
  .stat{background:var(--panel);border:1px solid var(--border);border-radius:12px;
    padding:12px 18px;min-width:130px;box-shadow:var(--shadow)}
  .stat .n{font-size:22px;font-weight:650}
  .stat .l{color:var(--muted);font-size:11px;text-transform:uppercase;
    letter-spacing:.05em;margin-top:2px}
  .headline{background:linear-gradient(135deg,#12261b,#0f1f2b);
    border:1px solid var(--border);border-radius:16px;padding:22px 24px;
    margin-bottom:20px;box-shadow:var(--shadow);position:relative;overflow:hidden}
  .headline:before{content:"";position:absolute;inset:0;
    background:linear-gradient(135deg,rgba(37,211,102,.08),transparent 55%%);
    pointer-events:none}
  .headline.none{background:var(--panel)}
  .hl-label{color:var(--muted);font-size:12px;text-transform:uppercase;
    letter-spacing:.06em;margin-bottom:8px}
  .hl-ip{font:600 30px/1.15 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    color:var(--accent);word-break:break-all}
  .headline.none .hl-ip{color:var(--muted);font-size:20px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));
    gap:16px}
  .card{background:var(--panel);border:1px solid var(--border);
    border-radius:16px;padding:18px 20px;box-shadow:var(--shadow);
    transition:border-color .15s ease,transform .15s ease}
  .card:hover{border-color:#33414f}
  .card.full{grid-column:1/-1}
  .card h2{font-size:12px;text-transform:uppercase;letter-spacing:.07em;
    color:var(--muted);margin:0 0 14px;font-weight:650;
    display:flex;align-items:center;gap:8px}
  .card h2:before{content:"";width:8px;height:8px;border-radius:3px;
    background:linear-gradient(135deg,var(--accent),var(--accent2))}
  .row{display:flex;justify-content:space-between;gap:16px;
    padding:8px 0;border-bottom:1px solid rgba(255,255,255,.05)}
  .row:last-child{border-bottom:0}
  .k{color:var(--muted)}
  .v{text-align:end;font-weight:500;word-break:break-word}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .empty{color:var(--muted);font-style:italic;font-size:13px}
  table{width:100%%;border-collapse:collapse;font-size:14px}
  th{text-align:start;color:var(--muted);font-weight:500;font-size:12px;
    padding:7px 8px;border-bottom:1px solid var(--border)}
  td{padding:8px 8px;border-bottom:1px solid rgba(255,255,255,.05)}
  td.neg{color:var(--neg)} td.pos{color:var(--pos)}
  .chip{display:inline-block;background:var(--panel2);border:1px solid var(--border);
    border-radius:20px;padding:4px 12px;margin:3px 4px 3px 0;font-size:12px;
    font-family:ui-monospace,monospace}
  #map{height:340px;width:100%%;border-radius:12px;overflow:hidden;
    display:none;border:1px solid var(--border)}
  #map-fallback{display:none}
  .leaflet-container{background:#0f141b}
  .caveats{margin:0;padding-inline-start:18px;color:var(--muted);font-size:13px}
  .caveats li{margin:7px 0}
  footer{color:var(--muted);font-size:12px;text-align:center;margin-top:30px}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">
      <div class="logo" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none"
             stroke="#0b0e13" stroke-width="2" stroke-linecap="round"
             stroke-linejoin="round">
          <path d="M12 21s7-6.5 7-11a7 7 0 1 0-14 0c0 4.5 7 11 7 11z"></path>
          <circle cx="12" cy="10" r="2.5"></circle>
        </svg>
      </div>
      <div>
        <h1 data-i18n="app.title">WhatsApp Karşı Taraf Verisi Yakalama</h1>
        <div class="sub"><span data-i18n="app.subtitle">Aramanın karşı tarafından gözlemlenen üstveri</span>
          &middot; <span data-i18n="app.generated">oluşturuldu</span> %(generated)s</div>
      </div>
    </div>
    <div class="langbox">
      <label for="lang" data-i18n="app.lang">Dil</label>
      <select id="lang">
        <option value="tr">Türkçe</option>
        <option value="en">English</option>
        <option value="ru">Русский</option>
        <option value="ar">العربية</option>
        <option value="zh">中文</option>
      </select>
    </div>
  </div>

  <div class="stat-row">
    <div class="stat"><div class="n">%(events)s</div><div class="l" data-i18n="stat.events">olay</div></div>
    <div class="stat"><div class="n">%(duration)s</div><div class="l" data-i18n="stat.duration">süre (sn)</div></div>
    <div class="stat"><div class="n">%(numeric)s</div><div class="l" data-i18n="stat.numeric">sayısal alan</div></div>
    <div class="stat"><div class="n">%(strings)s</div><div class="l" data-i18n="stat.strings">metin alanı</div></div>
  </div>

  %(headline)s

  <div class="grid">
    <div class="card">
      <h2 data-i18n="sec.geo">IP coğrafi konumu</h2>
      %(geo)s
    </div>
    <div class="card">
      <h2 data-i18n="sec.identity">Karşı tarafın kimliği</h2>
      %(identity)s
    </div>
    <div class="card">
      <h2 data-i18n="sec.mediumnat">Ağ türü ve NAT</h2>
      %(medium_nat)s
    </div>
    <div class="card full">
      <h2 data-i18n="sec.map">Konum haritası</h2>
      <div id="map"></div>
      <div id="map-fallback" class="empty"></div>
    </div>
    <div class="card full">
      <h2 data-i18n="sec.public">Genel uç noktalar (maskesiz)</h2>
      %(public_eps)s
    </div>
    <div class="card full">
      <h2 data-i18n="sec.private">Özel / yerel uç noktalar</h2>
      %(private_eps)s
    </div>
  </div>
</div>

%(leaflet_js)s
<script>
var I18N = %(i18n_json)s;
var MAP = %(map_config)s;
var DEFAULT_LANG = "tr";
var CUR = null;
try { CUR = localStorage.getItem("wa_lang"); } catch (e) {}
if (!CUR || !I18N[CUR]) { CUR = DEFAULT_LANG; }
var mapFallbackKey = null;

function tr(k){
  var d = I18N[CUR] || I18N.en;
  if (d && d[k] != null) return d[k];
  if (I18N.en[k] != null) return I18N.en[k];
  return k;
}
function applyLang(lang){
  CUR = I18N[lang] ? lang : "en";
  try { localStorage.setItem("wa_lang", CUR); } catch (e) {}
  var root = document.documentElement;
  root.lang = CUR;
  root.dir = (CUR === "ar") ? "rtl" : "ltr";
  document.title = tr("app.title");
  var nodes = document.querySelectorAll("[data-i18n]");
  for (var i = 0; i < nodes.length; i++){
    var k = nodes[i].getAttribute("data-i18n");
    var v = tr(k);
    if (v != null) nodes[i].textContent = v;
  }
  var values = document.querySelectorAll("[data-i18n-value]");
  for (var j = 0; j < values.length; j++){
    values[j].textContent = tr(values[j].getAttribute("data-i18n-value"));
  }
  var sel = document.getElementById("lang");
  if (sel) sel.value = CUR;
  if (mapFallbackKey){
    var fb = document.getElementById("map-fallback");
    if (fb) fb.textContent = tr(mapFallbackKey);
  }
}
function showFallback(key){
  mapFallbackKey = key;
  var el = document.getElementById("map");
  if (el) el.style.display = "none";
  var fb = document.getElementById("map-fallback");
  if (fb){ fb.style.display = "block"; fb.textContent = tr(key); }
}
function initMap(){
  if (!MAP || MAP.state !== "ok"){
    showFallback(MAP && MAP.state === "error" ? "map.error" : "map.nogeo");
    return;
  }
  if (typeof L === "undefined"){ showFallback("map.offline"); return; }
  var el = document.getElementById("map");
  el.style.display = "block";
  try {
    var m = L.map("map", {scrollWheelZoom:false}).setView([MAP.lat, MAP.lon], 10);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
      {maxZoom:18, attribution:"(c) OpenStreetMap contributors"}).addTo(m);
    L.circle([MAP.lat, MAP.lon],
      {radius:12000, color:"#25d366", weight:1,
       fillColor:"#25d366", fillOpacity:0.12}).addTo(m);
    var popupLabel = document.createElement("span");
    popupLabel.textContent = MAP.label == null ? "" : String(MAP.label);
    L.marker([MAP.lat, MAP.lon]).addTo(m).bindPopup(popupLabel).openPopup();
    setTimeout(function(){ m.invalidateSize(); }, 100);
  } catch (e){ showFallback("map.offline"); }
}
document.addEventListener("DOMContentLoaded", function(){
  applyLang(CUR);
  var sel = document.getElementById("lang");
  if (sel){ sel.addEventListener("change", function(){ applyLang(this.value); }); }
  initMap();
});
</script>
</body>
</html>"""

def write_outputs(report, outdir=".", open_browser=True):
    """Save full JSON + an HTML dashboard and (optionally) open the HTML."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    os.makedirs(outdir, exist_ok=True)
    json_path = os.path.join(outdir, "wa_peer_full_%s.json" % ts)
    html_path = os.path.join(outdir, "wa_peer_report_%s.html" % ts)

    with open(json_path, "w", encoding="utf8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(html_path, "w", encoding="utf8") as f:
        f.write(render_html(report))

    print("Tam JSON dosyası -> %s" % os.path.abspath(json_path), file=sys.stderr)
    print("HTML raporu -> %s" % os.path.abspath(html_path), file=sys.stderr)

    if open_browser:
        try:
            webbrowser.open("file:///" + os.path.abspath(html_path).replace("\\", "/"))
        except Exception as e:
            print("Tarayıcı açılamadı: %s" % e, file=sys.stderr)
    return json_path, html_path


# --- Runtime RVA auto-resolution -------------------------------------------
# The agent holds an inline BUILDS cache keyed by the DLL's SizeOfImage. When
# WhatsApp auto-updates, that size changes and the cache misses. Instead of
# failing (the old behaviour, which is what issue #3 reported), the agent asks
# us to derive the hook offsets from the loaded DLL on disk. This mirrors
# resolve_rva.py: find each function's self-labeling __FUNCTION__ string-load
# site in .text (a RIP-relative LEA), then map that site to the enclosing
# .pdata RUNTIME_FUNCTION entry — the hookable function start. No new WhatsApp
# build needs a hand-added BUILDS entry any more.

RVA_TARGETS = [
    "wa_call_set_field_stat_numeric",
    "wa_call_set_field_stat_str",
    "parse_endpoint_address",
    "platform_to_cstr",
    "wa_transport_get_peer_public_addr_str",
    "wa_call_participant_get_peer_test_bucket_id_list_str",
    "wa_call_participant_get_peer_test_bucket_str",
    "wa_call_participant_get_multi_device_info_count",
    "wa_call_participant_get_active_device_info_const",
    "wa_call_participant_get_audio_level",
    "wa_call_participant_get_offer_msg",
]

_REX = (0x48, 0x4C)
_MODRM_RIP = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}


def resolve_rvas_from_dll(path):
    """Derive {name: rva} for RVA_TARGETS from the DLL at *path*.

    Returns (table, size_of_image). Raises RuntimeError on any failure (pefile
    missing, unreadable file, or a target whose assert literal is not found) so
    the caller can fall back to the fail-closed 'refuse to hook' path.
    """
    import bisect
    try:
        import pefile
    except ImportError:
        raise RuntimeError("pefile yüklü değil (pip install pefile)")
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as exc:
        raise RuntimeError("DLL okunamadı %r: %s" % (path, exc))

    ib = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b"\x00").decode("ascii", "replace"),
             ib + s.VirtualAddress, s.get_data()) for s in pe.sections]

    strs = {}
    for name, va, data in secs:
        if name not in (".rdata", ".rodata", ".data"):
            continue
        start = None
        for i, b in enumerate(data):
            if 0x20 <= b < 0x7f:
                if start is None:
                    start = i
            else:
                if start is not None and i - start >= 4:
                    try:
                        strs[va + start] = data[start:i].decode("ascii")
                    except UnicodeDecodeError:
                        pass
                start = None

    byname = collections.defaultdict(list)
    for name, va, data in secs:
        if name != ".text":
            continue
        n = len(data)
        i = 0
        while i < n - 7:
            if data[i] in _REX and data[i + 1] == 0x8D and data[i + 2] in _MODRM_RIP:
                disp = struct.unpack_from("<i", data, i + 3)[0]
                s = strs.get(va + i + 7 + disp)
                if s is not None:
                    byname[s].append(va + i)
                i += 7
                continue
            i += 1

    ents = []
    d = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", None)
    if d:
        for e in d:
            b = e.struct.BeginAddress
            en = e.struct.EndAddress
            if b:
                ents.append((ib + b, ib + en))
    ents.sort()
    starts = [b for b, _ in ents]

    def enclosing(site):
        k = bisect.bisect_right(starts, site) - 1
        if k < 0:
            return None
        b, en = ents[k]
        return b if b <= site < en else None

    table, missing = {}, []
    for name in RVA_TARGETS:
        votes = collections.Counter()
        for site in byname.get(name, []):
            ent = enclosing(site)
            if ent is not None:
                votes[ent - ib] += 1
        if votes:
            table[name] = votes.most_common(1)[0][0]
        else:
            missing.append(name)
    if missing:
        raise RuntimeError("RVA çözümlenemedi: %s" % ", ".join(missing))
    return table, pe.OPTIONAL_HEADER.SizeOfImage


def builds_snippet(size, table):
    """A paste-ready BUILDS[...] block, so a maintainer can bake an auto-resolved
    build into the committed table for offline/instant reuse."""
    width = max(len(k) for k in RVA_TARGETS) + 1
    lines = ["  %d: {   // WhatsAppDesktop <version>  (SizeOfImage 0x%X)" % (size, size)]
    for k in RVA_TARGETS:
        lines.append("    %s 0x%X," % ((k + ":").ljust(width), table[k]))
    lines.append("  },")
    return "\n".join(lines)


class TurkishArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        return super().format_help().replace("usage: ", "Kullanım: ", 1)

    def format_usage(self):
        return super().format_usage().replace("usage: ", "Kullanım: ", 1)


def run_capture(process=PROCESS, seconds=0, raw=None, outdir=".", no_geo=False,
                no_browser=False, stop_event=None, status_callback=None,
                event_callback=None, report_callback=None):
    """Capture call metadata and return (report, JSON path, HTML path).

    Run this function on a worker thread in a GUI. Set stop_event (a
    threading.Event) to end capture cleanly. status_callback(str) and
    event_callback(dict) run on Frida's callback thread, so GUI clients should
    queue them for the UI. report_callback(report) runs on the worker thread.
    """
    if frida is None:
        raise RuntimeError("Frida yüklü değil: pip install -r requirements.txt")
    def emit_status(message):
        if status_callback is None:
            print(message, file=sys.stderr)
        else:
            try:
                status_callback(message)
            except Exception as exc:
                print("[durum geri çağrısı hatası] %s" % exc, file=sys.stderr)

    session = frida.attach(process)
    events = []
    raw_file = None
    message_lock = threading.Lock()
    accepting_messages = True

    try:
        raw_file = open(raw, "a", encoding="utf8") if raw else None

        def on_message(message, data):
            if message.get("type") == "error":
                emit_status("[ajan hatası] %s" % message.get("description"))
                return
            payload = message.get("payload")
            if payload is None:
                return
            with message_lock:
                if not accepting_messages:
                    return
                events.append(payload)
                if raw_file:
                    raw_file.write(json.dumps(payload, ensure_ascii=False) + "\n")
                    raw_file.flush()
            if event_callback is not None:
                try:
                    event_callback(payload)
                except Exception as exc:
                    print("[olay geri çağrısı hatası] %s" % exc, file=sys.stderr)
            if payload.get("event") == "error":
                emit_status("[ajan] %s" % payload.get("message"))
                return
            if payload.get("event") == "need_rva":
                # Unknown build: derive the offsets from the DLL and hand them back,
                # so the agent hooks this version instead of refusing.
                size, path = payload.get("size"), payload.get("path")
                try:
                    table, soi = resolve_rvas_from_dll(path)
                    script.post({"type": "rva_table", "rva": table})
                    emit_status("[ajan] Bilinmeyen sürüm (boyut=%s): DLL dosyasından %d RVA "
                                "otomatik çözümlendi; kancalar kuruluyor. Sonraki çalıştırmada "
                                "çevrimdışı ve anında kullanmak için aşağıdaki kaydı wa_peer.py "
                                "içindeki BUILDS tablosuna ekleyin:\n%s"
                                % (size, len(table), builds_snippet(soi, table)))
                except Exception as exc:
                    script.post({"type": "rva_table", "rva": None, "reason": str(exc)})
                    emit_status("[ajan] Otomatik RVA çözümleme başarısız (boyut=%s): %s"
                                % (size, exc))
                return
            if payload.get("event") == "hook_ready":
                stop_hint = ("ardından Durdur düğmesine basın." if stop_event is not None
                             else "ardından Ctrl+C tuşlarına basın.")
                emit_status("%s işlemine bağlandı (sürüm boyutu=%s, RVA kaynağı=%s) — %d kanca "
                            "etkin. Bir arama başlatın veya gelen aramayı kabul edin; %s"
                            % (process, payload.get("module_size"),
                               payload.get("rva_source"),
                               len(payload.get("hooked", [])), stop_hint))

        script = session.create_script(AGENT)
        script.on("message", on_message)
        script.load()

        deadline = time.monotonic() + seconds if seconds else None
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                remaining = deadline - time.monotonic() if deadline is not None else None
                if remaining is not None and remaining <= 0:
                    break
                pause = min(0.3, remaining) if remaining is not None else 0.3
                if stop_event is None:
                    time.sleep(pause)
                elif stop_event.wait(pause):
                    break
        except KeyboardInterrupt:
            pass
    finally:
        with message_lock:
            accepting_messages = False
        try:
            session.detach()
        except Exception:
            pass
        if raw_file:
            raw_file.close()

    report = build_report(events, geo_lookup=not no_geo)
    if report_callback is not None:
        report_callback(report)
    json_path, html_path = write_outputs(report, outdir=outdir,
                                         open_browser=not no_browser)
    return report, json_path, html_path


def main(argv=None):
    ap = TurkishArgumentParser(
        description="Windows WhatsApp aramalarında karşı taraf üstverisini yakalar.",
        add_help=False)
    ap._optionals.title = "Seçenekler"
    ap.add_argument("-h", "--help", action="help",
                    help="bu yardım iletisini göster ve çık")
    ap.add_argument("--process", metavar="İŞLEM", default=PROCESS,
                    help="bağlanılacak WhatsApp işlemi (varsayılan: %(default)s)")
    ap.add_argument("--seconds", metavar="SANİYE", type=float, default=0,
                    help="yakalama süresi (saniye); 0 = Ctrl+C tuşuna basılana kadar")
    ap.add_argument("--raw", metavar="DOSYA", help="ham olay akışını ayrıca dosyaya yaz")
    ap.add_argument("--compact", action="store_true",
                    help="JSON çıktısını tek satırda yaz")
    ap.add_argument("--outdir", metavar="DİZİN", default=".",
                    help="tam JSON ve HTML raporunun kaydedileceği dizin (varsayılan: geçerli dizin)")
    ap.add_argument("--no-browser", action="store_true",
                    help="HTML raporunu tarayıcıda otomatik açma")
    ap.add_argument("--no-geo", action="store_true",
                    help="çevrimiçi IP coğrafi konum sorgusunu atla (tamamen çevrimdışı)")
    args = ap.parse_args(argv)

    if frida is None:
        print("frida yüklü değil: pip install -r requirements.txt", file=sys.stderr)
        return 1

    try:
        run_capture(
            process=args.process, seconds=args.seconds, raw=args.raw,
            outdir=args.outdir, no_geo=args.no_geo, no_browser=args.no_browser,
            report_callback=lambda report: print(json.dumps(
                report, indent=None if args.compact else 2, ensure_ascii=False)))
    except frida.ProcessNotFoundError:
        print(json.dumps({"error": "%s çalışmıyor" % args.process}, indent=2))
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
