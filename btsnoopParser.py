#!/usr/bin/env python3
"""
BTSnoop HCI Log Parser - Filter BTATT + GATT service/characteristic table
No dependencies beyond Python stdlib.

Usage: python parse_btsnoop.py <btsnoop_hci.log>
"""
import re
import struct
import sys
from datetime import datetime, timezone

BTSNOOP_MAGIC = b"btsnoop\x00"
HCI_ACL = 0x02
L2CAP_CID_ATT = 0x0004
BTSNOOP_EPOCH_DELTA_US = 0x00DCDDB30F2F8000

ATT_OPCODES = {
    0x01: "ATT_ERROR_RSP",
    0x02: "ATT_EXCHANGE_MTU_REQ",
    0x03: "ATT_EXCHANGE_MTU_RSP",
    0x04: "ATT_FIND_INFO_REQ",
    0x05: "ATT_FIND_INFO_RSP",
    0x06: "ATT_FIND_BY_TYPE_VALUE_REQ",
    0x07: "ATT_FIND_BY_TYPE_VALUE_RSP",
    0x08: "ATT_READ_BY_TYPE_REQ",
    0x09: "ATT_READ_BY_TYPE_RSP",
    0x0A: "ATT_READ_REQ",
    0x0B: "ATT_READ_RSP",
    0x0C: "ATT_READ_BLOB_REQ",
    0x0D: "ATT_READ_BLOB_RSP",
    0x0E: "ATT_READ_MULTIPLE_REQ",
    0x0F: "ATT_READ_MULTIPLE_RSP",
    0x10: "ATT_READ_BY_GROUP_TYPE_REQ",
    0x11: "ATT_READ_BY_GROUP_TYPE_RSP",
    0x12: "ATT_WRITE_REQ",
    0x13: "ATT_WRITE_RSP",
    0x16: "ATT_PREPARE_WRITE_REQ",
    0x17: "ATT_PREPARE_WRITE_RSP",
    0x18: "ATT_EXECUTE_WRITE_REQ",
    0x19: "ATT_EXECUTE_WRITE_RSP",
    0x1B: "ATT_HANDLE_VALUE_NTF",
    0x1D: "ATT_HANDLE_VALUE_IND",
    0x1E: "ATT_HANDLE_VALUE_CFM",
    0x52: "ATT_WRITE_CMD",
    0xD2: "ATT_SIGNED_WRITE_CMD",
}

# Known 16-bit UUIDs
UUID16_NAMES = {
    0x2800: "PRIMARY_SERVICE",
    0x2801: "SECONDARY_SERVICE",
    0x2802: "INCLUDE",
    0x2803: "CHARACTERISTIC",
    0x2900: "CHAR_EXT_PROPERTIES",
    0x2901: "CHAR_USER_DESC",
    0x2902: "CLIENT_CHAR_CONFIG (CCCD)",
    0x2903: "SERVER_CHAR_CONFIG",
    0x2904: "CHAR_PRESENTATION_FORMAT",
    0x2905: "CHAR_AGGREGATE_FORMAT",
    0x2A00: "DEVICE_NAME",
    0x2A01: "APPEARANCE",
    0x2A04: "PERIPH_PREF_CONN_PARAMS",
    0x2A05: "SERVICE_CHANGED",
    0x2A19: "BATTERY_LEVEL",
    0x2A29: "MANUFACTURER_NAME",
    0x2A24: "MODEL_NUMBER",
    0x2A25: "SERIAL_NUMBER",
    0x2A26: "FIRMWARE_REVISION",
    0x2A27: "HARDWARE_REVISION",
    0x2A28: "SOFTWARE_REVISION",
    0x2A50: "PNP_ID",
}

CHAR_PROPS = {
    0x01: "BROADCAST",
    0x02: "READ",
    0x04: "WRITE_NO_RSP",
    0x08: "WRITE",
    0x10: "NOTIFY",
    0x20: "INDICATE",
    0x40: "AUTH_WRITE",
    0x80: "EXT_PROPS",
}


def uuid_str(raw):
    """Format a UUID from raw bytes (2 or 16 bytes, little-endian)."""
    if len(raw) == 2:
        val = struct.unpack_from("<H", raw)[0]
        name = UUID16_NAMES.get(val, "")
        label = f" ({name})" if name else ""
        return f"0x{val:04X}{label}"
    elif len(raw) == 16:
        # Standard UUID string format from LE bytes
        b = raw[::-1]  # reverse to big-endian
        return (f"{b[0:4].hex()}-{b[4:6].hex()}-{b[6:8].hex()}-"
                f"{b[8:10].hex()}-{b[10:16].hex()}")
    return raw.hex()


def props_str(props_byte):
    return "|".join(v for k, v in CHAR_PROPS.items() if props_byte & k) or "NONE"


# ---------------------------------------------------------------------------
# GATT table builder
# ---------------------------------------------------------------------------

class GattTable:
    """Accumulates GATT services and characteristics discovered during negotiation."""

    def __init__(self):
        self.services = {}          # start_handle -> {end, uuid}
        self.characteristics = {}   # decl_handle  -> {value_handle, props, uuid}
        self.cccd_handles = {}      # cccd_handle  -> value_handle (best-effort)
        self._last_char_value = None

    def add_service(self, start_h, end_h, uuid_raw):
        self.services[start_h] = {
            "end": end_h,
            "uuid": uuid_str(uuid_raw),
        }

    def add_characteristic(self, decl_handle, props, value_handle, uuid_raw):
        self.characteristics[decl_handle] = {
            "value_handle": value_handle,
            "props": props_str(props),
            "uuid": uuid_str(uuid_raw),
        }
        self._last_char_value = value_handle

    def add_cccd(self, cccd_handle):
        self.cccd_handles[cccd_handle] = self._last_char_value

    def print_table(self):
        if not self.services and not self.characteristics:
            print("  (no GATT table data captured)")
            return

        print(f"\n{'='*80}")
        print("  GATT TABLE")
        print(f"{'='*80}")

        # Build lookup: which chars belong to which service
        sorted_svcs = sorted(self.services.items())
        sorted_chars = sorted(self.characteristics.items())

        for svc_start, svc in sorted_svcs:
            svc_end = svc["end"]
            print(f"\n  SERVICE  handles 0x{svc_start:04X}–0x{svc_end:04X}  uuid={svc['uuid']}")
            for decl_h, ch in sorted_chars:
                if svc_start <= decl_h <= svc_end:
                    val_h = ch["value_handle"]
                    cccd = next((h for h, v in self.cccd_handles.items()
                                 if v == val_h), None)
                    cccd_str = f"  cccd=0x{cccd:04X}" if cccd else ""
                    print(f"    CHAR   decl=0x{decl_h:04X}  value=0x{val_h:04X}"
                          f"  props=[{ch['props']}]  uuid={ch['uuid']}{cccd_str}")

        # Orphan characteristics (outside any known service range)
        known_ranges = [(s, v["end"]) for s, v in sorted_svcs]
        for decl_h, ch in sorted_chars:
            in_svc = any(s <= decl_h <= e for s, e in known_ranges)
            if not in_svc:
                print(f"\n  CHAR (no service)  decl=0x{decl_h:04X}"
                      f"  value=0x{ch['value_handle']:04X}"
                      f"  props=[{ch['props']}]  uuid={ch['uuid']}")

        print(f"\n  {len(self.services)} service(s), {len(self.characteristics)} characteristic(s)")
        print(f"{'='*80}\n")


# ---------------------------------------------------------------------------
# GATT negotiation packet parsers
# ---------------------------------------------------------------------------

def process_gatt(opcode, att_payload, gatt: GattTable):
    """Parse GATT discovery responses and feed the GattTable."""

    # ATT_READ_BY_GROUP_TYPE_RSP — primary services
    if opcode == 0x11:
        if len(att_payload) < 2:
            return
        item_len = att_payload[1]
        items = att_payload[2:]
        i = 0
        while i + item_len <= len(items):
            chunk = items[i:i + item_len]
            start_h = struct.unpack_from("<H", chunk, 0)[0]
            end_h   = struct.unpack_from("<H", chunk, 2)[0]
            uuid_raw = chunk[4:]
            gatt.add_service(start_h, end_h, uuid_raw)
            i += item_len

    # ATT_READ_BY_TYPE_RSP — characteristics (UUID 0x2803)
    elif opcode == 0x09:
        if len(att_payload) < 2:
            return
        item_len = att_payload[1]
        items = att_payload[2:]
        i = 0
        while i + item_len <= len(items):
            chunk = items[i:i + item_len]
            if len(chunk) < 5:
                break
            decl_handle  = struct.unpack_from("<H", chunk, 0)[0]
            props        = chunk[2]
            value_handle = struct.unpack_from("<H", chunk, 3)[0]
            uuid_raw     = chunk[5:]
            gatt.add_characteristic(decl_handle, props, value_handle, uuid_raw)
            i += item_len

    # ATT_FIND_INFO_RSP — descriptors (catches CCCDs)
    elif opcode == 0x05:
        if len(att_payload) < 2:
            return
        fmt = att_payload[1]  # 1 = 16-bit UUIDs, 2 = 128-bit
        uuid_size = 2 if fmt == 1 else 16
        item_size = 2 + uuid_size
        items = att_payload[2:]
        i = 0
        while i + item_size <= len(items):
            handle   = struct.unpack_from("<H", items, i)[0]
            uuid_raw = items[i+2: i+2+uuid_size]
            if len(uuid_raw) == 2:
                uuid_val = struct.unpack_from("<H", uuid_raw)[0]
                if uuid_val == 0x2902:
                    gatt.add_cccd(handle)
            i += item_size


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------

def parse_header(f):
    magic = f.read(8)
    if magic != BTSNOOP_MAGIC:
        raise ValueError(f"Not a BTSnoop file. Got magic: {magic!r}")
    version, datalink = struct.unpack(">II", f.read(8))
    print(f"[*] BTSnoop version={version}  datalink={datalink}")


def iter_records(f):
    pkt_num = 0
    while True:
        header = f.read(24)
        if len(header) < 24:
            break
        orig_len, incl_len, flags, drops, ts_raw = struct.unpack(">IIIIq", header)
        data = f.read(incl_len)
        pkt_num += 1
        ts_us = ts_raw - BTSNOOP_EPOCH_DELTA_US
        yield pkt_num, ts_us, flags, data


def parse_att_from_acl(payload):
    if len(payload) < 8:
        return None
    handle_flags = struct.unpack_from("<H", payload, 0)[0]
    conn_handle  = handle_flags & 0x0FFF
    l2cap_len, cid = struct.unpack_from("<HH", payload, 4)
    if cid != L2CAP_CID_ATT:
        return None
    att_data = payload[8: 8 + l2cap_len]
    if not att_data:
        return None
    return conn_handle, att_data[0], att_data


def decode_att_summary(opcode, att_payload):
    """Return a human-readable summary of the ATT payload beyond raw hex."""
    try:
        # Opcodes that carry handle + value
        if opcode in (0x12, 0x52, 0xD2):  # WRITE_REQ, WRITE_CMD, SIGNED_WRITE_CMD
            handle = struct.unpack_from("<H", att_payload, 1)[0]
            value  = att_payload[3:]
            return f"handle=0x{handle:04X} ({handle})  value={value.hex()}"

        if opcode == 0x0A:  # READ_REQ
            handle = struct.unpack_from("<H", att_payload, 1)[0]
            return f"handle=0x{handle:04X} ({handle})"

        if opcode == 0x0B:  # READ_RSP
            return f"value={att_payload[1:].hex()}"

        if opcode in (0x1B, 0x1D):  # HANDLE_VALUE_NTF / IND
            handle = struct.unpack_from("<H", att_payload, 1)[0]
            value  = att_payload[3:]
            return f"handle=0x{handle:04X} ({handle})  value={value.hex()}"

        if opcode == 0x01:  # ERROR_RSP
            req_op, err_handle, err_code = struct.unpack_from("<BHB", att_payload, 1)
            return (f"req_opcode=0x{req_op:02X}  handle=0x{err_handle:04X}"
                    f"  error=0x{err_code:02X}")

        if opcode in (0x08, 0x10):  # READ_BY_TYPE/GROUP_REQ
            start_h = struct.unpack_from("<H", att_payload, 1)[0]
            end_h   = struct.unpack_from("<H", att_payload, 3)[0]
            uuid_raw = att_payload[5:]
            return f"handles=0x{start_h:04X}–0x{end_h:04X}  uuid={uuid_str(uuid_raw)}"

        if opcode == 0x02:  # EXCHANGE_MTU_REQ
            mtu = struct.unpack_from("<H", att_payload, 1)[0]
            return f"client_mtu={mtu}"

        if opcode == 0x03:  # EXCHANGE_MTU_RSP
            mtu = struct.unpack_from("<H", att_payload, 1)[0]
            return f"server_mtu={mtu}"

    except struct.error:
        pass

    return att_payload[1:].hex() if len(att_payload) > 1 else ""


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <btsnoop_hci.log>")
        sys.exit(1)

    total = att_count = 0
    gatt = GattTable()
    attackStrings = []
    with open(sys.argv[1], "rb") as f:
        parse_header(f)
        print(f"\n{'#':>6}  {'Timestamp (UTC)':>15}  {'Dir':<12}  {'Opcode':<32}  Details")
        print("-" * 110)

        for pkt_num, ts_us, flags, data in iter_records(f):
            total += 1
            if not data or data[0] != HCI_ACL:
                continue
            result = parse_att_from_acl(data[1:])
            if result is None:
                continue

            conn_handle, opcode, att_payload = result
            att_count += 1

            direction = "CTRL→HOST" if (flags & 0x01) else "HOST→CTRL"
            ts = datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc).strftime("%H:%M:%S.%f")
            opname  = ATT_OPCODES.get(opcode, f"UNKNOWN(0x{opcode:02X})")
            summary = decode_att_summary(opcode, att_payload)

            print(f"{pkt_num:>6}  {ts:>15}  {direction:<12}  {opname:<32}  {summary}")

            # Lazy parsing
            # Looking for value
            valueSearch = re.search(r'value=([0-9a-fA-F]+)', summary)

            # Looking for value and host sending to device
            if valueSearch and direction == "HOST→CTRL":
                # Print raw string
                print(f"         Raw ATT payload: {valueSearch.group(1)}")

                # Checking for uniqueness
                if "pkts.append(bytes.fromhex(\"" + valueSearch.group(1) + "\"))" not in attackStrings:
                    # Tie into notify-and-write.py command 
                    attackStrings.append("pkts.append(bytes.fromhex(\"" + valueSearch.group(1) + "\"))")
                # Reset 
                valueSearch = None
                    

            # Feed GATT table
            process_gatt(opcode, att_payload, gatt)

    print("-" * 110)
    print(f"[*] Total packets : {total}")
    print(f"[*] BTATT packets : {att_count}")

    gatt.print_table()

    print(f"\n[*] Unique ATT values captured (potential attack strings): {len(attackStrings)}")
    for attackString in attackStrings:
        print(f"         {attackString}")

if __name__ == "__main__":
    main()
