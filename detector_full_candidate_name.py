#!/usr/bin/env python3
"""
detector_full_candidate_name.py

Usage:
    python3 detector_full_candidate_name.py iscp_pii_dataset.csv

Produces:
    redacted_output_candidate_full_name.csv

Notes:
- Implements rules described in the prompt:
  * Standalone PII (A): phone (10 digits), aadhar (12 digits), passport (alpha+digits), upi_id (user@bank)
  * Combinatorial PII (B): requires 2+ of {full name (first+last), email, physical address (street+city+pin), device_id/IP when tied to user context}
  * Non-PII: single first name, single last name, standalone email (if not combinatorial), standalone pin/city/state, transaction/order ids, etc.
- Redaction approach:
  * Phones: keep first 2 and last 2 digits, mask middle with X (e.g., 98XXXXXX10)
  * Aadhar: keep first 4 and last 4, mask middle (1234XXXX9012)
  * Passport: keep first char and last 2, mask middle (PXXXXX67)
  * Email: keep first 2 chars of local-part, mask rest of local-part; domain preserved (joXXX@domain.com)
  * Full names: mask each name token to first char + Xs (Rajesh Kumar -> RXXXXX KXXXXX)
  * Address: replaced with "[REDACTED_ADDRESS]"
  * UPI ID: keep first 2 chars of user, mask the rest of user part, keep @bank
  * Device ID: keep first 3 chars, mask the rest (if considered PII to redact)
  * IP Address: mask last octet (192.168.1.xxx)
- Output JSON is compact (no spaces), safely quoted for CSV.
"""

import sys
import csv
import json
import re
from typing import Dict, Any

PHONE_RE = re.compile(r'^\d{10}$')
PHONE_RE_ANY = re.compile(r'\b\d{10}\b')
AADHAR_RE = re.compile(r'^\d{12}$')
PASSPORT_RE = re.compile(r'^[A-Za-z][0-9]{6,7}$')  # common pattern like P1234567
UPI_RE = re.compile(r'^[\w.+-]{2,}@[A-Za-z0-9_.-]+$')  # simple upi pattern
EMAIL_RE = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
PINCODE_RE = re.compile(r'\b\d{6}\b')  # Indian 6-digit pincode
# Helper redaction functions


def redact_phone(p: str) -> str:
    s = re.sub(r'\D', '', p)
    if len(s) != 10:
        return "[REDACTED_PII]"
    return f"{s[:2]}{'X' * 6}{s[-2:]}"


def redact_aadhar(a: str) -> str:
    s = re.sub(r'\D', '', a)
    if len(s) != 12:
        return "[REDACTED_PII]"
    return f"{s[:4]}{'X' * 4}{s[-4:]}"


def redact_passport(p: str) -> str:
    s = p.strip()
    if len(s) < 3:
        return "[REDACTED_PII]"
    if len(s) <= 3:
        return s[0] + "X" * (len(s) - 1)
    return s[0] + "X" * (len(s) - 3) + s[-2:]


def redact_email(e: str) -> str:
    try:
        local, domain = e.split("@", 1)
    except ValueError:
        return "[REDACTED_PII]"
    if len(local) <= 2:
        masked_local = local[0] + "X" * (len(local) - 1)
    else:
        masked_local = local[:2] + "X" * (max(1, len(local) - 2))
    return masked_local + "@" + domain


def redact_name(fullname: str) -> str:
    # Mask each token preserving first character
    parts = fullname.split()
    masked_parts = []
    for p in parts:
        if len(p) == 1:
            masked_parts.append(p)  # single initial, keep as-is (but this won't count as full name)
        else:
            masked_parts.append(p[0] + "X" * (len(p) - 1))
    return " ".join(masked_parts)


def redact_address(addr: str) -> str:
    return "[REDACTED_ADDRESS]"


def redact_upi(upi: str) -> str:
    if "@" not in upi:
        return "[REDACTED_PII]"
    user, bank = upi.split("@", 1)
    if len(user) <= 2:
        masked_user = user[0] + "X" * (len(user) - 1)
    else:
        masked_user = user[:2] + "X" * (max(1, len(user) - 2))
    return masked_user + "@" + bank


def redact_device_id(dev: str) -> str:
    if len(dev) <= 3:
        return "X" * len(dev)
    return dev[:3] + "X" * (len(dev) - 3)


def redact_ip(ip: str) -> str:
    # mask last octet
    if IPV4_RE.match(ip.strip()):
        parts = ip.strip().split(".")
        parts[-1] = "xxx"
        return ".".join(parts)
    return "[REDACTED_PII]"


def is_full_name_field(value: str) -> bool:
    if not isinstance(value, str):
        return False
    parts = [p for p in value.strip().split() if p]
    return len(parts) >= 2 and all(re.match(r"^[A-Za-z'-]+$", p) for p in parts)


def is_physical_address_field(value: str) -> bool:
    if not isinstance(value, str):
        return False
    # crude heuristic: contains comma (street, city) and a 6-digit pincode somewhere OR contains street keywords
    if PINCODE_RE.search(value):
        return True
    street_terms = ["road", "rd", "street", "st", "lane", "ln", "bungalow", "apartment", "blk", "block", "brg", "brigade"]
    lower = value.lower()
    if any(t in lower for t in street_terms) and ("," in value or len(value.split()) > 3):
        return True
    return False


def detect_standalone_A(fields: Dict[str, Any]) -> Dict[str, bool]:
    found = {}
    # phone
    phone_candidates = []
    for key in fields:
        if key.lower() in ("phone", "contact"):
            v = fields.get(key)
            if isinstance(v, (int, float)):
                v = str(int(v))
            if isinstance(v, str):
                s = re.sub(r'\D', '', v)
                if PHONE_RE.match(s):
                    phone_candidates.append((key, v))
    if phone_candidates:
        found['phone'] = True
    # aadhar
    if 'aadhar' in fields:
        v = fields.get('aadhar')
        if isinstance(v, (int, float)):
            v = str(int(v))
        if isinstance(v, str):
            s = re.sub(r'\D', '', v)
            if AADHAR_RE.match(s):
                found['aadhar'] = True
    # passport
    if 'passport' in fields:
        v = fields.get('passport')
        if isinstance(v, str) and PASSPORT_RE.match(v.replace(" ", "").strip()):
            found['passport'] = True
    # upi
    if 'upi_id' in fields:
        v = fields.get('upi_id')
        if isinstance(v, str) and UPI_RE.match(v.strip()):
            found['upi_id'] = True
    # Also detect generic phone-like values inside other fields (less prioritized)
    # (We already scanned phone/contact)
    return found


def detect_B_items(fields: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a dict listing detected items from list B and their keys.
    Keys of interest: 'name', 'email', 'address', 'device_or_ip'
    """
    found = {'name': [], 'email': [], 'address': [], 'device_or_ip': []}
    # Name: check 'name' field OR combined first_name+last_name
    if 'name' in fields and isinstance(fields['name'], str) and is_full_name_field(fields['name']):
        found['name'].append(('name', fields['name']))
    else:
        # check first_name + last_name pair
        if 'first_name' in fields and 'last_name' in fields:
            fn = fields.get('first_name')
            ln = fields.get('last_name')
            if isinstance(fn, str) and isinstance(ln, str) and fn.strip() and ln.strip():
                combined = (fn.strip() + " " + ln.strip())
                if is_full_name_field(combined):
                    found['name'].append(('first_last', combined))
    # Email
    for k in fields:
        if k.lower() == 'email':
            v = fields.get(k)
            if isinstance(v, str) and EMAIL_RE.match(v.strip()):
                found['email'].append((k, v))
    # Physical address detection
    # Check 'address' field first
    if 'address' in fields and isinstance(fields['address'], str) and is_physical_address_field(fields['address']):
        found['address'].append(('address', fields['address']))
    else:
        # try composition: city + pin_code presence -> not enough alone unless combined with street; but spec says physical address must have street, city, and pin.
        # We will treat presence of 'address' containing pincode as physical address.
        pass
    # Device / IP - considered only when tied to user context (we will treat this as candidate and only count it toward combinatorial if another B exists)
    if 'device_id' in fields and isinstance(fields['device_id'], str) and fields['device_id'].strip():
        found['device_or_ip'].append(('device_id', fields['device_id']))
    if 'ip_address' in fields and isinstance(fields['ip_address'], str) and fields['ip_address'].strip():
        found['device_or_ip'].append(('ip_address', fields['ip_address']))
    return found


def redact_fields(fields: Dict[str, Any], standaloneA: Dict[str, bool], B_detects: Dict[str, Any], combinatorial_trigger: bool) -> Dict[str, Any]:
    out = dict(fields)  # shallow copy
    # Redact standalone A items anywhere they appear (phone, aadhar, passport, upi)
    # Phone fields: 'phone', 'contact'
    for key in list(out.keys()):
        lk = key.lower()
        if lk in ('phone', 'contact'):
            v = out.get(key)
            if isinstance(v, (int, float)):
                v = str(int(v))
            if isinstance(v, str):
                s = re.sub(r'\D', '', v)
                if PHONE_RE.match(s):
                    out[key] = redact_phone(s)
        if lk == 'aadhar' and key in out:
            v = out.get(key)
            if isinstance(v, (int, float)):
                v = str(int(v))
            if isinstance(v, str):
                s = re.sub(r'\D', '', v)
                if AADHAR_RE.match(s):
                    out[key] = redact_aadhar(s)
        if lk == 'passport' and key in out:
            v = out.get(key)
            if isinstance(v, str) and PASSPORT_RE.match(v.replace(" ", "").strip()):
                out[key] = redact_passport(v.strip())
        if lk == 'upi_id' and key in out:
            v = out.get(key)
            if isinstance(v, str) and UPI_RE.match(v.strip()):
                out[key] = redact_upi(v.strip())
    # Redact B items only if combinatorial_trigger is True (i.e., two or more B items present)
    if combinatorial_trigger:
        # Name(s)
        for name_entry in B_detects.get('name', []):
            k, v = name_entry
            if k == 'name':
                out['name'] = redact_name(v)
            elif k == 'first_last':
                # we have first_name and last_name fields; redact both
                fn, ln = None, None
                if 'first_name' in out:
                    fn = out['first_name']
                    if isinstance(fn, str):
                        out['first_name'] = redact_name(fn) if is_full_name_field(fn + " " + out.get('last_name', "")) else redact_name(fn)
                if 'last_name' in out:
                    ln = out['last_name']
                    if isinstance(ln, str):
                        out['last_name'] = redact_name(ln)
        # Email(s)
        for email_entry in B_detects.get('email', []):
            k, v = email_entry
            out[k] = redact_email(v)
        # Physical address(es)
        for addr_entry in B_detects.get('address', []):
            k, v = addr_entry
            out[k] = redact_address(v)
        # Device/IP - redact only when counting toward combinatorial or if standalone A? (Spec: device/IP only PII when tied to user context)
        for d_entry in B_detects.get('device_or_ip', []):
            k, v = d_entry
            if k == 'device_id' and 'device_id' in out:
                out['device_id'] = redact_device_id(str(out['device_id']))
            if k == 'ip_address' and 'ip_address' in out:
                out['ip_address'] = redact_ip(str(out['ip_address']))
    else:
        # Even if combinatorial_trigger is False, if a device_id/ip appears AND also standalone A items exist, it's OK; but we do not redact device/ip unless required.
        pass
    return out


def process_record(record_id: str, data_json_str: str) -> (str, bool):
    """
    Returns a tuple: (redacted_json_str, is_pii_bool)
    """
    try:
        data = json.loads(data_json_str)
    except Exception:
        # try to sanitize minor CSV JSON quirks
        try:
            data = json.loads(data_json_str.replace("'", '"'))
        except Exception:
            # if unparsable, treat as non-PII and return original
            return json.dumps({"_parsing_error": data_json_str}), False

    # Detect standalone A
    standaloneA = detect_standalone_A(data)

    # Detect B items
    B_detects = detect_B_items(data)

    # Evaluate combinatorial rule:
    # Count B elements that qualify:
    # - name (full name)
    # - email
    # - physical address
    # - device_or_ip counts ONLY when tied to user context (we'll treat it as counting if present alongside any other B element)
    b_count = 0
    b_components = []
    if B_detects.get('name'):
        b_count += 1
        b_components.append('name')
    if B_detects.get('email'):
        b_count += 1
        b_components.append('email')
    if B_detects.get('address'):
        b_count += 1
        b_components.append('address')
    # device_or_ip: only count if present together with any other B element (i.e., tied to user context)
    device_or_ip_present = bool(B_detects.get('device_or_ip'))
    if device_or_ip_present:
        # If at least one other B exists, then device/ip counts as a B item.
        if b_count >= 1:
            b_count += 1
            b_components.append('device_or_ip')
        # else do not increment
    combinatorial_trigger = (b_count >= 2)

    # Final is_pii decision:
    is_pii = False
    if standaloneA:
        is_pii = True
    elif combinatorial_trigger:
        is_pii = True
    else:
        is_pii = False

    # Redact fields appropriately
    redacted = redact_fields(data, standaloneA, B_detects, combinatorial_trigger)

    # Additionally: If standaloneA included phone/aadhar/passport/upi, ensure those redactions applied even if they were under unexpected keys
    # (detect_standalone_A already checked well-known keys; redact_fields also masks common keys)

    # Return JSON string compact
    redacted_json_str = json.dumps(redacted, separators=(",", ":"))
    return redacted_json_str, is_pii


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv", file=sys.stderr)
        sys.exit(2)
    input_csv = sys.argv[1]
    output_csv = "redacted_output_candidate_full_name.csv"

    with open(input_csv, newline='', encoding='utf-8') as inf, \
            open(output_csv, 'w', newline='', encoding='utf-8') as outf:
        reader = csv.DictReader(inf)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(outf, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            rid = row.get('record_id') or row.get('record_id'.upper()) or ""
            data_json_str = row.get('data_json') or row.get('data_json'.upper()) or ""
            redacted_json_str, is_pii_flag = process_record(rid, data_json_str)
            writer.writerow({
                'record_id': rid,
                'redacted_data_json': redacted_json_str,
                'is_pii': "True" if is_pii_flag else "False"
            })

    # Print output path for convenience
    print(output_csv)


if __name__ == "__main__":
    main()
