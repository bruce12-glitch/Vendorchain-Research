"""Local GSTIN format/checksum/PAN checks; this does not query a tax authority."""
import re

ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
FORMAT = re.compile(r'[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]')

def check_digit(body):
    if not isinstance(body, str) or len(body) != 14 or any(c not in ALPHABET for c in body):
        raise ValueError('14 uppercase base-36 characters required')
    total = 0
    for index, char in enumerate(body):
        product = ALPHABET.index(char) * (1 if index % 2 == 0 else 2)
        total += product // 36 + product % 36
    return ALPHABET[(36-total % 36) % 36]

def valid_gstin(value, expected_pan=None):
    if not isinstance(value, str) or not FORMAT.fullmatch(value):
        return False
    return (value[-1] == check_digit(value[:14])
            and (expected_pan is None or value[2:12] == expected_pan))
