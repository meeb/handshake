_allowed_ascii_chars = (
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '0123456789'
    '-_'
)


def is_ascii_str(s):
    if not isinstance(s, str):
        return False
    for c in s:
        if c not in _allowed_ascii_chars:
            return False
    return True
