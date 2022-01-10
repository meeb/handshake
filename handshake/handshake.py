import os
import hmac
from time import time
from hashlib import sha256
from . import errors, utils


class AuthToken:

    MIN_SECRET_LEN = 16
    MAX_SECRET_LEN = 1024
    MAX_TOKEN_LEN = 2048

    def __init__(self, secret='', hashfunc=sha256, random_len=256):
        if isinstance(secret, str):
            secret = secret.encode()
        if not isinstance(secret, bytes):
            raise errors.ConfigError(f'secret must be a str or '
                              f'bytes, got: {type(secret)}')
        secret_len = len(secret)
        if (secret_len < self.MIN_SECRET_LEN or
            secret_len > self.MAX_SECRET_LEN):
            raise errors.ConfigError(f'secret must be between '
                                     f'{self.MIN_SECRET_LEN} and '
                                     f'{self.MAX_SECRET_LEN} chars or bytes '
                                     f'in length, got: {secret_len}')
        self.secret = secret
        if not callable(hashfunc):
            raise errors.ConfigError(f'hashfunc must be a callable, got: '
                              f'{type(hashfunc)}')
        try:
            h = hashfunc(b'').hexdigest()
        except Exception as e:
            raise errors.ConfigError(f'hash function is invalid: {hashfunc}, '
                                     f'the callable must return an object '
                                     f'with a hexdigest() method')
        self.hashfunc = hashfunc
        if not isinstance(random_len, int):
            raise errors.ConfigError(f'random_len must be an int, '
                              f'got: {type(random_len)}')
        if (random_len < self.MIN_SECRET_LEN or
            random_len > self.MAX_SECRET_LEN):
            raise errors.ConfigError(f'random_len must be between '
                                     f'{self.MIN_SECRET_LEN} and '
                                     f'{self.MAX_SECRET_LEN}, '
                                     f'got: {random_len}')
        self.random_len = random_len

    def create(self, *metadata):
        params = []
        for i, param in enumerate(metadata):
            if not utils.is_ascii_str(param):
                raise errors.InvalidValueError(f'metadata[{i}] contains '
                                               f'invalid characters, only '
                                               f'a-z A-Z 0-9 underscores '
                                               f'and hyphens are allowed, '
                                               f'got: {param}')
            params.append(param)
        param_str = ':'.join(params)
        ts = str(int(time()))
        random_str = self.hashfunc(os.urandom(self.random_len)).hexdigest()
        msg = f'{param_str}:{ts}:{random_str}'
        if len(msg) > self.MAX_TOKEN_LEN:
            raise errors.InvalidValueError(f'token must be less than '
                                           f'{self.MAX_TOKEN_LEN} characters '
                                           f'when generated (try specifying '
                                           f'shorter metadata), token was '
                                           f'{len(msg)} characters')
        h = hmac.new(self.secret, msg=msg.encode(), digestmod=self.hashfunc)
        return f'{msg}:{h.hexdigest()}'

    def verify(self, token, time_range=0):
        if not isinstance(token, str):
            raise errors.InvalidTokenError(f'token must be a str, '
                                           f'got: {type(token)}')
        if len(token) > self.MAX_TOKEN_LEN:
            raise errors.InvalidTokenError(f'token must be '
                                           f'{self.MAX_TOKEN_LEN} chars or '
                                           f'less, got: {len(token)}')
        parts = token.split(':')
        if len(parts) < 4:
            raise errors.InvalidTokenError(f'tokens must contain at least 4 '
                                           f'parts separated by colons (:), '
                                           f'got: {token}')
        if not isinstance(time_range, int):
            raise errors.InvalidValueError(f'time_range must be an int, '
                                           f'got: {type(time_range)}')
        if time_range < 0:
            raise errors.InvalidValueError(f'time_range must be postive, '
                                           f'got: {time_range}')
        timestamp, random, signature = parts[-3], parts[-2], parts[-1]
        try:
            timestamp = int(timestamp)
        except (ValueError, TypeError) as e:
            raise errors.InvalidTokenError(f'token has an invalid timestamp, '
                                           f'unable to parse {timestamp} as '
                                           f'an int: {e}')
        metadata = parts[0:-3]
        if time_range > 0:
            local_ts = int(time())
            min_drift = local_ts - time_range
            max_drift = local_ts + time_range
            if timestamp < min_drift or timestamp > max_drift:
                raise errors.TokenExpiredError(f'token has expired, timestamp '
                                               f'{timestamp} with time_range '
                                               f'of {time_range} and local '
                                               f'time of {local_ts}')
        metadata_str = ':'.join(metadata)
        msg = f'{metadata_str}:{timestamp}:{random}'
        h = hmac.new(self.secret, msg=msg.encode(), digestmod=self.hashfunc)
        test_signature = h.hexdigest()
        if not hmac.compare_digest(test_signature, signature):
            raise errors.TokenSignatureError(f'token has an invalid signature')
        return () if metadata == [''] else tuple(metadata)
