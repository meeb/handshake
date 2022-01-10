import os
import string
import unittest
from time import sleep
from hashlib import sha256, sha512
import handshake
from handshake import utils as handshake_utils


class HandshakeTestCase(unittest.TestCase):

    maxDiff = None

    def test_utils_is_ascii_str(self):
        # Invalid types
        self.assertFalse(handshake_utils.is_ascii_str(b''))
        self.assertFalse(handshake_utils.is_ascii_str(0))
        self.assertFalse(handshake_utils.is_ascii_str({}))
        self.assertFalse(handshake_utils.is_ascii_str(object()))
        # Invalid example chars
        self.assertFalse(handshake_utils.is_ascii_str(' '))
        self.assertFalse(handshake_utils.is_ascii_str('!'))
        self.assertFalse(handshake_utils.is_ascii_str('@'))
        self.assertFalse(handshake_utils.is_ascii_str('*'))
        self.assertFalse(handshake_utils.is_ascii_str(':'))
        # Valid chars
        for c in string.ascii_lowercase:
            self.assertTrue(handshake_utils.is_ascii_str(c))
        for c in string.ascii_uppercase:
            self.assertTrue(handshake_utils.is_ascii_str(c))
        for c in string.digits:
            self.assertTrue(handshake_utils.is_ascii_str(c))
        for c in '_-':
            self.assertTrue(handshake_utils.is_ascii_str(c))

    def test_interface(self):
        # No args
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken()
        # Too small a secret
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken('small')
        # Too large a secret
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken('massive' * 1024)
        # Invalid types
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken(0)
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken({})
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken(object())
        # Invalid callbacks
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken('secret secret secret', hashfunc=0)
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken('secret secret secret', hashfunc='')
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken('secret secret secret', hashfunc=b'')
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken('secret secret secret', hashfunc=lambda x: x)
        # Invalid random_len
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken('secret secret secret', random_len=0)
        with self.assertRaises(handshake.errors.ConfigError):
            handshake.AuthToken('secret secret secret', random_len=9999)
        # Valid initialisation
        handshake.AuthToken('secret secret secret')
        handshake.AuthToken(b'secret secret secret')
        handshake.AuthToken('secret secret secret', hashfunc=sha256)
        handshake.AuthToken('secret secret secret', random_len=128)

    def test_create_token(self):
        random_secret = os.urandom(256)
        auth_tokens = handshake.AuthToken(random_secret)
        # Invalid params
        with self.assertRaises(handshake.errors.InvalidValueError):
            auth_tokens.create(' ')
        with self.assertRaises(handshake.errors.InvalidValueError):
            auth_tokens.create('!')
        with self.assertRaises(handshake.errors.InvalidValueError):
            auth_tokens.create('@')
        with self.assertRaises(handshake.errors.InvalidValueError):
            auth_tokens.create('*')
        with self.assertRaises(handshake.errors.InvalidValueError):
            auth_tokens.create(':')
        # Too much metadata
        with self.assertRaises(handshake.errors.InvalidValueError):
            too_much_metadata = ['very long'] * 1024
            auth_tokens.create(*too_much_metadata)
        # Bare token
        test_token = auth_tokens.create()
        self.assertEqual(test_token[0], ':')
        token_parts = test_token.split(':')
        self.assertEqual(len(token_parts), 4)
        int(token_parts[1])                         # timestamp
        self.assertEqual(len(token_parts[2]), 64)   # random
        self.assertEqual(len(token_parts[3]), 64)   # signature
        # Arbitrary parameters
        test_token = auth_tokens.create('test', 'params')
        token_parts = test_token.split(':')
        self.assertEqual(len(token_parts), 5)
        self.assertEqual(token_parts[0], 'test')
        self.assertEqual(token_parts[1], 'params')
        int(token_parts[2])                         # timestamp
        self.assertEqual(len(token_parts[3]), 64)   # random
        self.assertEqual(len(token_parts[4]), 64)   # signature
        # Using a different hash function
        auth_tokens = handshake.AuthToken(random_secret, hashfunc=sha512)
        test_token = auth_tokens.create('test', 'params')
        token_parts = test_token.split(':')
        self.assertEqual(len(token_parts), 5)
        self.assertEqual(token_parts[0], 'test')
        self.assertEqual(token_parts[1], 'params')
        int(token_parts[2])                         # timestamp
        self.assertEqual(len(token_parts[3]), 128)  # random
        self.assertEqual(len(token_parts[4]), 128)  # signature

    def test_verify_token(self):
        random_secret = os.urandom(256)
        auth_tokens = handshake.AuthToken(random_secret)
        # Invalid token, modify the signature slightly
        test_token = auth_tokens.create()
        test_token_list = list(test_token)
        test_token_list[-1] = '1' if test_token_list[-1] == '0' else '0'
        test_token = ''.join(test_token_list)
        with self.assertRaises(handshake.errors.TokenSignatureError):
            auth_tokens.verify(test_token)
        # Valid token
        test_token = auth_tokens.create()
        verify_result = auth_tokens.verify(test_token)
        self.assertEqual(verify_result, ())
        # Arbitrary parameters
        test_token = auth_tokens.create('test', 'params')
        verify_result = auth_tokens.verify(test_token)
        self.assertEqual(verify_result, ('test', 'params'))
        # Valid time range
        test_token = auth_tokens.create('time', 'range')
        verify_result = auth_tokens.verify(test_token, time_range=100)
        self.assertEqual(verify_result, ('time', 'range'))
        # Invalid time range
        test_token = auth_tokens.create('time', 'range')
        sleep(2)  # Sleep for more than the specified time_range
        with self.assertRaises(handshake.errors.TokenExpiredError):
            verify_result = auth_tokens.verify(test_token, time_range=1)
        # Fixed, known token for full test
        auth_tokens = handshake.AuthToken('secret secret secret')
        test_token = ('test:'
                      '1:'
                      '00000000000000000000000000000000'
                      '00000000000000000000000000000000:'
                      'e7fb75d1239b69a9fbe7912719d70602'
                      '020322156d1bc8e3c31f3b2870180279')
        verify_result = auth_tokens.verify(test_token)
        self.assertEqual(verify_result, ('test',))
