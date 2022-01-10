# handshake

A Python library to create and validate authentication tokens.

`handshake` is used to generate and validate arbitrary authentication tokens
that contain arbitrary metadata and support expiration. It uses basic
cryptographic primitives (hashing, HMACs) and is based around the concept of a
shared private secret for security.

Example usage would be to create namespaced authentication tokens for clients
of an API which another service can check is valid and hasn't expired. The
tokens are safe to be made public, put in headers etc. and can be used like
session tokens.

The tokens are strings in the format of:

```
arbitrary:data:here:timestamp:random:signature
```

All fields other than timestamp, random and signature are optional. Signatures
are in the format of:

```
HMAC(arbitrary:data:here:timestamp:random){shared_secret}
```

The library is designed to allow whatever metadata is required into the token,
such as the first parameter could be a namespace and the second parameter an
object id. This allows tokens to be easily split between internal systems and
uses while containing metadata or IDs for other objects.

For example, you could use `handshake` to allow an API to generate tokens which
a client stores for a variable amount of time and can verify their state with
other services. The arbitrary data prefix can be used to store an application
namespace and the UUID of the object being referenced (such as `user:uuid` or
`service:recordtype:uuid`). This library is of most use if you have multiple
diverse systems, microservices or other distributed endpoints that require
ad-hoc authentication and something like JWT or OAuth is overkill.


## Installation

`handshake` is pure Python and has no dependancies. You can install `handshake`
via pip:

```bash
$ pip install handshake
```

Any modern version of Python3 will be compatible.


## Usage

`handshake` has one class providing two basic public functions. Examples:

```python
import os
from handshake import AuthToken

# The shared secret, keep this private, can be str or bytes but needs to be
# from a cryptographically secure source
secret = os.urandom(128)

# Create the instance
token = AuthToken(secret)

# Basic token with no additional parameters
plain_token = token.create()
token.verify(plain_token)

# The token must be no more than 300 seconds old
plain_token = token.create()
token.verify(plain_token, time_range=300)

# Namespaced but no specific item, namespace is arbitrary
namespaced_token = token.create('namespace')
token.verify(namespaced_token)

# Namespaced and with an arbitrary item ID
from uuid import uuid4
client_token = token.create('user', uuid4())
token.verify(client_token)

# Lots of metadata
client_token = token.create('network', 'node', '12345', '67890')
token.verify(client_token)
```

If a token fails to validate it raise the relevent exception:

```python
# Create a token with one secret
token = AuthToken('a secret')
plain_token = token.create()

# Attempt to verify it with a different token, this is invalid
token_with_different_secret = AuthToken('not the same secret')
token_with_different_secret.verify(plain_token)
# ... a child of handshake.errors.InvalidTokenError exception is raised
```

## Full API synopsis

### `handshake.AuthToken(secret=str_or_bool, hashfunc=function)` -> `None`

Initiates an AuthToken object using the specified secret. The secret is
required. It must be either a string or a bytes and must be between 32 and 1024
characters or bytes in length. The secret should be sourced from a
cryptographically safe random source, such as `os.urandom`.

`hashfunc` defaults to `hashlib.sha256` but you can replace it with another
hash function if you need to.

### `handshake.AuthToken.create(*arbitrary str)` -> `str`

Creates an authentication token.

### `handshake.AuthToken.verify(token=str, time_range=int)` -> `bool or dict`

Verifies an authentication token created with `handshake.AuthToken.create()`.

`time_range` is an optional integer which if set specifies the valid time
range the token must have been generated within. This is used to verify
expiring tokens. It defaults to `0` which disables time range validation.

If the token is valid a tuple containing any arbitrary data in the token. For
example a token of

```
arbitrary:data:here:timestamp:random:signature
```

If valid would return a tuple of:

```python
('arbitrary', 'data', 'here')
```

If the token is invalid for any reason a `handshake.errors.InvalidTokenError`
exception is raised (or a child exception of
`handshake.errors.InvalidTokenError`).


# Tests

There is a test suite that you can run by cloning this repository and
executing:

```bash
$ make test
```


# Contributing

All properly formatted and sensible pull requests, issues and comments are
welcome.
