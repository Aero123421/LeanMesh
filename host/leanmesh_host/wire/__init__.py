"""LM1 wire codecs for the Host (docs/09): strict CBOR, RF frame layouts, serial header, control
envelope and COSE_Sign1 structure. Pure functions, no I/O. The C++ codecs in src/core/wire/ and
this package are verified against each other and against scripts/wire_fixture.py by
host/tests/unit/test_wire_differential.py.
"""

from .cbor import WireError, cbor_decode, cbor_encode

__all__ = ["WireError", "cbor_decode", "cbor_encode"]
