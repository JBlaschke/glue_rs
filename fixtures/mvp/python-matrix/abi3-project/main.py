import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import hashlib
import json

digest = hashes.Hash(hashes.SHA256())
digest.update(b"unchanged prebuilt abi3")
assert digest.finalize() == hashlib.sha256(b"unchanged prebuilt abi3").digest()
key = Ed25519PrivateKey.generate()
signature = key.sign(b"abi3 operation")
key.public_key().verify(signature, b"abi3 operation")
print(json.dumps({"status": "abi3-ok", "cryptography": cryptography.__version__}))
