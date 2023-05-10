# Merkle Trees

The source for this article can be found here:
https://github.com/k98kurz/hacknwa-merkleasy-article

All libraries and packages cited in this article are free and open source.

## Overview

Merkle trees are tree data structures composed by recursive, pairwise hashing.

For example, say we have four messages we want to commit into a set. All four
will be hashed down into a single hash, called the root, and proofs can be
derived to verify set inclusion of any message.

```python
from hashlib import sha256

messages = [
    b'hello',
    b'world',
    b'HackNWA',
    b'keywords for algorithm',
]

leaves = [sha256(m).digest() for m in messages]

node01 = sha256(leaves[0] + leaves[1]).digest()
node23 = sha256(leaves[2] + leaves[3]).digest()

root = sha256(node01 + node23).digest()

assert root.hex() == '4d0a081ff4ec6a26bd11a3a554cd444735fb0f8b59827d3ec56415a328f5d29f'

for l in leaves:
    print(l.hex())

print(f'sha256({leaves[0].hex()} + {leaves[1].hex()})={node01.hex()}')
print(f'sha256({leaves[2].hex()} + {leaves[3].hex()})={node23.hex()}')
print(f'sha256({node01.hex()} + {node23.hex()})={root.hex()}')
```

## Proof verification

To prove set inclusion, a list of hashes and instructions must be produced that,
when followed, results in the root hash of the Merkle tree.

```python
from hashlib import sha256

root = bytes.fromhex('4d0a081ff4ec6a26bd11a3a554cd444735fb0f8b59827d3ec56415a328f5d29f')

message = b'HackNWA'

steps = [
    ('load_left', message.hex()),
    ('hash_left',),
    ('load_right', '168b9c92f443df0cfafcd44a24f74c7df45e1fbaf05b5b0f8fc672c4d9a4a95d'),
    ('hash_right',),
    ('load_left', '7305db9b2abccd706c256db3d97e5ff48d677cfe4d3a5904afb7da0e3950e1e2'),
    ('hash_final',)
]

left, right = b'', b''

for step in steps:
    if step[0] == 'hash_left':
        print('hash_left')
        left = sha256(left + right).digest()
        print(f'{left.hex()=}')
    if step[0] == 'hash_right':
        print('hash_right')
        right = sha256(left + right).digest()
        print(f'{right.hex()=}')
    if step[0] == 'load_left':
        print('load_left')
        left = bytes.fromhex(step[1])
        print(f'{left.hex()=}')
    if step[0] == 'load_right':
        print('load_right')
        right = bytes.fromhex(step[1])
        print(f'{right.hex()=}')
    if step[0] == 'hash_final':
        final = sha256(left + right).digest()
        print(final.hex())
        assert root == final, 'verification failed'
        print('verification succeeded')
```

## Merkleasy

The Merkleasy library makes Merkle tree construction and proof derivation and
verification simple and easy. It also includes tree serialization for storage or
transmission of the whole tree structure.

The package can be found on pypi here: https://pypi.org/project/merkleasy/

The repository can be found on github here: https://github.com/k98kurz/merkle

```python
from merkleasy import Tree
from hashlib import sha256

messages = [
    b'hello',
    b'world',
    b'HackNWA',
    b'keywords for algorithm',
    b'oddly numbered for fun',
]
leaves = [sha256(l).digest() for l in messages]

# method 1: automatic structure
tree1 = Tree.from_leaves(messages)

# method 2: manually specified structure
tree2 = Tree(
    Tree(
        Tree(leaves[0], leaves[1]),
        Tree(leaves[2], leaves[3])
    ),
    leaves[4]
)

assert tree1 == tree2

# proof
root = tree1.root
proof = tree1.prove(b'HackNWA')
print([p.hex() for p in proof])

# verification
try:
    Tree.verify(root, b'HackNWA', proof)
    print('verified')
except:
    print('error')

# serialization
serialized = tree1.to_json()
print(serialized)
deserialized = Tree.from_json(serialized)
assert deserialized == tree1

# pretty print
print(tree1.to_json(pretty=True))
```

## Uses

The Merkle tree is a fundamental building block of distributed applications.
Common software that uses the Merkle tree include BitTorrent and Bitcoin. Below
are explanations of how the Merkle tree is used in BitTorrent and Bitcoin, as
well as an example of the skeleton of a public key infrastructure.

### BitTorrent

The BitTorrent protocol uses the Merkle tree to break large files into smaller,
more manageable chunks. The full specification can be found here:
http://www.bittorrent.org/beps/bep_0003.html

According to BEP 3, version 0e08ddf84d8d3bf101cdf897fc312f2774588c9e, the
metainfo file for each torrent includes the sha1 hashes of all the pieces into
which the file/files has/have been broken. This info dict is then sha1 hashed to
create an info_hash used by trackers. This is a more primitive use of hashes to
form a deterministic, tree-like structure than is used in more recent
applications, and the use of sha1 is potentially insecure, but the basic
principle is the same: each piece of the torrent can be verified as belonging to
the torrent by its hash, which is committed to by the info_hash.

### Bitcoin

The Bitcoin block consists of a header and a body. The header contains primarily
the previous block hash, the nonce, and the root of a Merkle tree containing all
the transactions in the block body. This allows for transactions to be proven to
be included in a valid block even when the block chain is trimmed to just the
headers. Satoshi wrote in the whitepaper that this was done as a space-saving
measure for devices with limited storage as the block chain grew in size, and it
has worked for those who use it. However, the verification of transactions by
miners and nodes requires a full UTXO (unspent transaction output) set to be
maintained, and some UTXOs date back to the first few blocks, so in practice it
has not been a practice for miners and node operators to store trimmed blocks;
it remains possible to remove transactions without any outstanding UTXOs from
blocks without sacrificing forward security, but new nodes require full blocks
to verify the history of the chain, so this has not caught on.

### Public key infrastructure

Merkle trees can be used to build a PKI rather simply by including authorized
public key bytes as the leaves in a tree, then distributing the tree root as the
PKI commitment. These public keys could be the equivalent of certificate
authorities, and they can authorize further public keys by signing certificates
that include the Merkle root of more public keys, e.g. for a cluster of servers.

The below example uses the Ed25519 implementation from the PyNaCl library, the
`token_bytes` function for cryptographic quality entropy, and the `json` library
for a quick/dirty/contrived example of serialization/deserialization.

```python
from merkleasy import Tree
from nacl.signing import SigningKey, VerifyKey
from secrets import token_bytes
import json

# create 23 certificate authorities
cert_auths = [
    SigningKey(token_bytes(32))
    for _ in range(23)
]

# commit to their public keys
pki = Tree.from_leaves([bytes(key.verify_key) for key in cert_auths])


# create a certificate
some_server_keys = [
    SigningKey(token_bytes(32))
    for _ in range(12)
]
server_tree = Tree.from_leaves([
    bytes(key.verify_key)
    for key in some_server_keys
])
cert_doc = {
    'name': 'trollpwn.xyz',
    'key_root': server_tree.root.hex(),
    'expires': '1 million years',
    'pki_root': pki.root.hex(),
    'authorized_by': bytes(cert_auths[0].verify_key).hex(),
    'authorization': [
        step.hex()
        for step in pki.prove(bytes(cert_auths[0].verify_key))
    ]
}

# sign the cert
cert = cert_auths[0].sign(bytes(json.dumps(cert_doc), 'utf-8'))


# sign something with a key from the cert
message = b'do the protocol thing'
smsg = some_server_keys[1].sign(message)

# prove that the server key is authorized by the cert
server_auth = server_tree.prove(bytes(some_server_keys[1].verify_key))

# ship to client
response = json.dumps({
    'message': smsg.hex(),
    'server_key': bytes(some_server_keys[1].verify_key).hex(),
    'server_auth': [step.hex() for step in server_auth],
    'cert': cert.hex()
})


# client side setup and parsing
authorized_pki_roots = [pki.root, b'some other pki root, etc']
response = json.loads(response)
message = bytes.fromhex(response['message'])
server_key = VerifyKey(bytes.fromhex(response['server_key']))
server_auth = [bytes.fromhex(step) for step in response['server_auth']]
cert = bytes.fromhex(response['cert'])
cert_doc = json.loads(str(cert[64:], 'utf-8'))

# verify the cert
try:
    assert bytes.fromhex(cert_doc['pki_root']) in authorized_pki_roots
    print('verified: pki is authorized')
    _ = VerifyKey(bytes.fromhex(cert_doc['authorized_by'])).verify(cert)
    print('verified: the certificate was signed by the CA')
    Tree.verify(
        bytes.fromhex(cert_doc['pki_root']),
        bytes.fromhex(cert_doc['authorized_by']),
        [bytes.fromhex(step) for step in cert_doc['authorization']]
    )
    print('verified: the CA is part of the PKI')
except BaseException as e:
    print(f'error: {e}')

# verify the key used to sign the message is part of the cert
try:
    Tree.verify(
        bytes.fromhex(cert_doc['key_root']),
        bytes(server_key),
        server_auth
    )
    print('verified: server key')
except BaseException as e:
    print(f'error: {e}')

# verify the message was signed properly
try:
    _ = server_key.verify(message)
    print('verified: message signature from server')
except BaseException as e:
    print(f'error: {e}')
```
