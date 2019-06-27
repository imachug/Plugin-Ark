from Crypt.Cryptography import newSeed, WrongCryptoError
from crypto.configuration.network import get_network, set_network
from lib import pybitcointools as btctools
from crypto.identity.address import address_from_private_key
from crypto.identity.address import address_from_public_key
from crypto.identity.private_key import PrivateKey
from crypto.networks.mainnet import Mainnet
from coincurve import PublicKey
from base64 import b64encode, b64decode
import binascii
import hashlib

WORDLIST = btctools.wordlist_english

set_network(Mainnet)

def _intToBits(n, length=8):
    return bin(n)[2:].rjust(length, "0")

def _privatekeyToBip(private_key):
    private_key = bytes(bytearray.fromhex(private_key))  # Decode from hex
    bits = "".join(map(_intToBits, private_key))  # Split into bits
    bits += _intToBits(hashlib.sha256(private_key).digest()[0])[:4]  # Add checksum
    words = [WORDLIST[int(bits[i:i + 11], 2)].strip() for i in range(0, len(bits), 11)]
    return " ".join(words)

def _bipToPrivatekey(bip):
    if len(bip.split()) != 12:
        raise WrongCryptoError()
    # Restore bit stream
    bits = ""
    for word in bip.split():
        try:
            bits += _intToBits(WORDLIST.index(word + "\n"), 11)
        except IndexError:
            raise WrongCryptoError()
    # Get private key
    private_key = int(bits[:128], 2).to_bytes(16, byteorder="big")
    # Validate checksum
    checksum = _intToBits(hashlib.sha256(private_key).digest()[0])[:4]
    if checksum != bits[128:]:
        raise WrongCryptoError()
    return hashlib.sha256(bip.encode()).hexdigest()


def newPrivatekey():  # Return new private key
    return _privatekeyToBip(newSeed()[:32])

def hdPrivatekey(seed, child):
    seed = b"\x00" + \
        (child % 100000000).to_bytes(4, "big") + \
        seed.encode() + \
        b"\x01"
    return _privatekeyToBip(hashlib.sha256(seed).hexdigest()[:32])

def privatekeyToAddress(privatekey):  # Return address from private key
    return address_from_private_key(_bipToPrivatekey(privatekey))

def sign(data, privatekey):  # Return sign to data using private key
    privatekey = _bipToPrivatekey(privatekey)
    sig = PrivateKey(privatekey).private_key.sign_recoverable(data.encode())
    return b64encode(sig).decode()

def verify(data, valid_address, sign):  # Verify data using address and sign
    sign = b64decode(sign)
    try:
        publickey = PublicKey.from_signature_and_message(sign, data.encode())
    except Exception:
        raise WrongCryptoError()
    publickey = binascii.hexlify(publickey.format(compressed=True))
    address = address_from_public_key(publickey.decode())
    if isinstance(valid_address, (list, tuple)):
        return address in valid_address
    else:
        return address == valid_address

def isAddress(address):
    return re.match("^A[A-Za-z0-9]{25,34}$", address)