from Crypt.Cryptography import WrongCryptoError

from crypto.configuration.network import get_network, set_network
from crypto.identity.address import address_from_private_key
from crypto.identity.address import address_from_public_key
from crypto.identity.private_key import PrivateKey
from crypto.networks.mainnet import Mainnet
from binary.unsigned_integer.writer import write_bit8
from coincurve import PublicKey
from base58 import b58encode_check, b58decode_check
from base64 import b64encode, b64decode
import binascii
import hashlib

# We brazenly use CryptBitcoin for some utility functions which are implemented
# the same way to avoid code duplication
from Crypt import CryptBitcoin

set_network(Mainnet)


newSeed = CryptBitcoin.newSeed

def _privatekeyToWif(private_key):
    network_wif = get_network()["wif"]
    seed = write_bit8(network_wif) + \
        bytes(bytearray.fromhex(private_key)) + \
        write_bit8(0x01)
    return b58encode_check(seed).decode()

def _wifToPrivatekey(wif):
    network_wif = get_network()["wif"]
    seed = b58decode_check(wif)
    if seed[0] != network_wif or seed[-1] != 0x01:
        raise WrongCryptoError()
    return binascii.hexlify(bytearray(seed[1:-1])).decode()


def newPrivatekey():  # Return new private key
    return _privatekeyToWif(newSeed())

def hdPrivatekey(seed, child):
    if not seed.startswith("Ark|"):
        raise WrongCryptoError()
    seed = b"\x00" + \
        (child % 100000000).to_bytes(4, "big") + \
        seed.encode() + \
        b"\x01"
    return _privatekeyToWif(hashlib.sha256(seed).hexdigest())

def privatekeyToAddress(privatekey):  # Return address from private key
    return address_from_private_key(_wifToPrivatekey(privatekey))

def sign(data, privatekey):  # Return sign to data using private key
    privatekey = _wifToPrivatekey(privatekey)
    sig = PrivateKey(privatekey).private_key.sign_recoverable(data.encode())
    return b64encode(sig)

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