try:
	import crypto
except ImportError:
	print("Please install Ark crypto library by running 'pip install arkecosystem-crypto'")
	raise SystemExit(1)


from Crypt import Cryptography
from . import CryptArk

Cryptography.registerCrypto("ark", CryptArk)