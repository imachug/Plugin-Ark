try:
	import crypto
except ImportError:
	print("Please install Ark crypto library by running 'pip install arkecosystem-crypto'")
	raise SystemExit(1)


from Crypt import Crypt
from . import CryptArk

Crypt.registerCrypto("Ark", CryptArk)