# https://gist.github.com/DainisGorbunovs/c190aecba33c431f0c5d194a1aeace9c
from Cryptodome.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]


class AESCipher:
    def __init__(self, key):
        """
        Requires hex encoded param as a key
        """
        # self.key = key.decode("hex")  # Python 2
        self.key = bytes.fromhex(key)

    def encrypt(self, raw):
        """
        Returns hex encoded encrypted value!
        """
        raw = pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        # return cipher.encrypt(raw).encode("hex")  # Python 2
        return cipher.encrypt(raw.encode()).hex()

    def decrypt(self, enc):
        """
        Requires hex encoded param to decrypt
        """
        # enc = enc.decode("hex")  # Python 2
        enc = bytes.fromhex(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        # return unpad(cipher.decrypt(enc))  # Python 2
        return unpad(cipher.decrypt(enc).decode())
