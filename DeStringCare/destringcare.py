import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import OpenSSL
import jks
from Crypto.Cipher import AES
from OpenSSL import crypto

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
CODIFICATION = 'UTF-8'


def get_sha1_key(apk_filepath: str) -> str:
    # https://stackoverflow.com/questions/45104923/pyopenssls-pkcs7-object-provide-very-little-information-how-can-i-get-the-sha1
    def get_certificates(self):
        from OpenSSL.crypto import _lib, _ffi, X509
        """
        https://github.com/pyca/pyopenssl/pull/367/files#r67300900

        Returns all certificates for the PKCS7 structure, if present. Only
        objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
        certificates.

        :return: The certificates in the PKCS7, or :const:`None` if
            there are none.
        :rtype: :class:`tuple` of :class:`X509` or :const:`None`
        """
        certs = _ffi.NULL
        if self.type_is_signed():
            certs = self._pkcs7.d.sign.cert
        elif self.type_is_signedAndEnveloped():
            certs = self._pkcs7.d.signed_and_enveloped.cert
        #
        pycerts = []
        for i in range(_lib.sk_X509_num(certs)):
            pycert = X509.__new__(X509)
            pycert._x509 = _lib.sk_X509_value(certs, i)
            pycerts.append(pycert)
        #
        if not pycerts:
            return None
        return tuple(pycerts)

    archive = zipfile.ZipFile(apk_filepath, 'r')
    imgdata = archive.read('META-INF/CERT.RSA')
    pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, imgdata)
    certs = get_certificates(pkcs7)

    hashes = [cert.digest('sha1').decode() for cert in certs]
    return hashes[0] if len(hashes) == 1 else hashes


def generate_key(full_sha1_key: str) -> str:
    return hashlib.sha1(full_sha1_key.encode(CODIFICATION)).digest()[:16]


def encrypt_secret(raw: str, generated_key: str = None) -> str:
    if generated_key is None:
        generated_key = generate_key(SHA1_KEY)
    raw = pad(raw)
    cipher = AES.new(generated_key, AES.MODE_ECB)
    return cipher.encrypt(raw).hex().upper()


def decrypt_secret(enc: str, generated_key: str = None) -> str:
    if generated_key is None:
        generated_key = generate_key(SHA1_KEY)
    secret_array = bytes.fromhex(enc)
    cipher = AES.new(generated_key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(secret_array).decode(CODIFICATION))
    return plaintext


def load_file(xml_path, encrypt_key: str = None):
    # use apktool to decode the resources beforehand
    valmap = {}
    encmap = {}

    xml = ET.parse(xml_path)

    for el in xml.findall('string'):
        propname = el.attrib['name']
        val = el.text

        try:
            known = decrypt_secret(val)
            valmap[propname] = known
            if encrypt_key is not None:
                encmap[propname] = encrypt_secret(known, generate_key(encrypt_key))
                el.text = encmap[propname]
        except (TypeError, ValueError):
            # ignore values which cannot be decrypted
            pass

    if encrypt_key is not None and len(encmap) > 0:
        xml.write('resigned-strings.xml', encoding='utf-8', xml_declaration=True)

    return valmap


def get_key_from_android_debug_keystore(keystore_path: str, keystore_pass: str = 'android') -> str:
    ks = jks.KeyStore.load(keystore_path, keystore_pass)
    cert_bytes = ks.entries['androiddebugkey'].cert_chain[0][1]
    public_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bytes)
    sha1hash = public_cert.digest('sha1').decode()
    return sha1hash


def main():
    global APK_FILEPATH, SHA1_KEY

    parser = argparse.ArgumentParser(description="Extract StringCare secrets from an Android APK.")
    parser.add_argument("-r", "--resign", action="store_true", help="Resign and save xml file")
    parser.add_argument("apk", help="Path to the apk", type=str)
    parser.add_argument("xml", help="Path to an xml containing StringCare secrets", type=str)
    args = parser.parse_args()

    APK_FILEPATH = str(Path.cwd().joinpath(args.apk))
    SHA1_KEY = get_sha1_key(APK_FILEPATH)

    # resign the file with our own key
    if args.resign:
        keystore_path = str(Path.home().joinpath('.android', 'debug.keystore'))
        sha1hash = get_key_from_android_debug_keystore(keystore_path)
        valmap = load_file(str(Path.cwd().joinpath(args.xml)), sha1hash)
    else:
        valmap = load_file(str(Path.cwd().joinpath(args.xml)))

    # print the secrets
    print(json.dumps(valmap, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()
