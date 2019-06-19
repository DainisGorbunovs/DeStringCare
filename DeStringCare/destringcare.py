import argparse
import hashlib
import json
import logging
import os
from pathlib import Path

import OpenSSL
from OpenSSL import crypto
from jks import jks
from pyaxmlparser import APK

from DeStringCare import AESCipher

CODIFICATION = 'utf-8'


def generate_key(full_sha1_key: str) -> str:
    return hashlib.sha1(full_sha1_key.encode(CODIFICATION)).digest()[:16].hex()


def get_decrypt_keys(apk: APK, certificate_files: list):
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

    sha1hashes = []
    # assume there are more than one certificate file
    for certificate_file in certificate_files:
        certificate_bytes = apk.zip.read(certificate_file)
        pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, certificate_bytes)
        # assume there are more than one certificate
        certs = get_certificates(pkcs7)
        hashes = [cert.digest('sha1').decode() for cert in certs]
        sha1hashes.extend(hashes)

    keys = []
    for hash in sha1hashes:
        keys.append(generate_key(hash))

    return keys


def extract_secrets(apk: APK, decrypt_ciphers: list, encrypt_cipher: AESCipher,
                    replaced_values: dict, other_secrets: bool = False) -> dict:
    secret_keys = set()

    if other_secrets:
        with open(Path(os.path.dirname(__file__)).joinpath('other_secrets.txt'), 'r') as f:
            for line in f:
                secret_keys.add(line.strip())

    res = apk.get_android_resources()
    logging.getLogger("pyaxmlparser.stringblock").setLevel(logging.ERROR)
    res._analyse()
    logging.getLogger("pyaxmlparser.stringblock").setLevel(logging.NOTSET)

    strings = res.values[apk.get_package()]['\x00\x00']['string']

    valmap = {}
    for index, (property_name, value) in enumerate(strings):
        for decrypt_cipher in decrypt_ciphers:
            try:
                known = decrypt_cipher.decrypt(value)
                valmap[property_name] = known

                if property_name in replaced_values:
                    known = replaced_values[property_name]
                if encrypt_cipher is not None:
                    strings[index][1] = encrypt_cipher.encrypt(known).upper()
                break
            except (TypeError, ValueError, IndexError):
                # add the secret keys to the value map
                if property_name in secret_keys:
                    valmap[property_name] = value
                # ignore other values which cannot be decrypted

    if encrypt_cipher is not None:
        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        char_map = {
            '<': '&lt;',
            '@': '\@'
        }
        for key, value in strings:
            value = value.replace('&', '&amp;')
            for old_symbol, new_symbol in char_map.items():
                value = value.replace(old_symbol, new_symbol)

            if '\n' in value or '\'' in value:
                value = '"{}"'.format(value)

            if value == '':
                buff += '    <string name="{}"/>\n'.format(key)
            else:
                buff += '    <string name="{}">{}</string>\n'.format(key, value)

        buff += '</resources>\n'

        xml = buff.encode('utf-8')

        with open('resigned-strings.xml', 'wb') as f:
            f.write(xml)

    return valmap


def main():
    parser = argparse.ArgumentParser(description="Extract StringCare secrets from an Android APK.")
    parser.add_argument("-r", "--resign", action="store_true", help="Resign and save xml file")
    parser.add_argument("-o", "--other", action="store_true", help="Include a list of other secrets")
    parser.add_argument("apk", help="Path to the apk", type=str)
    parser.add_argument("replaced", help="Path to the replaced values", type=str, nargs='?')
    args = parser.parse_args()

    logging.getLogger("pyaxmlparser.core").setLevel(logging.ERROR)
    apk = APK(args.apk)
    logging.getLogger("pyaxmlparser.core").setLevel(logging.NOTSET)
    certificate_files = [f for f in apk.files if f.startswith('META-INF/') and f.endswith('.RSA')]

    decrypt_keys = get_decrypt_keys(apk, certificate_files)
    decrypt_ciphers = [AESCipher(key) for key in decrypt_keys]

    encrypt_cipher = None
    if args.resign:
        def get_key_from_android_debug_keystore(keystore_path: str, keystore_pass: str = 'android') -> str:
            ks = jks.KeyStore.load(keystore_path, keystore_pass)
            cert_bytes = ks.entries['androiddebugkey'].cert_chain[0][1]
            public_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bytes)
            sha1hash = public_cert.digest('sha1').decode()
            return sha1hash

        keystore_path = str(Path.home().joinpath('.android', 'debug.keystore'))
        sha1hash = get_key_from_android_debug_keystore(keystore_path)
        encrypt_key = generate_key(sha1hash)
        encrypt_cipher = AESCipher(encrypt_key)

    replaced_map = {}
    if args.replaced is not None:
        with open(args.replaced, 'rb') as f:
            replaced_map = json.load(f)

    valmap = extract_secrets(apk, decrypt_ciphers, encrypt_cipher, replaced_map, args.other)
    print(json.dumps(valmap, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()
