#!/usr/bin/python
# -*- encoding: utf-8 -*-
# Example barebones file decryption application using envelope encryption from Alibaba Cloud's KMS
# This script assumes a user has already generated a CMK and has access to the ID of the CMK in order to use it
import sys
import json
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from credentials import ACCESS_KEY_ID, ACCESS_KEY_SECRET, REGION, CMK_ID 
from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120 import DecryptRequest
    
# Instantiate an AliCloud client object
CLIENT = AcsClient(ACCESS_KEY_ID, ACCESS_KEY_SECRET, REGION)

# Decrypt Data Keys with Alibaba Cloud. Perform local file decryption using a plaintext Data Key
# Returns plaintext data
def envelope_decrypt(cipherText, encrypted_data_key, context):

    try:

        # Call the Alibaba Cloud Decrypt API for decryption, passing in the encryption context
        # This decrypts data using the *Master Key* (CMK)
        request = DecryptRequest.DecryptRequest()
        
        # Set parameters for JSON format, connection over TLS and associated encryption context 
        request.set_accept_format('json')
        request.set_protocol_type('https')
        request.set_EncryptionContext(context)

        # Set the ciphertext to decrypt
        request.set_CiphertextBlob(encrypted_data_key)

        # Call the Alibaba Cloud Encrypt API and parse the JSON response for the plaintext Data Key. 
        # Response also requires base64 decoding
        # Plaintext data key stored in mutable object which can later be zero'd
        response = CLIENT.do_action_with_exception(request)
        data_key = b64decode(json.loads(response)['Plaintext'])

        # Base64 decode the ciphertext
        cipherText = b64decode(cipherText)

        # Extract the Initialization Vector from ciphertext for subsequent AES decryption
        # Instantiate an AES cipher object and perform decryption of ciphertext data. Remove padding from plaintext
        iv = cipherText[:AES.block_size]
        cipher = AES.new(data_key[0], AES.MODE_CBC, iv)
        plainText = unpad(cipher.decrypt(cipherText[AES.block_size:]), AES.block_size)

        # Clear the data_key variable
        data_key[0] = 0

        return plainText  
    
    except ValueError as err:
        print("ERROR: Incorrect Decryption - {}".format(err))
        sys.exit(1)

# Main
def main():

    # Get user input. Filepaths for ciphertext data and where to write plaintext output
    ciphertext_filepath = sys.argv[1]
    plaintext_filepath = sys.argv[2]

    # Open the ciphertext data file and perform envelope decryption of its contents
    # Write plaintext to chosen output filepath
    with open(ciphertext_filepath, 'r') as fin:
        filedata = fin.read().split('*---*')
        cipherText = filedata[0]
        encrypted_data_key = filedata[1]
        encryption_context = filedata[2]

        # Write the plaintext to output file
        with open(plaintext_filepath, 'w') as fout:
            fout.write(envelope_decrypt(cipherText, encrypted_data_key, encryption_context))

if __name__ == '__main__':
    main() 