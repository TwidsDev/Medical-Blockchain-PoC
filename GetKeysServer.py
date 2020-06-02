# Code for the getting keys

# Import Cryptography library
# This allows us to make RSA keys that secures our program

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import base64


# This function will generate a public key and private key
def rsakeys():
     length=7936 # 7936 for the server and 1024 for the client
     privatekey = RSA.generate(length, Random.new().read)
     publickey = privatekey.publickey()
     return privatekey, publickey

def RSAmain():
    privatekey, publickey = rsakeys()

    # This gets the private key and put into a foramt that can be written into a file
    exportPK=privatekey.exportKey("PEM")
    f=open("PrivateKeyServer.txt", "w")
    f.write(exportPK.decode("UTF-8"))
    f.close()

    # This gets the publick key and put into a foramt that can be written into a file
    exportPBK=publickey.exportKey("PEM")
    f=open("PublicKeyServer.txt", "w")
    f.write(exportPBK.decode("UTF-8"))
    f.close()

# This find whether the code is being run from its source or from another python file. If its the former then this program will run.
if __name__ == "__main__":
   RSAmain()
