import rsa
from Crypto.Hash import SHA256
from hashlib import sha512


# todo need to add function that implements nonce
class Voter:
    def __init__(self, name, id):
        self.voter_private_key = None  # changed to none
        self.voter_public_key = None
        self.vote = None
        self.name = name
        self.voter_id = id
        self.nonce = b"123456789"  # example nonce

    def choose_vote(self, choice):
        self.vote = choice

    # todo: do also authentication ?

    def create_packet_to_EVB(self, DKB_publicKey, EVB_publicKey):
        # calc hash private key
        private_key_bytes = self.voter_private_key.save_pkcs1(format='DER')
        # privateKey_hash = SHA256.new(private_key_bytes).digest()  #todo unable to unhash
        privateKey_hash = self.RSA_encryption(DKB_publicKey, private_key_bytes)

        # enc vote+nonce with DKB and then with publicKey
        data = self.RSA_encryption(DKB_publicKey, self.vote.encode()) + self.nonce
        enc_vote = self.RSA_encryption(EVB_publicKey, data)
        enc_vote = self.RSA_encryption(self.voter_public_key, enc_vote)

        # enc privateKey with EVB
        enc_privateKey = self.RSA_encryption(EVB_publicKey, private_key_bytes)

        # enc voter details with DKB
        public_key_bytes = self.voter_public_key.save_pkcs1(format='DER')
        data = (str(self.voter_id) + ' ').encode() + public_key_bytes
        enc_voter_details = self.RSA_encryption(DKB_publicKey, data)

        # h = SHA256.new(privateKey_hash + enc_vote)
        # signature = pkcs1_15.new(self.voter_privateKey).sign(h)
        # signature = rsa.sign(privateKey_hash + enc_vote, self.voter_private_key, "SHA-256") # todo why does the message contain private key hash?
        signature = rsa.sign(enc_privateKey + enc_vote, self.voter_private_key, "SHA-256")

        return {
            # "message": privateKey_hash + enc_vote,  # todo why does the message contain private key hash?
            "message": enc_vote,
            "signature": signature,
            "voter_details": enc_voter_details,
            "privateKey": enc_privateKey
        }

    def set_key_pair(self, private_key, public_key):
        """ set the private and public key of the voter"""
        self.voter_private_key = private_key
        self.voter_public_key = public_key

    def get_name(self):
        return self.name

    def get_id(self):
        return self.voter_id

    def RSA_encryption(self, key, byte_message):
        result = []
        for n in range(0,len(byte_message),245):
            part = byte_message[n:n+245]
            result.append(rsa.encrypt(part, key))
        return b''.join(result)

    def RSA_decryption(self, key, message):
        result = []
        for n in range(0,len(message),256):
            part = message[n:n+256]
            result.append(rsa.decrypt(part, key))
        return b''.join(result)