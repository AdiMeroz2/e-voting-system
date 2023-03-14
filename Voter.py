import rsa
from Crypto.Hash import SHA256

class Voter:
    def __init__(self, name, id):
        self.voter_privateKey = None  # changed to none
        self.voter_public_key = None
        self.vote = None
        self.name = name
        self.voter_id = id
        self.nonce = b"123456789"  # example nonce

    def choose_vote(self, choice):
        self.vote = choice

    def encrypt_with_publicKey(self, data, publicKey):
        # cipher = PKCS1_OAEP.new(publicKey)
        # encrypted_data = cipher.encrypt(data)
        # return encrypted_data
        return rsa.encrypt(data, publicKey)

    # todo: do also authentication ?

    def create_packet_to_EVB(self, DKB_publicKey, EVB_publicKey):
        # calc hash private key
        privateKey_hash = SHA256.new(self.voter_privateKey.export_key()).digest()

        # enc vote+nonce with DKB and then with publicKey
        data = self.vote.encode() + self.nonce
        enc_vote = self.encrypt_with_publicKey(data, DKB_publicKey)
        enc_vote = self.encrypt_with_publicKey(enc_vote, self.voter_public_key)

        # enc privateKey with EVB
        enc_privateKey = self.encrypt_with_publicKey(self.voter_privateKey, EVB_publicKey)

        # enc voter details with DKB
        data = (str(self.voter_id) + ' ').encode() + self.voter_public_key.export_key()
        enc_voter_details = self.encrypt_with_publicKey(data, DKB_publicKey)

        # h = SHA256.new(privateKey_hash + enc_vote)
        # signature = pkcs1_15.new(self.voter_privateKey).sign(h)
        signature = rsa.sign(privateKey_hash + enc_vote, self.voter_privateKey, "SHA-256")

        return {
            "message": privateKey_hash + enc_vote,
            "signature": signature,
            "voter_details": enc_voter_details,
            "privateKey": enc_privateKey
        }

    def decrypte_data(self, encrypted_data, privateKey):
        # Decrypt vote with private key
        # cipher_DKB = PKCS1_OAEP.new(privateKey)
        # data = cipher_DKB.decrypt(encrypted_data)
        # return data.decode()
        return rsa.decrypt(encrypted_data, privateKey)

    def set_key_pair(self, private_key, public_key):
        self.voter_privateKey = private_key
        self.voter_public_key = public_key

    def get_name(self):
        return self.name

    def get_id(self):
        return self.voter_id