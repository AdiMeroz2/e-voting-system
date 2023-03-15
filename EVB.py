from datetime import time

import rsa
from Crypto.Hash import SHA256
from DKB import DKB, VoterCertificate
from BlockChain import Block, Blockchain
from nacl.encoding import Base64Encoder
# import base64
from base64 import b64decode

# todo need to add timestamp or something instead
class EVB:
    def __init__(self):
        self.used_certificate_nums = {}

        self.blockchain = Blockchain()
        self.public_key ,self.private_key = self.generate_key_pair()

    def generate_key_pair(self):
        public_key, private_key = rsa.newkeys(2048)
        return public_key, private_key

    def vote(self, crypted_vote, private_key, nonce):
        # todo before this step vote must be valid

        # block = {"vote": crypted_vote, "private key": private_key}
        last_block = self.blockchain.last_block
        new_block = Block(index=last_block.index + 1,
                          vote=crypted_vote.decode("latin1"),
                          previous_hash=last_block.hash,
                          nonce=nonce)

        proof = self.blockchain.proof_of_work(new_block)
        self.blockchain.add_block(new_block, proof)
        return new_block.index

    def get_results(self, dkb):
        for vote in self.blockchain.chain[1:]:
            dkb.count_vote(bytes(vote.transactions.encode("latin1")))

    def get_packet_from_user(self, packet, dkb):
        # get private key
        voter_private_key = packet["privateKey"]
        voter_private_key = self.RSA_decryption(self.private_key, voter_private_key)
        voter_private_key = rsa.PrivateKey.load_pkcs1(voter_private_key, format='DER')
        # verify signature
        message = packet["message"]
        self.verify_signature(packet["privateKey"] + message, packet["signature"], voter_private_key)
        # send voter detail to DKB
        if not dkb.get_voter_from_EVB(packet["voter_details"]):
            print("invalid voter information")
            return

        message = self.RSA_decryption(voter_private_key, message)
        message = self.RSA_decryption(self.private_key, message)
        vote = message[:len(message)-9]  # todo need to think of something more correct for getting vote and nonce
        nonce = message[len(message)-9:].decode()
        print(f"vote:{vote}")
        print(f"nonce: {nonce}")
        self.vote(vote, voter_private_key, nonce)


    def verify_signature(self, enc_message, signature,voter_Key):
        h = SHA256.new(enc_message)
        try:
            # pkcs1_15.new(voter_publicKey).verify(h, signature)
            rsa.verify(enc_message, signature, voter_Key)
        except (ValueError, TypeError):
            return False
        return True

    def RSA_encryption(self, key, byte_message):
        # (public_key, private_key) = get_keys()
        # txt = json.dumps(txt)
        result = []
        for n in range(0,len(byte_message),245):
            part = byte_message[n:n+245]
            result.append(rsa.encrypt(part, key))
        # print(len(result),len(result[0]))
        return b''.join(result)

    def RSA_decryption(self, key, message):
        # (public_key, private_key) = get_keys()
        result = []
        for n in range(0,len(message),256):
            part = message[n:n+256]
            result.append(rsa.decrypt(part, key))
        # result = json.loads(''.join(result))
        return b''.join(result)