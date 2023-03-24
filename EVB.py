import random

import rsa
from BlockChain import Block, Blockchain


class EVB:
    BLOCK_NONCE_INDEX = 9
    MAX_STORE_VOTE_NUM = 10

    def __init__(self):
        self.used_certificate_nums = {}

        self.blockchain = Blockchain()
        self.public_key, self.private_key = self.generate_key_pair()

        self.vote_list = {}  # todo added
        self.counter = 0

    def generate_key_pair(self):
        """
        generates a new RSA key pair with a key size of 2048 bits.
        :return:
        """
        public_key, private_key = rsa.newkeys(2048)
        return public_key, private_key

    def vote(self):
        """
        Creates a new block with the encrypted vote and nonce, adds it to the blockchain, and returns its index.
        :param crypted_vote:
        :param nonce:
        :return:
        """
        last_block = self.blockchain.last_block
        random_num, vote_info = random.choice(list(self.vote_list.items()))
        new_block = Block(index=last_block.index + 1,
                          vote=vote_info.vote.decode("latin1"),
                          previous_hash=last_block.hash,
                          nonce=vote_info.nonce)

        proof = self.blockchain.proof_of_work(new_block)
        self.blockchain.add_block(new_block, proof)
        self.vote_list.pop(random_num)
        return new_block.index

    def get_results(self, dkb):
        """
        Iterates through the blockchain and sends each block to DKB in order to calculate the voting result.        :param dkb:
        :return:
        """
        for vote in self.blockchain.chain[1:]:
            dkb.count_vote(bytes(vote.transactions.encode("latin1")))

    def get_packet_from_user(self, packet, dkb):
        """
        Decrypts the relevant messages from the packet, verifies the voter details and signature with DKB, and adds
        the decrypted vote to the blockchain.
        :param packet: the packet is in the format of { "message": VoterPrivateKey_Encrypt[enc_vote + nonce],
                                                        "signature": signature signed with voter's private key,
                                                        "voter_details": EVBPublicKey_Encrypt[voter's id + voter's private key],
                                                        "privateKey": EVBPublicKey_Encrypt[enc_privateKey] }
        :param dkb:
        :return:
        """
        # get private key
        voter_private_key = packet["privateKey"]
        voter_private_key = self.RSA_decryption(self.private_key, voter_private_key)
        voter_private_key = rsa.PrivateKey.load_pkcs1(voter_private_key, format='DER')

        # # verify signature
        message = packet["message"]

        # send voter detail to DKB
        if not dkb.verify_voter_details_and_signature(
                enc_message=message,
                enc_voter_details=packet["voter_details"],
                signature=packet["signature"]):
            print("invalid try to vote.")
            raise TypeError

        # get vote and nonce from message
        message = self.RSA_decryption(voter_private_key, message)
        message = self.RSA_decryption(self.private_key, message)
        vote = message[:len(message) - EVB.BLOCK_NONCE_INDEX]
        nonce = message[len(message) - EVB.BLOCK_NONCE_INDEX:].decode()

        self.vote_list[self.counter] = self.crypted_vote(vote, nonce)
        self.counter += 1
        if len(self.vote_list) >= self.MAX_STORE_VOTE_NUM:
            # add the vote to blockchain
            self.vote()

    def verify_signature(self, enc_message, signature, voter_Key):
        """
        Verifies the signature of an encrypted message using the voter's public key.
        :param enc_message:
        :param signature:
        :param voter_Key:
        :return:
        """
        try:
            rsa.verify(enc_message, signature, voter_Key)
        except (ValueError, TypeError):
            return False
        return True

    def end_of_election(self):
        for i in range(len(self.vote_list)):
            self.vote()

    def RSA_encryption(self, key, byte_message):
        """
        Encrypts a message using RSA encryption with the given public key.
        :param key:
        :param byte_message:
        :return:
        """
        result = []
        for n in range(0, len(byte_message), 245):
            part = byte_message[n:n + 245]
            result.append(rsa.encrypt(part, key))
        return b''.join(result)

    def RSA_decryption(self, key, message):
        """
        Decrypts a message using RSA encryption with the given private key.
        :param key:
        :param message:
        :return:
        """
        result = []
        for n in range(0, len(message), 256):
            part = message[n:n + 256]
            result.append(rsa.decrypt(part, key))
        return b''.join(result)

    class crypted_vote:
        def __init__(self, vote, nonce):
            self.vote = vote
            self.nonce = nonce
