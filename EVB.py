from datetime import time

import rsa

from DKB import DKB, VoterCertificate
from BlockChain import Block, Blockchain
from nacl.encoding import Base64Encoder
# import base64
from base64 import b64decode

class EVB:
    def __init__(self, num):
        self.blocks = []
        self.block_num = num
        self.used_certificate_nums = {}

        self.blockchain = Blockchain()

    def add_vote(self, crypted_vote, nonce, private_key, dkb):
        # todo check candidate valid
        # todo DKB identification
        # if dkb.EVB_code_identification(code_num):
        #     self.blocks[block_num].add_vote(crpted_vote)
        #     print("ok")
        self.vote(crypted_vote, private_key, nonce)


    def get_block(self, num):
        if num < len(self.blocks):
            return self.blocks[num].get_votings()

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
        print("Vote recorded successfully.")

        return new_block.index

    def get_results(self, dkb):
        for vote in self.blockchain.chain[1:]:
            dkb.count_vote(bytes(vote.transactions.encode("latin1")))


