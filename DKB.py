from random import randint

import rsa


class Block:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.generate_key_pair()

    def generate_key_pair(self):
        public_key, private_key = rsa.newkeys(2048)
        self.public_key = public_key
        self.private_key = private_key

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.public_key

class BlockChain:
    def __init__(self):
        pass


class ProofOfWork:
    def __init__(self):
        pass


class DKB:
    def __init__(self, num):
        self.blocks = []
        self.block_num = num
        self.legal_voter_dic = {'1111': VoterCertificate("Alice", '1111'), '2222': VoterCertificate("Bob", '2222')}
        self.generate_blocks()

        self.certificate_codes = {}
        self.candidate = []

    def generate_blocks(self):
        for i in range(self.block_num):
            self.blocks.append(Block())

    def voter_identification(self, id_num, name):
        if self.check_if_valid_voter(id_num, name):
            ran_block_num = randint(0, self.block_num - 1)
            block = self.blocks[ran_block_num]
            code_num = self.simple_code_generator()
            self.certificate_codes[code_num] = self.legal_voter_dic[id_num]
            return ran_block_num, block.get_public_key(), code_num
        print("identification failed")
        return False

    def EVB_code_identification(self, code_num):
        if code_num in self.certificate_codes:
            self.certificate_codes.pop(code_num)
            return True
        return False

    def check_if_valid_voter(self, id_num, name):
        if id_num not in self.legal_voter_dic.keys():
            return False
        if not self.legal_voter_dic[id_num].same(name, id_num):
            return False
        if self.legal_voter_dic[id_num].get_voted_status():
            return False
        return True

    def simple_code_generator(self):
        code = randint(0, 1000)
        if code in self.certificate_codes.keys():
            code = randint(0,1000)
        return code

    def count_block_in_EVB(self, evb):
        for i in range(self.block_num):
            self.count_vote_in_block(evb,i)

    def count_vote_in_block(self, evb, block_num):
        for vote in evb.get_block(block_num):
            private_key = self.blocks[block_num].get_private_key()
            vote_res = rsa.decrypt(vote, private_key)
            self.candidate.append(vote_res.decode())
            print(vote_res.decode())

class VoterCertificate:
    def __init__(self, name, id_num):
        self.name = name
        self.id = id_num
        self.vote_status = False
        self.vote_code = None

    def __str__(self):
        return f"name: {self.name}, id: {self.id}, voted: {self.vote_status}"

    def same(self, other_name, other_id):
        return self.name == other_name and self.id == other_id

    def get_voted_status(self):
        return self.vote_status

    def set_voted(self):
        self.vote_status = True

    def encode(self):
        str_output = "{name}; {id}; {voted}".format(
            name=self.name,
            id=self.id,
            voted=self.vote_status
        )
        return bytes(str_output, 'utf-8')
