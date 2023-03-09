from DKB import DKB, VoterCertificate

class Block:
    def __init__(self):
        self.voting_list = []

    def add_vote(self, vote):
        self.voting_list.append(vote)

    def get_votings(self):
        return self.voting_list

class BlockChain:
    def __init__(self):
        pass

class EVB:
    def __init__(self, num):
        self.blocks = []
        self.block_num = num
        self.generate_blocks()
        self.used_certificate_nums = {}

    def generate_blocks(self):
        for i in range(self.block_num):
            self.blocks.append(Block())

    def add_vote(self, block_num, crpted_vote, code_num, dkb):
        # todo check certification before adding vote
        # todo shouldn't allow to vote twice
        if dkb.EVB_code_identification(code_num):
            self.blocks[block_num].add_vote(crpted_vote)
            print("ok")

    def get_block(self, num):
        if num < len(self.blocks):
            return self.blocks[num].get_votings()

