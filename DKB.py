from random import randint

import rsa
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


class DKB:
    """
    In charge of identifying the voters,
    once identification success then chooses a random block and returns its public key
    """
    def __init__(self):
        self.legal_voter_dic = {'1111': VoterCertificate("Alice", '1111'), '2222': VoterCertificate("Bob", '2222')} #todo temporary

        self.certificate_codes = {}
        self.candidate_vote_num = {}

        self.public_key, self.private_key = self.generate_key_pair()
        self.generate_key_pair()

    def generate_key_pair(self):
        public_key, private_key = rsa.newkeys(2048)
        return public_key, private_key

    # def generate_blocks(self):
    #     for i in range(self.block_num):
    #         self.blocks.append(Block())

    def voter_identification(self, name, id_num):
        """
        identifies the voter according to self.legal_voter_dic
        :param id_num: the id of the voter
        :param name: the voters name
        :return: in case of valid voter, the algorithm will return the following things:
                 * the number of block that has been chosen randomly
                 * the public key that the random block owns
                 * a code that the users uses to prove that he passed the identification
        """
        if self.check_if_valid_voter(id_num, name):
            # ran_block_num = randint(0, self.block_num - 1)
            # block = self.blocks[ran_block_num]
            # code_num = self.simple_code_generator()
            # self.certificate_codes[code_num] = self.legal_voter_dic[id_num]
            voter = self.legal_voter_dic[id_num]
            user_public_key, user_private_key = self.generate_key_pair()
            voter.set_public_key(user_public_key)
            return user_public_key, user_private_key
        print("identification failed")
        return False

    def check_if_valid_voter(self, id_num, name):
        """
        given the name and id number, checks if the person has the right to vote
        :param id_num:
        :param name:
        :return:
        """
        if id_num not in self.legal_voter_dic.keys():
            # invalid id number
            return False
        if not self.legal_voter_dic[id_num].same(name, id_num):
            # invalid information
            return False
        if self.legal_voter_dic[id_num].get_voted_status():
            # the voter already voted before
            return False
        return True

    def EVB_code_identification(self, code_num):
        """
        given a code, checks if the codes owner has passed the identification
        :param code_num:
        :return:
        """
        if code_num in self.certificate_codes:
            self.certificate_codes.pop(code_num)  # pops from the list so that a voter couldn't vote twice
            return True
        return False

    def simple_code_generator(self):
        # simple code generator to give the voter, maybe need to change
        code = randint(0, 1000)
        if code in self.certificate_codes.keys():
            code = randint(0,1000)
        return code

    def count_block_in_EVB(self, evb):
        """
        goes through the blocks in the EVB, and counts the votes in each block
        :param evb:
        :return:
        """
        for i in range(self.block_num):
            self.count_vote_in_block(evb,i)

    def count_vote_in_block(self, evb, block_num):
        """
        decrypt the voted in the EVB block by using the private key
        :param evb:
        :param block_num:
        :return:
        """
        for vote in evb.get_block(block_num):
            private_key = self.blocks[block_num].get_private_key()
            vote_res = rsa.decrypt(vote, private_key)
            vote_res = vote_res.decode()
            if vote_res not in self.candidate_vote_num.keys():
                self.candidate_vote_num[vote_res] = 1
            else:
                self.candidate_vote_num[vote_res] += 1

    def count_vote(self, vote):
        vote_res = rsa.decrypt(vote,self.private_key)
        vote_res = vote_res.decode()
        if vote_res not in self.candidate_vote_num.keys():
            self.candidate_vote_num[vote_res] = 1
        else:
            self.candidate_vote_num[vote_res] += 1

    def print_results(self):
        for candidate, votes in self.candidate_vote_num.items():
            print(f"candidate num: {candidate}, num of votes: {votes}")

    def get_public_key(self):
        return self.public_key

    """new added func"""
    def decrypte_data(self, encrypted_data, privateKey):
        # Decrypt vote with private key
        # cipher_DKB = PKCS1_OAEP.new(privateKey)
        # data = cipher_DKB.decrypt(encrypted_data)
        # return data.decode()
        return rsa.decrypt(encrypted_data, privateKey)

    def verify_voter_details_from_EVB(self,id, publicKey): # todo: need to add to dict (in the init) the voter keys
        return id in self.legal_voter_dic.keys() \
               and self.legal_voter_dic[id]["publicKey"] == publicKey

    def verify_signature(self, enc_message, signature,voter_publicKey):
        h = SHA256.new(enc_message)
        try:
            # pkcs1_15.new(voter_publicKey).verify(h, signature)
            rsa.verify(enc_message, signature, voter_publicKey)
        except (ValueError, TypeError):
            return False
        return True

    def verify_voter_details_and_signature(self,enc_message, enc_voter_details, signature):
        # after receiving voter details and signature
        id, voter_publicKey = self.decrypte_data(enc_voter_details,self.private_key).split()
        # voter_publicKey = RSA.import_key(voter_publicKey)
        if not self.verify_voter_details_from_EVB(id,voter_publicKey):
            return False
        if not self.verify_signature(enc_message,signature,voter_publicKey):
            return False
        return True

class VoterCertificate:
    # once a person is verified as a legal voter, his status would be stored in this class
    def __init__(self, name, id_num):
        self.name = name
        self.id = id_num
        self.vote_status = False
        self.vote_code = None
        self.public_key = None

    def __str__(self):
        return f"name: {self.name}, id: {self.id}, voted: {self.vote_status}"

    def same(self, other_name, other_id):
        return self.name == other_name and self.id == other_id

    def get_voted_status(self):
        return self.vote_status

    def set_voted(self):
        self.vote_status = True

    def encode_certification(self):
        # not sure if need this
        str_output = "{name}; {id}; {voted}".format(
            name=self.name,
            id=self.id,
            voted=self.vote_status
        )
        return bytes(str_output, 'utf-8')

    def get_public_key(self):
        return self.public_key

    def set_public_key(self, public_key):
        self.public_key = public_key