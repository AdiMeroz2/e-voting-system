import rsa
from Crypto.Hash import SHA256


class DKB:
    """
    In charge of identifying the voters,
    once identification success then chooses a random block and returns its public key
    """

    def __init__(self):
        self.legal_voter_dic = {'1111': VoterCertificate("Alice", '1111'),
                                '2222': VoterCertificate("Bob", '2222')}  # todo temporary

        self.certificate_codes = {}
        self.candidate_vote_num = {}

        self.public_key, self.private_key = self.generate_key_pair()
        self.generate_key_pair()

    def generate_key_pair(self):
        public_key, private_key = rsa.newkeys(2048)
        return public_key, private_key

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

    def count_vote(self, vote):
        """
        get a vote from EVB and decrypt it, and then counts the vote by adding it to candidate_vote_num dictionary
        :param vote:
        :return:
        """
        vote_res = rsa.decrypt(vote, self.private_key)
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

    def get_voter_from_EVB(self, enc_voter_details):
        """
        gets the voter's information from EVB and verifies it's identity
        :param enc_voter_details:
        :return:
        """
        voter_info = self.RSA_decryption(self.private_key, enc_voter_details)
        voter_id = voter_info[:4]  # todo think of a better way to get the id and public key
        voter_public_key = voter_info[5:]
        return self.verify_voter_details_from_EVB(voter_id.decode(), voter_public_key)

    def verify_voter_details_from_EVB(self, id: str, publicKey):
        return id in self.legal_voter_dic.keys() \
               and self.legal_voter_dic[id].get_public_key().save_pkcs1(format='DER') == publicKey

    def verify_signature(self, enc_message, signature, voter_publicKey):
        # todo currently the DKB doesn't receives any signature
        try:
            rsa.verify(enc_message, signature, voter_publicKey)
        except (ValueError, TypeError):
            return False
        return True

    def verify_voter_details_and_signature(self, enc_message, enc_voter_details, signature):
        # todo currently the DKB doesn't receives any signature
        # after receiving voter details and signature
        id, voter_publicKey = self.RSA_decryption(self.private_key, enc_voter_details).split()
        # voter_publicKey = RSA.import_key(voter_publicKey)
        if not self.verify_voter_details_from_EVB(id, voter_publicKey):
            return False
        if not self.verify_signature(enc_message, signature, voter_publicKey):
            return False
        return True

    def RSA_encryption(self, key, byte_message):
        result = []
        for n in range(0, len(byte_message), 245):
            part = byte_message[n:n + 245]
            result.append(rsa.encrypt(part, key))
        return b''.join(result)

    def RSA_decryption(self, key, message):
        result = []
        for n in range(0, len(message), 256):
            part = message[n:n + 256]
            result.append(rsa.decrypt(part, key))
        return b''.join(result)


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
