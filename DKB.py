import rsa


class DKB:
    """
    In charge of identifying the voters,
    once identification success then chooses a random block and returns its public key
    """

    def __init__(self):
        """
        initializes the class and creates a dictionary of legal voters, generates a key pair, and initializes
         dictionaries to keep track of votes and certificate codes.
        """
        self.legal_voter_dic = {'111111111': VoterCertificate("Alice", '111111111'),
                                '222222222': VoterCertificate("Bob", '222222222')}

        self.certificate_codes = {}
        self.candidate_vote_num = {"Candidates 1": 0, "Candidates 2": 0, "Candidates 3": 0,
                                   "Candidates 4": 0, "Candidates 5": 0, "Candidates 6": 0,
                                   "Candidates 7": 0, "Candidates 8": 0, "Candidates 9": 0}

        self.public_key, self.private_key = self.generate_key_pair()
        self.generate_key_pair()

    def get_candidates_list(self):
        """
        returns a list of candidates.
        """
        return list(self.candidate_vote_num.keys())

    def generate_key_pair(self):
        """
        generates an RSA key pair and returns the public and private keys.
        :return:
        """
        public_key, private_key = rsa.newkeys(2048)
        return public_key, private_key

    def encrypt_keys(self,public_key,private_key,enc_key):
        # Convert keys to bytes
        public_key_bytes = public_key.save_pkcs1(format='DER')
        private_key_bytes = private_key.save_pkcs1(format='DER')

        # Encrypt the keys
        encrypted_public_key = self.RSA_encryption(enc_key,public_key_bytes)
        encrypted_private_key = self.RSA_encryption(enc_key,private_key_bytes)

        return encrypted_public_key,encrypted_private_key

    def voter_identification(self, name, id_num, id_public_key):
        """
        identifies the voter according to self.legal_voter_dic and returns the public key and private key for the voter.
        :param id_public_key:
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
            # return user_public_key, user_private_key
            return self.encrypt_keys(user_public_key, user_private_key,id_public_key)
        print("Unregistered. Identification failed for name: " + name + " , id:" + id_num)
        return None

    def check_if_valid_voter(self, id_num, name):
        """
        checks if the voter is valid based on their ID number and name.
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
        vote_nonce_res = rsa.decrypt(vote, self.private_key)
        vote_nonce_res = vote_nonce_res.decode()
        vote, nonce = vote_nonce_res.split(',')
        self.candidate_vote_num[vote] += 1

    def print_results(self):
        """
        prints the results of the election.
        :return:
        """
        print("THE RESULTS:")
        for candidate, votes in self.candidate_vote_num.items():
            print(f"candidate num: {candidate}, num of votes: {votes}")

    def get_public_key(self):
        """
        returns the public key for the DKB.
        :return:
        """
        return self.public_key

    def verify_voter_details_from_EVB(self, id: str, publicKey):
        """
        verifies that the ID and public key of the voter provided by EVB match the records in the system.
        :param id:
        :param publicKey:
        :return:
        """
        return id in self.legal_voter_dic.keys() \
               and self.legal_voter_dic[id].get_public_key().save_pkcs1(format='DER') == publicKey

    def verify_signature(self, vote, signature, voter_publicKey):
        """
        verifies that the vote was signed by the corresponding voter using their private key.
        :param vote:
        :param signature:
        :param voter_publicKey:
        :return:
        """
        try:
            rsa.verify(vote, signature, rsa.PublicKey.load_pkcs1(voter_publicKey, format='DER'))
        except (ValueError, TypeError):
            print("wrong signature")
            return False
        return True

    def verify_voter_details_and_signature(self, enc_message, enc_voter_details, signature):
        """
        decrypts the voter details using the DKB's private key, verifies the voter's ID and public key, verifies
        the signature, and marks the voter as having voted.
        :param enc_message:
        :param enc_voter_details:
        :param signature:
        :return:
        """
        voter_info = self.RSA_decryption(self.private_key, enc_voter_details)
        voter_id = voter_info[:9].decode()
        voter_public_key = voter_info[10:]
        if not self.verify_voter_details_from_EVB(voter_id, voter_public_key):
            print("invalid voter details")
            return False
        if not self.verify_signature(enc_message, signature, voter_public_key):
            print("invalid signature")
            return False
        if self.legal_voter_dic[voter_id].get_voted_status():
            print("voter can't vote twice")
            return False
        self.legal_voter_dic[voter_id].set_voted()
        print(voter_id + " - marked as voted.")
        return True

    def RSA_encryption(self, key, byte_message):
        """
        encrypts a byte message using RSA.
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
        decrypts a message using RSA.
        :param key:
        :param message:
        :return:
        """
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
