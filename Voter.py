import rsa
import secrets


def generate_key_pair():
    """
    generates a new RSA key pair with a key size of 2048 bits.
    :return:
    """
    public_key, private_key = rsa.newkeys(2048)
    return public_key, private_key

class Voter:
    """
    A class that represents a voter in an electronic voting system.
    """

    def __init__(self, name, id):
        """
        Initializes a Voter object with a name and an ID, generates a random nonce and sets initial values for the
        voter_private_key, voter_public_key and vote.
        :param name:
        :param id:
        """
        self.self_public_key, self.self_private_key = generate_key_pair()

        self.voter_private_key = None  # changed to none
        self.voter_public_key = None
        self.vote = None
        self.name = name
        self.voter_id = id
        self.nonce = ''.join(secrets.choice('0123456789') for i in range(9))
        self.block_nonce = ''.join(secrets.choice('0123456789') for i in range(9)).encode()

    def get_self_public_key(self):
        return self.self_public_key

    def choose_vote(self, candidates_list: list):
        """
        Prompts the voter to choose a candidate from the given candidates_list and sets the vote attribute accordingly.
        :param candidates_list:
        :return:
        """
        vote = ""
        while not (vote.isdigit() and (0 < int(vote) < 10)):
            vote = input(f"chose number of candidate from the following list : \n{candidates_list}")
        self.vote = candidates_list[int(vote) - 1]

    def create_packet_to_EVB(self, DKB_publicKey, EVB_publicKey):
        """
        Creates a packet of data that includes the encrypted vote and nonce, encrypted private key, encrypted voter
         details and the signature. It takes in DKB_publicKey and EVB_publicKey as input parameters.
        :param DKB_publicKey:
        :param EVB_publicKey:
        :return:
        """
        print("stage: Voter " + self.voter_id + " cast his vote")

        private_key_bytes = self.voter_private_key.save_pkcs1(format='DER')

        # enc vote+nonce with DKB and then with publicKey
        data = self.RSA_encryption(DKB_publicKey, (self.vote + ',' + self.nonce).encode()) + self.block_nonce
        enc_vote = self.RSA_encryption(EVB_publicKey, data)
        enc_vote = self.RSA_encryption(self.voter_public_key, enc_vote)

        # enc privateKey with EVB
        enc_privateKey = self.RSA_encryption(EVB_publicKey, private_key_bytes)

        # enc voter details with DKB
        public_key_bytes = self.voter_public_key.save_pkcs1(format='DER')
        data = (str(self.voter_id) + ' ').encode() + public_key_bytes
        enc_voter_details = self.RSA_encryption(DKB_publicKey, data)

        signature = rsa.sign(enc_vote, self.voter_private_key, "SHA-256")

        return {
            "message": enc_vote,
            "signature": signature,
            "voter_details": enc_voter_details,
            "privateKey": enc_privateKey
        }

    def set_key_pair(self, encrypted_public_key, encrypted_private_key):
        """
        Sets the private and public key of the voter.
        :param private_key:
        :param public_key:
        :return:
        """
        decrypted_public_key_bytes = self.RSA_decryption(self.self_private_key,encrypted_public_key)
        self.voter_public_key = rsa.PublicKey.load_pkcs1(decrypted_public_key_bytes, format='DER')

        decrypted_private_key_bytes = self.RSA_decryption(self.self_private_key,encrypted_private_key)
        self.voter_private_key = rsa.PrivateKey.load_pkcs1(decrypted_private_key_bytes, format='DER')


    def get_name(self):
        """
        Returns the name of the Voter object.
        :return:
        """
        return self.name

    def get_id(self):
        """
        Returns the ID of the Voter object.
        :return:
        """
        return self.voter_id

    def RSA_encryption(self, key, byte_message):
        """
        Encrypts the byte_message using RSA encryption algorithm with the given key.
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
        Decrypts the message using RSA decryption algorithm with the given key.
        :param key:
        :param message:
        :return:
        """
        result = []
        for n in range(0, len(message), 256):
            part = message[n:n + 256]
            result.append(rsa.decrypt(part, key))
        return b''.join(result)
