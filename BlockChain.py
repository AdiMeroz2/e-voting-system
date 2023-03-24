from hashlib import sha256
import secrets


class Block:
    """
    The Block class represents a single block in the blockchain.
    """

    def __init__(self, index, vote, previous_hash, nonce):
        self.index = index
        self.transactions = vote
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash= 0


    def __str__(self):
        return f"Block(index={self.index}, transactions={self.transactions}, previous_hash={self.previous_hash}, nonce={self.nonce})"

    def compute_hash(self):
        """
        Hashing each block ensures the security of each one individually,
        making it extremely difficult to tamper with the data within the blocks
        :return:
        """
        block_string = str(self).encode('utf-8')
        return sha256(block_string).hexdigest()


class Blockchain:
    """
    The Blockchain class represents the entire blockchain.
    """

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()
        self.difficulty = 2

    def create_genesis_block(self):
        """
        creates the genesis block, which is the first block in the blockchain.
        :return:
        """
        genesis_block = Block(0, [], None,secrets.randbits(9))
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        """
        returns the last block in the chain.
        :return:
        """
        return self.chain[-1]

    def proof_of_work(self, block):
        """
        implements the proof-of-work algorithm, which is used to create a new block.
        computes the hash value of the block by randomizing the nonce value until the hash value starts with
         difficulty number of zeroes.
        :param block:
        :return:
        """
        block.nonce = secrets.randbits(9)
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce = secrets.randbits(9)
            computed_hash = block.compute_hash()
        return computed_hash

    def add_block(self, block, proof):
        """
        adds a block to the chain by first checking that the previous_hash value of the block matches the hash
        value of the previous block in the chain. It then checks that the provided proof value is valid by computing
        the hash of the block and comparing it to the provided proof value. If both checks pass, the block is added
        to the chain.
        :param block:
        :param proof:
        :return:
        """
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            # checks that proof == block.compute_hash()
            return False
        block.hash = proof
        self.chain.append(block)
        return True

    def is_valid_proof(self, block, block_hash):
        """
        checks if a provided block_hash value is a valid proof of work for a given block. It checks that the hash value
        starts with difficulty number of zeroes and that it matches the hash value of the block.
        :param block:
        :param block_hash:
        :return:
        """
        return (block_hash.startswith('0' * self.difficulty) and
                block_hash == block.compute_hash())

    def add_new_transaction(self, transaction):
        """
        Addes a new transaction to the unconfirmed transactions.
        :param transaction:
        :return:
        """
        self.unconfirmed_transactions.append(transaction)

    def mine(self):
        """
        Mines a new block and adds it to the blockchain if there are any unconfirmed transactions.
        If there are no unconfirmed transactions in the blockchain, the function returns False.
        :return:
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block
        new_block = Block(
            index=last_block.index + 1,
            vote=self.unconfirmed_transactions,
            previous_hash=last_block.hash,
            nonce=None
        )
        proof = self.proof_of_work(block=new_block)
        self.add_block(new_block, proof)
        self.unconfirmed_transactions = []

        return new_block.index
