from DKB import DKB, VoterCertificate
from EVB import EVB
import rsa


if __name__ == '__main__':
    number_of_blocks = 1
    dkb = DKB(1)
    evb = EVB(1)
    print("please enter name: ")
    name = input()
    print("please enter id: ")
    id = input()
    cer = VoterCertificate(name, id)
    block_num, public_key, code_num = dkb.voter_identification(id, name)
    print("please choose the candidate you wish to vote for: 1.xxx 2.yyy 3.zzz")
    vote = input()
    evb.add_vote(block_num, rsa.encrypt(vote.encode(), public_key),code_num, dkb)

    dkb.count_block_in_EVB(evb)