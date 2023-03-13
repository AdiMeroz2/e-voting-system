from DKB import DKB, VoterCertificate
from EVB import EVB
import rsa


if __name__ == '__main__':
    number_of_blocks = 1
    dkb = DKB(1)
    evb = EVB(1)
    # print("please enter name: ")
    name = "Alice"
    # print("please enter id: ")
    id = "1111"
    cer_1 = VoterCertificate(name, id)
    public_key, private_key, code_num = dkb.voter_identification(id, name)
    # print("please choose the candidate you wish to vote for: 1.xxx 2.yyy 3.zzz")
    vote = "1"
    evb.add_vote(rsa.encrypt(vote.encode(), dkb.get_public_key()),private_key, code_num, dkb)

    # print("please enter name: ")
    name = "Bob"
    print("please enter id: ")
    id = "2222"
    cer_2 = VoterCertificate(name, id)
    public_key, private_key, code_num = dkb.voter_identification(id, name)
    # print("please choose the candidate you wish to vote for: 1.xxx 2.yyy 3.zzz")
    vote = "2"
    evb.add_vote(rsa.encrypt(vote.encode(), dkb.get_public_key()), private_key, code_num, dkb)

    evb.get_results(dkb)
    dkb.print_results()