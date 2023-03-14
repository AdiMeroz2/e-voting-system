from DKB import DKB, VoterCertificate
from EVB import EVB
from Voter import Voter
import rsa


if __name__ == '__main__':
    dkb = DKB()
    evb = EVB()

    voter_1 = Voter(name="Alice", id="1111")  # todo maybe change this to something that asks input from the user
    cer_1 = VoterCertificate("Alice", "1111")
    public_key, private_key = dkb.voter_identification(voter_1.get_name(), voter_1.get_id())
    # print("please choose the candidate you wish to vote for: 1.xxx 2.yyy 3.zzz")
    vote = "1"
    evb.add_vote(rsa.encrypt(vote.encode(), dkb.get_public_key()),private_key, voter_1.nonce, dkb)

    voter_2 = Voter(name="Bob", id="2222")
    cer_2 = VoterCertificate(voter_2.get_name(), voter_2.get_id())
    public_key, private_key = dkb.voter_identification(voter_2.get_name(), voter_2.get_id())
    # print("please choose the candidate you wish to vote for: 1.xxx 2.yyy 3.zzz")
    vote = "2"
    evb.add_vote(rsa.encrypt(vote.encode(), dkb.get_public_key()), private_key, voter_2.nonce, dkb)

    evb.get_results(dkb)
    dkb.print_results()