from DKB import DKB, VoterCertificate
from EVB import EVB
from Voter import Voter
import rsa

# todo need to implement a list of candidate, and if the voter votes for an invalid candidate. then return false, haven't figure out where this feature should be
if __name__ == '__main__':
    dkb = DKB()
    evb = EVB()

    voter_1 = Voter(name="Alice", id="1111")  # todo maybe change this to something that asks input from the user
    cer_1 = VoterCertificate("Alice", "1111")  # todo this need to be crypted by DKB's publlic key
    public_key, private_key = dkb.voter_identification(voter_1.get_name(), voter_1.get_id())
    voter_1.set_key_pair(public_key=public_key, private_key=private_key)
    vote = "1"
    voter_1.choose_vote(vote)
    packet_1 = voter_1.create_packet_to_EVB(dkb.public_key, evb.public_key)
    evb.get_packet_from_user(packet_1, dkb)


    voter_2 = Voter(name="Bob", id="2222")
    cer_2 = VoterCertificate(voter_2.get_name(), voter_2.get_id())
    public_key, private_key = dkb.voter_identification(voter_2.get_name(), voter_2.get_id())
    voter_2.set_key_pair(public_key=public_key, private_key=private_key)
    vote = "2"
    voter_2.choose_vote(vote)
    packet_2 = voter_2.create_packet_to_EVB(dkb.public_key, evb.public_key)
    evb.get_packet_from_user(packet_2, dkb)

    evb.get_results(dkb)
    dkb.print_results()