from DKB import DKB, VoterCertificate
from EVB import EVB
from Voter import Voter

def try_to_vote():
    # Ask the user for their name
    name = input("Please enter your name: ")
    id = input("Please enter your id: ")
    voter_1 = Voter(name=name, id=id)

    try:
        enc_public_key, enc_private_key = \
            dkb.voter_identification(voter_1.get_name(), voter_1.get_id(),voter_1.get_self_public_key())
        voter_1.set_key_pair(enc_public_key, enc_private_key)
        voter_1.choose_vote(candidates_list)
        packet_1 = voter_1.create_packet_to_EVB(dkb.public_key, evb.public_key)
        evb.get_packet_from_user(packet_1, dkb)
    except TypeError:
        print(f"{name} {id} Failed voting.")
    else:
        print(f"{name} {id} succeeded voting.")
    print()

if __name__ == '__main__':
    dkb = DKB()
    evb = EVB()

    candidates_list = dkb.get_candidates_list()

    print("---Voter 1 tried to vote:")
    # please enter : "Alice", "111111111"
    try_to_vote()
    print("---Voter 2 tried to vote:")
    # Please enter: name="Bob", id="222222222"
    try_to_vote()

    # voter tries to vote twice
    print("---Voter 2 tried to vote (again):")
    # Please enter: name="Bob", id="222222222"
    try_to_vote()

    # unregistered person tries to vote
    print("---unregistered voter tried to vote.")
    # please enter name="Joe", id="222222222"
    try_to_vote()
    voter_3 = Voter(name="Joe", id="222222222")

    evb.end_of_election()
    evb.get_results(dkb)
    dkb.print_results()
