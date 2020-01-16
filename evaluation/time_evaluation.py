from zero_knowledge_proofs.ff_based.linear_algebra.modular_addition import ModularAdditionZKP, generate_dummy_data
from zero_knowledge_proofs.ff_based.linear_algebra.modular_multiplication import ModularMultiplicationZKP
from zero_knowledge_proofs.ff_based.proof_range_ff import ProofRange
from zero_knowledge_proofs.ff_based.proof_signature_from_set import ProofSignatureSet, dummy_data, dummy_roots

from primitives.algebra_lib import FFGroup
from primitives.pedersen import PublicKey, Commitment
from primitives.polynomial import Polynomial

import matplotlib.pyplot as plt
import numpy as np
from petlib.bn import Bn
from time import time
from scipy import mean
import csv


def modular_addition():
    added_value1, added_value2, result, modulo = generate_dummy_data()
    G = FFGroup()
    order = G.order()
    com_pk = PublicKey(G, 1)
    random_comm_add1 = order.random()
    random_comm_add2 = order.random()
    random_comm_res = order.random()
    random_comm_modulo = order.random()
    commitment_added_1 = com_pk.commit([added_value1], random_comm_add1)
    commitment_added_2 = com_pk.commit([added_value2], random_comm_add2)
    commitment_result = com_pk.commit([result], random_comm_res)
    commitment_modulo = com_pk.commit([modulo], random_comm_modulo)

    proof = ModularAdditionZKP(com_pk, added_value1, added_value2, result, modulo, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo, random_comm_add1, random_comm_add2, random_comm_res, random_comm_modulo)
    print(proof.verify(com_pk, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo))

    print("Time range proofs: ", proof.time_secret_exponent - proof.time_range_proofs)
    print("Time secret exponent: ", proof.time_end - proof.time_secret_exponent)


def modular_multiplication():
    added_value1, added_value2, result, modulo = generate_dummy_data()
    G = FFGroup()
    order = G.order()
    com_pk = PublicKey(G, 1)
    random_comm_add1 = order.random()
    random_comm_add2 = order.random()
    random_comm_res = order.random()
    random_comm_modulo = order.random()
    commitment_added_1 = com_pk.commit([added_value1], random_comm_add1)
    commitment_added_2 = com_pk.commit([added_value2], random_comm_add2)
    commitment_result = com_pk.commit([result], random_comm_res)
    commitment_modulo = com_pk.commit([modulo], random_comm_modulo)

    proof = ModularMultiplicationZKP(com_pk, added_value1, added_value2, result, modulo, commitment_added_1,
                                     commitment_added_2, commitment_result, commitment_modulo, random_comm_add1,
                                     random_comm_add2, random_comm_res, random_comm_modulo)
    time_verify = time()
    print(proof.verify(com_pk, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo))
    time_verify_end = time()

    print("Time range proofs: ", proof.time_secret_exponent - proof.time_range_proofs)
    print("Time secret exponent: ", proof.time_end - proof.time_secret_exponent)
    print("Time verification: ", time_verify_end - time_verify)


def range_proofs():
    G = FFGroup()
    com_pk = PublicKey(G, 1)
    order = com_pk.order
    number = Bn.from_num(7)
    random_commitment = order.random()
    commitment = com_pk.commit([number], random_commitment)
    lower_bound = Bn.from_num(3)
    upper_bound = Bn.from_num(9)
    proof = ProofRange(com_pk, number, commitment, random_commitment, lower_bound, upper_bound)
    print(proof.verify(com_pk, commitment, lower_bound, upper_bound))

    print("time setting: ", proof.time_setting - proof.time_init)
    print("time same log: ", proof.time_proof_same_log - proof.time_init)
    print("time square 1: ", proof.time_proof_square - proof.time_proof_same_log)
    print("time square 2: ", proof.time_proof_second_square - proof.time_proof_square)
    print("time responses: ", proof.time_response_calc - proof.time_proof_second_square)


def signature_from_set(size_set=5):
    G = FFGroup()
    order = G.order()
    com_pk = PublicKey(G, 1)
    signed_message, message, exponent, modulo = dummy_data()
    roots = dummy_roots(modulo, size_set)
    polynomial = Polynomial.from_roots_opt(roots, order)
    polynomial_list = polynomial.coefficients

    proof = ProofSignatureSet(com_pk, signed_message, message, modulo, polynomial_list)
    proof.verify(com_pk, message, polynomial_list)

    return proof.time_ful_membership_proof, proof.time_ful_sig_proof, proof.time_ful_membership_verif, proof.time_ful_sig_verif


def average_signature_from_set(repetitions=10, sizes_set=[4, 8, 16]):
    G = FFGroup()
    order = G.order()
    com_pk = PublicKey(G, 1)
    signed_message, message, exponent, modulo = dummy_data()

    time_full_membership_proof = []
    time_full_sig_proof = []
    time_full_membership_verif = []
    time_full_sig_verif = []
    for size in sizes_set:
        print(size)
        mem_proof = []
        sig_proof = []
        mem_verif = []
        sig_verif = []
        roots = dummy_roots(modulo, size)
        polynomial = Polynomial.from_roots_opt(roots, order)
        polynomial_list = polynomial.coefficients
        for _ in range(repetitions):
            print(_)
            proof = ProofSignatureSet(com_pk, signed_message, message, modulo, polynomial_list)
            proof.verify(com_pk, message, polynomial_list)

            mem_proof.append(proof.time_ful_membership_proof)
            sig_proof.append(proof.time_ful_sig_proof)
            mem_verif.append(proof.time_ful_membership_verif)
            sig_verif.append(proof.time_ful_sig_verif)

        time_full_membership_proof.append(mean(mem_proof))
        time_full_sig_proof.append(mean(sig_proof))
        time_full_membership_verif.append(mean(mem_verif))
        time_full_sig_verif.append(mean(sig_verif))

    with open('./correct_decryption.csv', 'w', newline='') as file:
        filewriter = csv.writer(file, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for i in range(len(sizes_set)):
            filewriter.writerow([sizes_set[i], time_full_membership_proof[i], time_full_sig_proof[i], time_full_membership_verif[i], time_full_sig_verif[i]])


sizes_set = list(np.linspace(1, 512, num=20, dtype=int))
average_signature_from_set(repetitions=10, sizes_set=sizes_set)


number_keys = []
proof_time = []
verif_time = []
with open('correct_decryption.csv','r') as csvfile:
    plots = csv.reader(csvfile, delimiter=',')
    for row in plots:
        number_keys.append(int(row[0]))
        proof_time.append(float(row[1]) + float(row[2]))
        verif_time.append(float(row[3]) + float(row[4]))

plt.plot(number_keys, proof_time, 'b-', label='Proof time')
plt.plot(number_keys, verif_time, 'r-', label='Verif time')
plt.xlabel('Number Keys')
plt.ylabel('Time (s)')
plt.title('Proof of ownership if RSA signature')
plt.legend()
plt.show()
plt.savefig('proof_sig_ownership.png')
# modular_addition()
# modular_multiplication()
# range_proofs()
