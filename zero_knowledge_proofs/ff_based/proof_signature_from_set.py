from petlib.bn import Bn
from time import time

from primitives.algebra_lib import FFGroup
from primitives.pedersen import PublicKey
from primitives.polynomial import Polynomial

from zero_knowledge_proofs.ff_based.linear_algebra.modular_exponantiation import ModularExponantiation
from zero_knowledge_proofs.ff_based.proof_poly_eval_ff import PolynomialProof


class ProofSignatureSet:
    """
    We provide a proof which allows a prover to show a verifier that it owns a signature over a message with a key
    which is among a set of other keys without disclosing which.

    We follow the construction explained in the paper ATLaS from Nappa et al.
    """

    def __init__(self, com_pk, signature, message, modulus, polynomial_list):
        self.order = com_pk.group.order()
        random_commitment_modulo = self.order.random()
        self.commitment_modulo = com_pk.commit([modulus], random_commitment_modulo)
        time_sig_verif = time()
        self.signature_verification_proof = ModularExponantiation(com_pk, signature, message, modulus,
                                                             self.commitment_modulo, random_commitment_modulo,
                                                             upper_bound_moduli=2049)

        self.time_ful_sig_proof = time() - time_sig_verif

        time_membership_proof = time()
        random_commitment_zero = Bn.from_num(0)
        commitment_zero = com_pk.commit([Bn.from_num(0)], random_commitment_zero)

        self.set_membership_proof = PolynomialProof(com_pk, polynomial_list, self.commitment_modulo, commitment_zero, modulus,
                                               Bn.from_num(0), random_commitment_modulo, random_commitment_zero)
        self.time_ful_membership_proof = time() - time_membership_proof

    def verify(self, com_pk, message, polynomial_list):
        """
        This contains the whole proof. First the prover shows that it owns a signature from an RSA key (without
        disclosing the key), and then it proves that this particular committed key is the root of a given polynomial.

        Note that this proof can only be used for a set where all public keys of the set have the same exponent. In our
        particular case, for e = 65537.

        Example:
            >>> G = FFGroup()
            >>> order = G.order()
            >>> com_pk = PublicKey(G, 1)
            >>> signed_message, message, exponent, modulo = dummy_data()
            >>> roots = dummy_roots(modulo, 5)
            >>> polynomial = Polynomial.from_roots_opt(roots, order)
            >>> polynomial_list = polynomial.coefficients

            >>> proof = ProofSignatureSet(com_pk, signed_message, message, modulo, polynomial_list)
            >>> proof.verify(com_pk, message, polynomial_list)
            True
        """
        time_verif_sig = time()
        check1 = self.signature_verification_proof.verify(com_pk, message, self.commitment_modulo)
        time_membership_proof = time()
        random_commitment_zero = Bn.from_num(0)
        commitment_zero = com_pk.commit([Bn.from_num(0)], random_commitment_zero)
        check2 = self.set_membership_proof.verify(com_pk, polynomial_list, self.commitment_modulo, commitment_zero)
        time_end = time()
        self.time_ful_sig_verif = time_membership_proof - time_verif_sig
        self.time_ful_membership_verif = time_end - time_membership_proof

        return check1 and check2

def dummy_data():
    signed_message = Bn.from_decimal(
        '3267130879652831345725274493091864173664779686561468331327307223118323180854374368529709859982539642304106382710168349440365177585819079044569348143553775020001583232051912120786084941259615483456026526492763529867283809400541253655294703304694694909884547949906276978485121556989589857652551913425494558579463581603660708622220905750902818300028192076087236543955719381287851483715165947067927182725405602362444409787890483125799654250244631251471267796093361828588756267394621662915328665759959690382774526091733083749530315566527452075807834066136830598666022369230448170344189801089070846765236463368261702522541')
    exponent = 65537
    modulo = Bn.from_decimal(
        '24328626682289136570751536147321521934883276496444403637200791710959330225351187858816284221467749949170967552592192324486105274675745073644298833869379510880054061897691638487850358168087009962101666739301242027780261176000688299869458451077243785452946211728488732020837306283402441986288004713904032620106051702880664181957060410226643578290964003019109479261826859822942513350862756778747973875209750342357933539552875979843312957639435564366361012366291495216191958522420513908595748516389774971404368853339932587005401457667821996489027145786706555858193202229433265835452932244580820310037045608574782179678733')
    message = Bn.from_decimal(
        '11264652154564453430496457908736657358871063001580135036668449613782230474459257779414388868316229696383854723322449620745661789436311083644365634341878899213582433948857540063959886940283100303353993687683220603410174885414773674640271479382463017909443209457963651086343524408892370053021366218888537626071176180227351772812727213839393673750595723751542387782154335908765160334619620925620997573259209043281609289966399749247144781174471547367051885787071526349266540287740194115106732940765466163844605690702280531411994620726755519791560618601886973709571223025009898754616870597545257136677180192006890805219737')

    assert(signed_message.mod_pow(exponent, modulo) == message)

    return signed_message, message, exponent, modulo

def dummy_roots(modulo, size):
    return [modulo for _ in range(size)]
