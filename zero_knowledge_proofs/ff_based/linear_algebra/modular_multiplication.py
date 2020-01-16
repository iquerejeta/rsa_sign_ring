from primitives.pedersen import PublicKey, Commitment
from primitives.algebra_lib import FFGroup
from zero_knowledge_proofs.ff_based.proof_range_ff import ProofRange
from zero_knowledge_proofs.ff_based.proof_square_ff import ProofSameLog

from petlib.ec import Bn
from time import time


class ModularMultiplicationZKP:
    def __init__(self, com_pk, multiplied_value_1, multiplied_value_2, result, modulo,
                 commitment_multiplied_1, commitment_multiplied_2, commitment_result, commitment_modulo,
                 random_comm_value1, random_comm_value2, random_comm_result, random_comm_modulo,
                 upper_bound_moduli=2048):
        """
        Prove that multiplied_value_1 * multiplied_value_2 = result mod modulo in zero knowledge.

        :param security_parameter: We should prepare it in such a way that we do not use the hardcoded values. For
        the moment we stick to that for evaluation
        """

        self.group = com_pk.group
        self.order = self.group.order()

        order_bits = self.order.num_bits()
        modulo_bits = modulo.num_bits()
        self.upper_bound_calculations = Bn.from_num(2) ** (upper_bound_moduli)
        self.lower_bound_calculations = - (Bn.from_num(2) ** (upper_bound_moduli))


        # Range proofs
        self.time_range_proofs = time()
        self.range_added_value_1 = ProofRange(com_pk, multiplied_value_1, commitment_multiplied_1, random_comm_value1,
                                              self.lower_bound_calculations, self.upper_bound_calculations)

        self.range_added_value_2 = ProofRange(com_pk, multiplied_value_2, commitment_multiplied_2, random_comm_value2,
                                              self.lower_bound_calculations, self.upper_bound_calculations)

        self.range_result = ProofRange(com_pk, result, commitment_result, random_comm_result,
                                  self.lower_bound_calculations, self.upper_bound_calculations)

        self.range_modulo = ProofRange(com_pk, modulo, commitment_modulo, random_comm_modulo,
                                  self.lower_bound_calculations, self.upper_bound_calculations)

        self.time_secret_exponent = time()
        secret_exponent = (result - multiplied_value_1 * multiplied_value_2) / modulo
        secret_random = (random_comm_result - random_comm_value2 * multiplied_value_1 - random_comm_modulo * secret_exponent).mod(self.order)

        # print(commitment_result / (commitment_added_1 * commitment_added_2) == Commitment(commitment_modulo.commitment ** secret_exponent * com_pk.generators[1] ** secret_random))
        self.com_pk_exponent = PublicKey(self.group, 1)
        self.h_base_verification = commitment_multiplied_2.commitment ** multiplied_value_1 * com_pk.generators[1] ** secret_random
        # todo: fucking fails when I change the second generator! Why is that! ($$ Removed the error with the DL equality. But please find out why this was fucking up so much)
        self.com_pk_exponent.generators = [commitment_modulo.commitment, self.h_base_verification]
        # todo: clarify the generation of the proof with such a com_pk (the usage of random = 1)
        self.commitment_secret_exponent = self.com_pk_exponent.commit([secret_exponent], Bn.from_num(1))

        ''' from here '''
        random_normal_comm_secret_exp = self.order.random()
        self.normal_commitment_secret_exponent = com_pk.commit([secret_exponent], random_normal_comm_secret_exp)
        self.lets_try_this_proof = ProofSameLog(secret_exponent, random_normal_comm_secret_exp, Bn.from_num(1), com_pk.generators[0], com_pk.generators[1],
                                                self.com_pk_exponent.generators[0], self.com_pk_exponent.generators[1], self.order)

        ''' to here, I AM GOING AROUND THE PROBLEM, NOT SOLVING IT! THIS SOLUTION IS WORSE IN PERFORMANCE! '''

        self.range_secret_exponent = ProofRange(com_pk, secret_exponent, self.normal_commitment_secret_exponent, random_normal_comm_secret_exp,
                                   self.lower_bound_calculations, self.upper_bound_calculations)
        self.time_end = time()

    def verify(self, com_pk, commitment_multiplied_1, commitment_multiplied_2, commitment_result, commitment_modulo):
        """
        Verify modular addition

        Example:
            >>> added_value1, added_value2, result, modulo = generate_dummy_data()
            >>> G = FFGroup()
            >>> order = G.order()
            >>> com_pk = PublicKey(G, 1)
            >>> random_comm_add1 = order.random()
            >>> random_comm_add2 = order.random()
            >>> random_comm_res = order.random()
            >>> random_comm_modulo = order.random()
            >>> commitment_added_1 = com_pk.commit([added_value1], random_comm_add1)
            >>> commitment_added_2 = com_pk.commit([added_value2], random_comm_add2)
            >>> commitment_result = com_pk.commit([result], random_comm_res)
            >>> commitment_modulo = com_pk.commit([modulo], random_comm_modulo)

            >>> proof = ModularMultiplicationZKP(com_pk, added_value1, added_value2, result, modulo, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo, random_comm_add1, random_comm_add2, random_comm_res, random_comm_modulo)
            >>> proof.verify(com_pk, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo)
            True

        """
        check1 = self.range_added_value_1.verify(com_pk, commitment_multiplied_1, self.lower_bound_calculations, self.upper_bound_calculations)
        check2 = self.range_added_value_2.verify(com_pk, commitment_multiplied_2, self.lower_bound_calculations, self.upper_bound_calculations)
        check3 = self.range_result.verify(com_pk, commitment_result, self.lower_bound_calculations, self.upper_bound_calculations)
        check4 = self.range_modulo.verify(com_pk, commitment_modulo, self.lower_bound_calculations, self.upper_bound_calculations)

        # todo: Read the following comment
        ''' Now doing the same log verification. If this is ever taken to deployment, this must be thoroughtly studied. 
        This has been done as a avoidement of a problem, and was not defined as is in the original paper. '''

        check_same_log = self.lets_try_this_proof.verify(self.normal_commitment_secret_exponent, commitment_result,
                                                         com_pk.generators[0], com_pk.generators[1],
                                                         self.com_pk_exponent.generators[0],
                                                         self.com_pk_exponent.generators[1]
                                                         )
        check5 = self.range_secret_exponent.verify(com_pk, self.normal_commitment_secret_exponent,
                                                   self.lower_bound_calculations, self.upper_bound_calculations)

        return check1 and check2 and check3 and check4 and check_same_log and check5


def generate_dummy_data():
    added_value1 = Bn.from_decimal('13847976329747413320017540798875114689276100972391420103438096531581159088648204133754044748488566834263717408522075684280054627521580320751973184955107287860415951850037127529825922046189326854021487239490140723522398888184592925098132380377807239919609373837699787710259206390189790963304399586697080640585013122122220161400916923448566963308747795037457352415011815579868591916802944334856417632365914794939964039868730332200676033520423063519641421959887734728457181422498748789762430381242536798476534888032408367003425345633834383979649462296802021301919092321455153908244817007553839678053198798510037641184412')
    added_value2 = Bn.from_decimal('1691391675651105360726264778501827149173432271285000590655071789063047110285371931758868865626301173278060927331112314747184003673683844575644433956130487456256657333756584527231309494911684075822618033841809888770084753189672869085131760097169618643141369829067812850256770872860707380354955125871372195136805374219303365089328689556855243474858648439374789326331839020078480669688339602319484730021484561274318488540902497387726593351750542860750453199539142122005231232564803664787853041606584203530046682386518085530540757165724796626268715439720837057345680600811327751065602343968648113347616210939742418391799')
    result = Bn.from_decimal('3338925052947680760541686338839853050070652260224659671290204334390928859917187128822250861634665224685345787243877304164614728233608867118081002522350961882499516797409618907946775884508286006893734776195370078030301519896110698569912963490142908419484997589159492256917525146254779781561813878419091430817715770851631996912678679401723605145796708987945048677938907218038268827366682496761592186889936821061131838496801470365004304506120908133910807027829590466175437427634095032979785379671359858406770569989397228532801547054351424509343102265204147281906313181465761759795408275035752985517344187461483438262984')
    modulo = Bn.from_decimal('31021061651860055779860385145673491318711580034455489926249930553793143524452445216959301530073707352244502048313261260040669415286585055595722431529716744518604863581475152532809934715959313944192670349963603806081347252998658729767156061376406481979947486427341062468180116586893708393214961512543268589960175969629630711844616409451411497610472843006785045155818432858368501834173929914853530784732999272628131704013946553133780339016229805732018886157096782889879882864356849353318859193181573502375705060416125471778796521822707163808667931415666093350858711728871720842683019193079496755227899588770611382572971')
    return added_value1, added_value2, result, modulo