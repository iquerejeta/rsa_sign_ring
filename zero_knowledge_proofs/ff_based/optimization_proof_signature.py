from primitives.pedersen import PublicKey
from primitives.algebra_lib import FFGroup
from zero_knowledge_proofs.ff_based.proof_range_ff import ProofRange

from time import time
from petlib.bn import Bn


class ModularExponantiation:
    """
    This will generate a proof that a hidden signature to the power a public exponent equals a public message modulo
    a private modulo.
    """

    def __init__(self, com_pk, signature, message, modulus,
                 commitment_modulo, random_committed_modulo, exponent=65537, upper_bound_moduli=2048):
        self.com_pk = com_pk
        self.message = message

        self.exponent = exponent

        "For the case of exponent 65537, it basically consists of 16 squares and one multiplication."
        self.group = com_pk.group
        self.order = self.group.order()

        self.upper_bound_calculations = Bn.from_num(2) ** (upper_bound_moduli)
        self.lower_bound_calculations = - (Bn.from_num(2) ** (upper_bound_moduli))

        # random_committed_modulo = self.order.random()
        # self.commitment_modulo = com_pk.commit([modulo], random_committed_modulo)

        squared_steps = []
        multiplication_steps = []
        self.commitments_squares = []
        commitment_squares_randomizers = []
        self.commitments_multiplication = []
        commitment_multiplication_randomizers = []
        self.proofs_exponantiations = []

        random_committed_signature = self.order.random()
        committed_signature = com_pk.commit([signature], random_committed_signature)
        self.commitments_squares.append(committed_signature)
        commitment_squares_randomizers.append(random_committed_signature)

        exponantiated_value = Bn.from_num(1)
        random_commitment_exponantiated_value = self.order.random()
        commitment_exponantiated_value = com_pk.commit([exponantiated_value], random_commitment_exponantiated_value)
        self.commitments_multiplication.append(commitment_exponantiated_value)
        commitment_multiplication_randomizers.append(random_commitment_exponantiated_value)

        X = signature
        squared_steps.append(X)
        multiplication_steps.append(exponantiated_value)

        self.range_modulo = ProofRange(com_pk, modulo, commitment_modulo, random_committed_modulo,
                                       self.lower_bound_calculations, self.upper_bound_calculations)

        temp_exp = exponent
        while temp_exp > 0:
            if temp_exp % 2 == 0:
                temp_value = (X * X).mod(modulus)

                random_committed_result = self.order.random()
                committed_result = com_pk.commit([temp_value], random_committed_result)
                self.commitments_squares.append(committed_result)
                commitment_squares_randomizers.append(random_committed_result)

                proof = ModularSquaringZKP(com_pk, X, temp_value, modulus,
                                           self.commitments_squares[-2], self.commitments_squares[-1], commitment_modulo,
                                           commitment_squares_randomizers[-2], commitment_squares_randomizers[-1], random_committed_modulo)
                self.proofs_exponantiations.append(proof)

                X = temp_value
                squared_steps.append(X)
                temp_exp = temp_exp / 2

            else:
                temp_value = (X * exponantiated_value).mod(modulus)

                random_committed_result = self.order.random()
                committed_result = com_pk.commit([temp_value], random_committed_result)
                self.commitments_multiplication.append(committed_result)
                commitment_multiplication_randomizers.append(random_committed_result)

                proof = ModularMultiplicationZKP(com_pk, X, exponantiated_value, temp_value, modulus,
                                                 self.commitments_squares[-1], self.commitments_multiplication[-2], self.commitments_multiplication[-1], commitment_modulo,
                                                 commitment_squares_randomizers[-1], commitment_multiplication_randomizers[-2],
                                                 commitment_multiplication_randomizers[-1], random_committed_modulo)

                self.proofs_exponantiations.append(proof)

                exponantiated_value = temp_value
                multiplication_steps.append(exponantiated_value)
                temp_exp -= 1

        self.randomiser_result = commitment_multiplication_randomizers[-1]

    def verify(self, com_pk, message, commitment_modulo):
        """
        Verify the exponantiation proof.

        Example:
            # >>> G = FFGroup()
            # >>> order = G.order()
            # >>> com_pk = PublicKey(G, 1)
            # >>> ModularExponantiation(com_pk, signed_message, message, modulo)
        """
        temp_exponent = self.exponent
        verifications = []

        check_modulo = self.range_modulo.verify(com_pk, commitment_modulo, self.lower_bound_calculations,
                                          self.upper_bound_calculations)

        nr_squares = 0
        nr_multiplications = 0
        nr_proofs = 0
        while temp_exponent > 0:
            if temp_exponent % 2 == 0:
                committed_value = self.commitments_squares[nr_squares]
                committed_result = self.commitments_squares[nr_squares + 1]
                verifications.append(self.proofs_exponantiations[nr_proofs].verify(com_pk, committed_value, committed_result, commitment_modulo))
                nr_squares += 1
                nr_proofs += 1
                temp_exponent /= 2
            else:
                committed_value_1 = self.commitments_squares[nr_squares]
                committed_value_2 = self.commitments_multiplication[nr_multiplications]
                committed_result = self.commitments_multiplication[nr_multiplications + 1]
                verifications.append(self.proofs_exponantiations[nr_proofs].verify(com_pk, committed_value_1, committed_value_2, committed_result, commitment_modulo))
                nr_multiplications += 1
                nr_proofs += 1
                temp_exponent -= 1

        check_result = self.commitments_multiplication[-1] == com_pk.commit([message], self.randomiser_result)

        return check_result and all(verifications) and check_modulo


class ModularSquaringZKP:
    def __init__(self, com_pk, value, result, modulo,
                 commitment_value, commitment_result, commitment_modulo,
                 random_comm_value, random_comm_result, random_comm_modulo,
                 upper_bound_moduli=2049):
        """
        Prove that value ^ 2 = result mod modulo in zero knowledge.

        :param security_parameter: We should prepare it in such a way that we do not use the hardcoded values. For
        the moment we stick to that for evaluation

        Note that for the particular proof we are constructing, every value that we square has already been proven
        to be among the accepted range. So we can skip that proof here.
        """

        self.group = com_pk.group
        self.order = self.group.order()

        self.upper_bound_calculations = Bn.from_num(2) ** (upper_bound_moduli)
        self.lower_bound_calculations = - (Bn.from_num(2) ** (upper_bound_moduli))


        # Range proofs
        self.time_range_proofs = time()

        self.range_result = ProofRange(com_pk, result, commitment_result, random_comm_result,
                                  self.lower_bound_calculations, self.upper_bound_calculations)

        self.time_secret_exponent = time()
        secret_exponent = (result - value * value) / modulo
        secret_random = (random_comm_result - random_comm_value * value - random_comm_modulo * secret_exponent).mod(self.order)

        self.com_pk_exponent = PublicKey(self.group, 1)

        self.h_base_verification = commitment_value.commitment ** value * com_pk.generators[1] ** secret_random
        self.com_pk_exponent.generators = [commitment_modulo.commitment, self.h_base_verification]

        self.commitment_secret_exponent = self.com_pk_exponent.commit([secret_exponent], Bn.from_num(1))

        self.range_secret_exponent = ProofRange(self.com_pk_exponent, secret_exponent, self.commitment_secret_exponent, Bn.from_num(1),
                                   self.lower_bound_calculations, self.upper_bound_calculations)
        self.time_end = time()

    def verify(self, com_pk, commitment_value, commitment_result, commitment_modulo):
        """
        Verify modular addition

        Example:
            # >>> value, result, modulo = generate_dummy_data()
            # >>> G = FFGroup()
            # >>> order = G.order()
            # >>> com_pk = PublicKey(G, 1)
            # >>> random_comm_1 = order.random()
            # >>> random_comm_res = order.random()
            # >>> random_comm_modulo = order.random()
            # >>> commitment_added_1 = com_pk.commit([value], random_comm_1)
            # >>> commitment_result = com_pk.commit([result], random_comm_res)
            # >>> commitment_modulo = com_pk.commit([modulo], random_comm_modulo)
            #
            # >>> proof = ModularSquaringZKP(com_pk, value, result, modulo, commitment_added_1, commitment_result, commitment_modulo, random_comm_1, random_comm_res, random_comm_modulo)
            # >>> proof.verify(com_pk, commitment_added_1, commitment_result, commitment_modulo)
            # True

        """
        check3 = self.range_result.verify(com_pk, commitment_result, self.lower_bound_calculations, self.upper_bound_calculations)

        check5 = self.range_secret_exponent.verify(self.com_pk_exponent, commitment_result,
                                                   self.lower_bound_calculations, self.upper_bound_calculations)

        return check3 and check5


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

        self.time_secret_exponent = time()
        secret_exponent = (result - multiplied_value_1 * multiplied_value_2) / modulo
        secret_random = (random_comm_result - random_comm_value2 * multiplied_value_1 - random_comm_modulo * secret_exponent).mod(self.order)

        self.com_pk_exponent = PublicKey(self.group, 1)

        self.h_base_verification = commitment_multiplied_2.commitment ** multiplied_value_1 * com_pk.generators[1] ** secret_random
        self.com_pk_exponent.generators = [commitment_modulo.commitment, self.h_base_verification]

        self.commitment_secret_exponent = self.com_pk_exponent.commit([secret_exponent], Bn.from_num(1))

        self.range_secret_exponent = ProofRange(self.com_pk_exponent, secret_exponent, self.commitment_secret_exponent, Bn.from_num(1),
                                   self.lower_bound_calculations, self.upper_bound_calculations)
        self.time_end = time()

    def verify(self, com_pk, commitment_multiplied_1, commitment_multiplied_2, commitment_result, commitment_modulo):
        """
        Verify modular addition

        Example:
            # >>> added_value1, added_value2, result, modulo = generate_dummy_data()
            # >>> G = FFGroup()
            # >>> order = G.order()
            # >>> com_pk = PublicKey(G, 1)
            # >>> random_comm_add1 = order.random()
            # >>> random_comm_add2 = order.random()
            # >>> random_comm_res = order.random()
            # >>> random_comm_modulo = order.random()
            # >>> commitment_added_1 = com_pk.commit([added_value1], random_comm_add1)
            # >>> commitment_added_2 = com_pk.commit([added_value2], random_comm_add2)
            # >>> commitment_result = com_pk.commit([result], random_comm_res)
            # >>> commitment_modulo = com_pk.commit([modulo], random_comm_modulo)
            #
            # >>> proof = ModularMultiplicationZKP(com_pk, added_value1, added_value2, result, modulo, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo, random_comm_add1, random_comm_add2, random_comm_res, random_comm_modulo)
            # >>> proof.verify(com_pk, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo)
            # True

        """
        check1 = self.range_added_value_1.verify(com_pk, commitment_multiplied_1, self.lower_bound_calculations, self.upper_bound_calculations)
        check2 = self.range_added_value_2.verify(com_pk, commitment_multiplied_2, self.lower_bound_calculations, self.upper_bound_calculations)
        check3 = self.range_result.verify(com_pk, commitment_result, self.lower_bound_calculations, self.upper_bound_calculations)

        check5 = self.range_secret_exponent.verify(self.com_pk_exponent, commitment_result,
                                                   self.lower_bound_calculations, self.upper_bound_calculations)

        return check1 and check2 and check3 and check5


def exponantiation(message, exponent, modulo):
    """ Always using the exponent 65537. So in reality the input variable is not needed. """
    X = message
    product = 1 * X
    for _ in range(16):
        X = (X * X).mod(modulo)

    product = (product * X).mod(modulo)

    return product

def generate_dummy_data():
    added_value1 = Bn.from_decimal('13847976329747413320017540798875114689276100972391420103438096531581159088648204133754044748488566834263717408522075684280054627521580320751973184955107287860415951850037127529825922046189326854021487239490140723522398888184592925098132380377807239919609373837699787710259206390189790963304399586697080640585013122122220161400916923448566963308747795037457352415011815579868591916802944334856417632365914794939964039868730332200676033520423063519641421959887734728457181422498748789762430381242536798476534888032408367003425345633834383979649462296802021301919092321455153908244817007553839678053198798510037641184412')

    result = Bn.from_decimal('21912617384096062167187931131626963416730812001554606652271996769231523304523319036448654871662584864457828186854067132654460112841230183317692648554880891758900191749363860151425210083977236023191607309490629787415444367052485742182398945274901588869956283317669354717365622709886833339972184369324879720991739689547323442090710645199917237735095839627786896450830840384507445088160621958772290675750634926821821419609921885822120151259619081107421422922535235432113222472570034445063887762647208652476139516883826138498973305690231251145297483082686044839866309901519570416771620715249542591130415602706650088968070')
    modulo = Bn.from_decimal('31021061651860055779860385145673491318711580034455489926249930553793143524452445216959301530073707352244502048313261260040669415286585055595722431529716744518604863581475152532809934715959313944192670349963603806081347252998658729767156061376406481979947486427341062468180116586893708393214961512543268589960175969629630711844616409451411497610472843006785045155818432858368501834173929914853530784732999272628131704013946553133780339016229805732018886157096782889879882864356849353318859193181573502375705060416125471778796521822707163808667931415666093350858711728871720842683019193079496755227899588770611382572971')
    return added_value1, result, modulo



if __name__ == '__main__':
    import doctest

    doctest.testmod()
    signed_message = Bn.from_decimal(
        '3267130879652831345725274493091864173664779686561468331327307223118323180854374368529709859982539642304106382710168349440365177585819079044569348143553775020001583232051912120786084941259615483456026526492763529867283809400541253655294703304694694909884547949906276978485121556989589857652551913425494558579463581603660708622220905750902818300028192076087236543955719381287851483715165947067927182725405602362444409787890483125799654250244631251471267796093361828588756267394621662915328665759959690382774526091733083749530315566527452075807834066136830598666022369230448170344189801089070846765236463368261702522541')
    exponent = 65537
    modulo = Bn.from_decimal(
        '24328626682289136570751536147321521934883276496444403637200791710959330225351187858816284221467749949170967552592192324486105274675745073644298833869379510880054061897691638487850358168087009962101666739301242027780261176000688299869458451077243785452946211728488732020837306283402441986288004713904032620106051702880664181957060410226643578290964003019109479261826859822942513350862756778747973875209750342357933539552875979843312957639435564366361012366291495216191958522420513908595748516389774971404368853339932587005401457667821996489027145786706555858193202229433265835452932244580820310037045608574782179678733')
    message = Bn.from_decimal(
        '11264652154564453430496457908736657358871063001580135036668449613782230474459257779414388868316229696383854723322449620745661789436311083644365634341878899213582433948857540063959886940283100303353993687683220603410174885414773674640271479382463017909443209457963651086343524408892370053021366218888537626071176180227351772812727213839393673750595723751542387782154335908765160334619620925620997573259209043281609289966399749247144781174471547367051885787071526349266540287740194115106732940765466163844605690702280531411994620726755519791560618601886973709571223025009898754616870597545257136677180192006890805219737')
    print(exponantiation(signed_message, exponent, modulo) == message)

    G = FFGroup()
    order = G.order()
    com_pk = PublicKey(G, 1)
    random_committed_modulo = order.random()
    commitment_modulo = com_pk.commit([modulo], random_committed_modulo)
    time_proof = 0
    time_verif = 0
    REPS = 10
    for _ in range(REPS):
        time_full_proof = time()
        exponantiation_proof = ModularExponantiation(com_pk, signed_message, message, modulo, commitment_modulo,
                                                     random_committed_modulo)
        time_full_verif = time()
        print(exponantiation_proof.verify(com_pk, message, commitment_modulo))
        time_end = time()
        time_proof += time_full_verif - time_full_proof
        time_verif += time_end - time_full_verif
    print("time generating full proof: ", time_proof / REPS)
    print("time verifying full proof: ", time_verif / REPS)
