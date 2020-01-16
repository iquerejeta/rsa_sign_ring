from primitives.pedersen import PublicKey, Commitment
from primitives.algebra_lib import FFGroup
from zero_knowledge_proofs.ff_based.proof_range_ff import ProofRange

from petlib.ec import Bn
from time import time


class ModularAdditionZKP:
    def __init__(self, com_pk, added_value_1, added_value_2, result, modulo,
                 commitment_added_1, commitment_added_2, commitment_result, commitment_modulo,
                 random_comm_value1, random_comm_value2, random_comm_result, random_comm_modulo,
                 upper_bound_moduli=2050):
        """
        Prove that added_value_1 + added_value_2 = result mod modulo in zero knowledge.

        :param security_parameter: We should prepare it in such a way that we do not use the hardcoded values. For
        the moment we stick to that for evaluation
        """
        # Sanity checks
        self.group = com_pk.group
        self.order = self.group.order()

        order_bits = self.order.num_bits()
        modulo_bits = modulo.num_bits()
        self.upper_bound_calculations = Bn.from_num(2) ** (upper_bound_moduli)
        self.lower_bound_calculations = - Bn.from_num(2) ** (upper_bound_moduli)



        # Range proofs
        self.time_range_proofs = time()
        self.range_added_value_1 = ProofRange(com_pk, added_value_1, commitment_added_1, random_comm_value1,
                                         self.lower_bound_calculations, self.upper_bound_calculations)

        self.range_added_value_2 = ProofRange(com_pk, added_value_2, commitment_added_2, random_comm_value2,
                                         self.lower_bound_calculations, self.upper_bound_calculations)

        self.range_result = ProofRange(com_pk, result, commitment_result, random_comm_result,
                                  self.lower_bound_calculations, self.upper_bound_calculations)

        self.range_modulo = ProofRange(com_pk, modulo, commitment_modulo, random_comm_modulo,
                                  self.lower_bound_calculations, self.upper_bound_calculations)

        self.time_secret_exponent = time()
        secret_exponent = (result - added_value_1 - added_value_2) / modulo
        secret_exponent_mod_order = secret_exponent.mod(self.order)
        secret_random = (random_comm_result - random_comm_value1 - random_comm_value2 - random_comm_modulo * secret_exponent).mod(self.order)
        self.commitment_secret_exponent = Commitment(commitment_modulo.commitment ** secret_exponent_mod_order * com_pk.generators[1] ** secret_random)
        # print(commitment_result / (commitment_added_1 * commitment_added_2) == Commitment(commitment_modulo.commitment ** secret_exponent * com_pk.generators[1] ** secret_random))
        com_pk_exponent = PublicKey(self.group, 1)
        com_pk_exponent.generators = [commitment_modulo.commitment, com_pk.generators[1]]
        self.range_secret_exponent = ProofRange(com_pk_exponent, secret_exponent, self.commitment_secret_exponent, secret_random, self.lower_bound_calculations, self.upper_bound_calculations)
        self.time_end = time()

    def verify(self, com_pk, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo):
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

            >>> proof = ModularAdditionZKP(com_pk, added_value1, added_value2, result, modulo, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo, random_comm_add1, random_comm_add2, random_comm_res, random_comm_modulo)
            >>> proof.verify(com_pk, commitment_added_1, commitment_added_2, commitment_result, commitment_modulo)
            True

        """
        check1 = self.range_added_value_1.verify(com_pk, commitment_added_1, self.lower_bound_calculations, self.upper_bound_calculations)
        check2 = self.range_added_value_2.verify(com_pk, commitment_added_2, self.lower_bound_calculations, self.upper_bound_calculations)
        check3 = self.range_result.verify(com_pk, commitment_result, self.lower_bound_calculations, self.upper_bound_calculations)
        check4 = self.range_modulo.verify(com_pk, commitment_modulo, self.lower_bound_calculations, self.upper_bound_calculations)

        com_pk_exponent = PublicKey(self.group, 1)
        com_pk_exponent.generators = [commitment_modulo.commitment, com_pk.generators[1]]
        check5 = self.range_secret_exponent.verify(com_pk_exponent,
                                                   commitment_result / (commitment_added_1 * commitment_added_2),
                                                   self.lower_bound_calculations, self.upper_bound_calculations)

        return check1 and check2 and check3 and check4 and check5


def generate_dummy_data():
    added_value1 = Bn.from_decimal('24162543347661669391984139420333330003193037569677628657075296755996545606440342653773228182181074585909743473241178111023940829383800177028297149836819890236067905461561323120285857837943781234080644548802875877543075933964282119162618153390229742482581166765792694385789805824272693991974383467478651581221658984995893057526076009846185776075672586408202325043713822364320582961976139894538498313333250094652596028061483281131053549691578171645089957817044992203595984907306624894095934384116888385008526375918727740324869169132237005273795714314504555976647636629197384603503622486279291112135762761131359851901045')
    added_value2 = Bn.from_decimal('17306564212284067686400661721747208862933037462203798226034177831143496955083350939494006650118046126257121253996803204094317529199072270569019006996460981096733070758960069817969941863582783753328515790167040021263911823847722753032604981962557242433989040164010065744366795658065387654293271439665407249016679388179504761815444472683715224447920092623964777035010636583643616951750762166353185143955725771689589545287387793660975833951295365455954386892400070720759991122883968500546119508822265400007885794965773626525779623244521388916219339584023963346628466892563747397021059058679424841578144639757587199241768')
    result = Bn.from_decimal('11744251646293852142764285228412726703371370661259653105388429806663117457030327161148467423734765500002445151453600626084027238469443404109464463929854712834543940632171887499574300390633507817877644324865523623911880133130207077363755907416596194159666435172615479161515191624635590262633305704604370574282573065435968867007892309463634283525198270827227364082217788883270985534282118085053551819100571201122712829883906835461293178045627812409822585781457464226946004958506829591641561035216629581009478695315460701306166182410546517556076569147123383741848538832213144325691137975892184375134867315084289749762054')
    modulo = Bn.from_decimal('29724855913651884935620515913667812162754704370621773777721044780476925104493366432118767408564355212164419575784380689034231120113429043487851692903426158498257035588349505438681499310893057169531516014104392274895107624681797794831467227936190790756903771757187280968641409857702491383634349202539688255955765307739428952333628173066266716998394408204939737996506670064693214379444783975838131638188404665219472743464964239330736205597245724691221758927987598697409971071683763803000492857722524204006933475569040665544482609966211876633938484751405135581427564689547987674833543569066531578579040085804657301380759')
    return added_value1, added_value2, result, modulo