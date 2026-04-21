"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple

from serialization import jsonpickle

from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.bn import Bn
import hashlib
import copy

class Attribute:
    def __init__(self, label:str, value:bytes = b''):
        # value is a bytestring
        self.label = label
        self.value = value

    def __repr__(self):
        return f"Attribute:\nlabel = {self.label}\nvalue={self.value}"
    
    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Attribute):
            return False
        return self.label == other.label and self.value == other.value
    
class SecretKey:
    def __init__(self, x:Bn, X:G1, y:List[Bn]):

        self.x = x
        self.X = X
        self.y = y
    
    def __repr__(self):
        return f"SecretKey:\nx={self.x},\nX={self.X},\ny={self.y}"

class PublicKey:
    def __init__(self, Xtilde:G2, Y:List[G1], Ytilde:List[G2], attributes: List[str]):

        self.Xtilde = Xtilde
        self.Y = Y
        self.Ytilde = Ytilde 
        self.attribute_labels = attributes

    def __repr__(self):
        return f"PublicKey:\nXtilde={self.Xtilde},\nY={self.Y},\nYtilde={self.Ytilde},\nattributes={self.attribute_labels}"

class Signature:
    def __init__(self, h:G1, htilde:G1):
        self.h = h
        self.htilde = htilde
        
    def __repr__(self):
        return f"Signature:\nh={self.h},\nh_tilde={self.htilde}"

class AttributeMap:
    def __init__(self, attributes: List[Attribute], issuer_attributes: List[Attribute] = None, user_attributes:List[Attribute] = None):
        
        self.attributes = attributes

        attributes_labels = [attribute.label for attribute in attributes]

        if issuer_attributes is None and user_attributes is None:
            raise ValueError("Either issuer_attributes or user_attributes must be provided")

        if issuer_attributes is not None:
            issuer_attributes_labels = [attribute.label for attribute in issuer_attributes]
            for issuer_attribute_label in issuer_attributes_labels:
                if issuer_attribute_label not in attributes_labels:
                    raise ValueError(f"Issuer attribute {issuer_attribute_label} not in attributes")
                if user_attributes != None: 
                    user_attributes_labels = [attribute.label for attribute in user_attributes]
                    if issuer_attribute_label in user_attributes_labels:
                        raise ValueError(f"Issuer attribute {issuer_attribute_label} is also a user attribute")
            self.issuer_attributes = issuer_attributes
            self.user_attributes = [attribute for attribute in attributes if attribute not in issuer_attributes]
        else:
            user_attributes_labels = [attribute.label for attribute in user_attributes]
            for user_attribute_label in user_attributes_labels:
                if user_attribute_label not in attributes_labels:
                    raise ValueError(f"User attribute {user_attribute_label} not in attributes")
                if issuer_attributes != None:
                    issuer_attributes_labels = [attribute.label for attribute in issuer_attributes]
                    if user_attribute_label in issuer_attributes_labels:
                        raise ValueError(f"User attribute {user_attribute} is also an issuer attribute")
            self.user_attributes = user_attributes
            self.issuer_attributes = [attribute for attribute in attributes if attribute not in user_attributes]
    
    def __repr__(self):
        return f"AttributeMap:\nattributes={self.attributes},\nissuer_attributes={self.issuer_attributes},\nuser_attributes={self.user_attributes}"
    
    def labels(self) -> List[str]:
        """ Return a list of the labels of the attributes """
        return [attribute.label for attribute in self.attributes]
        
class ZKProof:
    def __init__(self, c:Bn, st:Bn, sa:List[Bn]):

        self.c = c
        self.st = st
        self.sa = sa

    def __repr__(self):
        return f"ZKProof:\nc={self.c},\nst={self.st},\nsa={self.sa}"
        
class IssueRequest:
    def __init__(self, commitment:G1, pi:ZKProof, at_public:AttributeMap):

        self.commitment = commitment
        self.proof = pi
        self.public_attributes = at_public

    def __repr__(self):
        return f"IssueRequest:\ncommitment={self.commitment},\npi={self.proof}\npublic_attributes={self.public_attributes}"

class BlindSignature:
    def __init__(self, h:G1, htilde:G1):

        self.h = h
        self.htilde = htilde

    def __repr__(self):
        return f"BlindSignature:\nh={self.h},\nh_tilde={self.htilde}"

class AnonymousCredential:
    def __init__(self, signature: Signature, attributes: AttributeMap):
        self.signature = signature
        self.attributes = attributes

    def __repr__(self):
        return f"AnonymousCredential:\nsignature={self.signature},\nattributes={self.attributes}"
    
class DisclosureProof:
    def __init__(self, signature: Signature, proof: ZKProof, attributes: List[Attribute]):
        self.signature = signature
        self.proof = proof
        self.attributes = attributes

    def __repr__(self):
        return f"DisclosureProof:\nsignature={self.signature},\nproof={self.proof},\nattributes={self.attributes},\nhash={self.hash}"
    

######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """Generate a signer key pair.

    Args:
        attributes: List of available attributes.

    Returns:
        A tuple containing:
            - SecretKey: The secret key used for signing.
            - PublicKey: The public key used for verification.
    """
    L = len(attributes)
    x = G1.order().random()
    y = []
    for i in range(L):
        y.append(G2.order().random())
    
    X = G1.generator() ** x
    Xtilde = G2.generator() ** x
    Y = []
    Ytilde = []
    for i in range(L):
        Y.append(G1.generator() ** y[i])
        Ytilde.append(G2.generator() ** y[i])

    attribute_labels = [attribute.label for attribute in attributes]

    pk = PublicKey(Xtilde, Y, Ytilde, attribute_labels)
    sk = SecretKey(x, X, y)

    return sk, pk


def sign(
        sk: SecretKey,
        msgs: List[bytes] 
    ) -> Signature:
    """Sign a vector of messages.

    Args:
        sk: The secret key used to generate the signature.
        msgs: A list of messages in bytes.

    Returns:
        signature: A signature over the message vector.
    """

    if len(msgs) != len(sk.y):
        raise ValueError("Number of messages must match number of attributes")
    
    L = len(msgs)

    a = G1.order().random()
    while a == 0:
        a = G1.order().random()
    h = G1.generator() ** a

    m = [int.from_bytes(msgs[i],'big')% G1.order() for i in range(L)]

    power = sk.x + sum([sk.y[i]*m[i] for i in range(L)])
    signature = Signature(h,h**power)
    return signature

def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes] 
    ) -> bool:
    """Verify a signature on a vector of messages.

    Args:
        pk: The public key used for verification.
        signature: The signature to verify.
        msgs: A list of signed messages.

    Returns:
        A boolean indicating whether the signature is valid.
    """
    if len(msgs) != len(pk.Y):
        raise ValueError("Number of messages must match number of attributes")
    L = len(msgs)

    m = [int.from_bytes(msgs[i],'big')% G1.order() for i in range(L)]

    if signature.h == G1.neutral_element():
        return False
    
    s = G2.neutral_element()
    for i in range(L):
        s *= pk.Ytilde[i] ** m[i]
    s *= pk.Xtilde
    return signature.h.pair(s) == signature.htilde.pair(G2.generator()) 


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

def non_interactive_proof(
        Group,
        generator,#: G1 | GT,
        Y,#: List[G1|GT],
        witness: Tuple[Bn, List[bytes]],
        commitment,#: G1 | GT,
        message: bytes = b''
    ) -> ZKProof:
    """Create a non-interactive zero-knowledge proof.

    Args:
        Group: The cryptographic group.
        generator: The group generator.
        Y: List of public elements related to attributes.
        witness: A tuple containing a blinding factor and the list of attribute values.
        commitment: The commitment value being proved.
        message: Optional auxiliary message.

    Returns:
        A zero-knowledge proof object.
    """
    t,attributes = witness

    l = len(attributes)

    rt = Group.order().random()
    ra = []
    for _ in range(l):
        ra.append(Group.order().random())
    
    s = Group.neutral_element()
    for i in range(l):
        s *= Y[i] ** ra[i]

    R = generator ** rt * s

    to_hash = str(generator) +str(Y) + str(commitment) + str(R) + str(message)

    c = hashlib.sha256(to_hash.encode()).digest()
    c = int.from_bytes(c,'big') % Group.order()

    st = (rt - c * t) % Group.order()
    sa = []
    for i in range(l):
        sa.append((ra[i] - c * int.from_bytes(attributes[i],'big')) % Group.order())

    return ZKProof(c, st, sa)

def verify_non_interactive_proof(
        Group,
        generator,#: G1 | GT,
        Y,#: List[G1|GT],
        proof: ZKProof,
        commitment,#: G1 | GT,
        message: bytes = b''
    ) -> bool:
    """Verify a non-interactive zero-knowledge proof.

    Args:
        Group: The cryptographic group.
        generator: The group generator.
        Y: List of public elements related to attributes.
        proof: The zero-knowledge proof to verify.
        commitment: The commitment corresponding to the proof.
        message: Optional auxiliary message.

    Returns:
        A boolean indicating whether the proof is valid.
    """
    s = Group.neutral_element()
    for i in range(len(proof.sa)):
        s *= Y[i] ** proof.sa[i]

    R = commitment**proof.c * generator ** proof.st *s

    to_hash = str(generator)+ str(Y) + str( commitment)+str( R) + str(message)

    c = hashlib.sha256(to_hash.encode()).digest()
    c = int.from_bytes(c,'big') % Group.order()

    return proof.c == c

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey, 
        attributes: AttributeMap 
    ) -> Tuple[IssueRequest, Bn]:
    """Create an issuance request for anonymous credentials.

    Args:
        pk: The issuer’s public key.
        attributes: A map of user and issuer attributes.

    Returns:
        A tuple containing:
            - IssueRequest: The request to send to the issuer.
            - Bn: The random scalar used to blind the commitment.
    """

    # check if pk can be used to sign the attributes
    if len(pk.Y) != len(attributes.attributes):
        raise ValueError("Public key does not match the number of attributes")
    for attribute_label in pk.attribute_labels:
        if attribute_label not in attributes.labels():
            raise ValueError(f"Public key does not match the attributes: {attribute_label} not in {attributes.labels()}")

    # get indices for user attributes
    indices_user_attributes = []
    for attribute in attributes.user_attributes:
        if attribute in attributes.attributes:
            index = attributes.attributes.index(attribute)
        else:
            raise ValueError(f"User attribute {attribute} not found in attributes")
        indices_user_attributes.append(index)

    t = G1.order().random()

    witness_values = []
    commitment = G1.generator() ** t
    for i in range(len(indices_user_attributes)):

        # generate bytestring from attribute
        attribute_label = attributes.user_attributes[i].label.encode()
        attribute_value = attributes.user_attributes[i].value

        witness_values.append(attribute_label+attribute_value)

        attribute_int_G1 = int.from_bytes(attribute_label+attribute_value,'big')% G1.order()       
        commitment *= pk.Y[indices_user_attributes[i]] ** attribute_int_G1

    witness = (t, witness_values)

    Y_ZK_proof = [pk.Y[i] for i in indices_user_attributes]

    pi = non_interactive_proof(G1,G1.generator(),Y_ZK_proof, witness, commitment)

    attributes_public = copy.deepcopy(attributes.attributes)
    for i in indices_user_attributes:
        attributes_public[i].value = b''
     
    at_public = AttributeMap(attributes_public, issuer_attributes=attributes.issuer_attributes)

    return IssueRequest(commitment, pi, at_public=at_public), t


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        attributes: AttributeMap # this does not contain the user attributes --> set the value of them to None
    ) -> BlindSignature:
    """Create a blind signature corresponding to the user's request.

    Args:
        sk: The issuer's secret key.
        pk: The issuer’s public key.
        request: The user’s issuance request containing the commitment and proof.
        attributes: A map of issuer-side attributes with user attribute values hidden.

    Returns:
        A blind signature over the attribute values.
    """

    # get indices for issuer attributes
    indices_issuer_attributes = []
    for attribute in attributes.issuer_attributes:
        if attribute in attributes.attributes:
            index = attributes.attributes.index(attribute)
            indices_issuer_attributes.append(index)
        else:
            raise ValueError(f"Issuer attribute {attribute} not found in attributes")
    
    indices_user_attributes = [i for i in range(len(attributes.attributes)) if not i in  indices_issuer_attributes]

    Y_ZK_proof = [pk.Y[i] for i in indices_user_attributes]

    proof = request.proof
    if not verify_non_interactive_proof(G1,G1.generator(),Y_ZK_proof, proof, request.commitment):
        raise ValueError("Invalid proof")

    u = G1.order().random()

    h = sk.X * request.commitment
    for i in range(len(indices_issuer_attributes)):

        attribute_label = attributes.issuer_attributes[i].label.encode()
        attribute_value = attributes.issuer_attributes[i].value

        attribute_int_G1 = int.from_bytes(attribute_label+attribute_value,'big')% G1.order()

        h *= pk.Y[indices_issuer_attributes[i]] ** attribute_int_G1
    h = h ** u 

    return BlindSignature(G1.generator()**u, h )


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        state: Bn,
        attributes: AttributeMap
    ) -> AnonymousCredential:
    """Unblind the issuer's response to obtain a credential.

    Args:
        pk: The issuer’s public key.
        response: The blind signature returned by the issuer.
        state: The blinding scalar used in the request.
        attributes: The full attribute map including user and issuer attributes.

    Returns:
        An anonymous credential verified against the public key.
    """

    t = state
    sig = Signature(response.h, response.htilde/(response.h ** t))

    attributes_bytes = [ attribute.label.encode() + attribute.value for attribute in attributes.attributes]

    if verify(pk, sig, attributes_bytes):
        return AnonymousCredential(sig, attributes)
    else:
        raise ValueError("Invalid signature")


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        disclosed_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """Create a proof for selective attribute disclosure.

    Args:
        pk: The issuer’s public key.
        credential: The credential from which attributes will be disclosed.
        disclosed_attributes: The list of attributes to reveal.
        message: A message to bind into the proof.

    Returns:
        A disclosure proof containing the randomized signature and proof of knowledge.
    """

    attributes = credential.attributes.attributes
    
    # get indices for disclosed attributes
    indices_disclosed_attributes = []
    for attribute in disclosed_attributes:
        if attribute in attributes:
            index = attributes.index(attribute)
            indices_disclosed_attributes.append(index)
        else:
            raise ValueError(f"Disclosed attribute {attribute} not found in attributes of credential")
    
    hidden_attributes = [attribute for attribute in credential.attributes.attributes if attribute not in disclosed_attributes]

    # get indices for hidden attributes
    indices_hidden_attributes = []
    for attribute in hidden_attributes:
        if attribute in attributes:
            index = attributes.index(attribute)
            indices_hidden_attributes.append(index)
    
    r = G1.order().random()
    t = G1.order().random()

    sig = credential.signature
    sig_prime = Signature(sig.h**r,(sig.htilde*sig.h**t) ** r)

    generator = sig_prime.h.pair(G2.generator())
    witness = (t, [attribute.label.encode() + attribute.value for attribute in hidden_attributes])

    commitment = sig_prime.htilde.pair(G2.generator())
    for i in range (len(disclosed_attributes)):

        attribute_label = disclosed_attributes[i].label.encode()
        attribute_value = disclosed_attributes[i].value

        attribute_int_G1 = -int.from_bytes(attribute_label+attribute_value,'big')% G1.order()

        commitment *= sig_prime.h.pair(pk.Ytilde[indices_disclosed_attributes[i]]) ** attribute_int_G1
    commitment = commitment/sig_prime.h.pair(pk.Xtilde)

    Y = [sig_prime.h.pair(pk.Ytilde[indices_hidden_attributes[i]]) for i in range(len(indices_hidden_attributes))]
    
    pi = non_interactive_proof(GT,generator,Y, witness, commitment, message=message)

    return DisclosureProof(sig_prime, pi, disclosed_attributes)


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        attributes: List[Attribute], # all attributes of the credential in the right order
        message: bytes
    ) -> bool:
    """Verify a selective disclosure proof.

    Args:
        pk: The issuer’s public key.
        disclosure_proof: The proof to verify.
        attributes: All attributes (in order) from the credential.
        message: The message that was bound to the proof.

    Returns:
        A boolean indicating whether the proof is valid.
    """

    if disclosure_proof.signature.h == G1.neutral_element():
        return False
    
    disclosed_attributes = disclosure_proof.attributes
    disclosed_attributes_labels = [attribute.label for attribute in disclosed_attributes]
    attributes_labels = [attribute.label for attribute in attributes]

    # get indices for hidden attributes
    indices_disclosed_attributes = []
    for attribute_label in disclosed_attributes_labels:
        if attribute_label in attributes_labels:
            index = attributes_labels.index(attribute_label)
            indices_disclosed_attributes.append(index)
        else:
            raise ValueError(f"Disclosed attribute {attribute_label} not found in attributes")
        
    indices_hidden_attributes = [ i for i in range(len(attributes)) if not i in  indices_disclosed_attributes]

    sig_prime = disclosure_proof.signature

    Y = [sig_prime.h.pair(pk.Ytilde[indices_hidden_attributes[i]]) for i in range(len(indices_hidden_attributes))]
    
    commitment = sig_prime.htilde.pair(G2.generator())
    for i in range (len(disclosed_attributes)):

        attribute_label = disclosed_attributes[i].label.encode()
        attribute_value = disclosed_attributes[i].value

        attribute_int_G1 = - int.from_bytes(attribute_label+attribute_value,'big')% G1.order()

        commitment *= sig_prime.h.pair(pk.Ytilde[indices_disclosed_attributes[i]]) ** attribute_int_G1
    commitment /= sig_prime.h.pair(pk.Xtilde)

    generator = sig_prime.h.pair(G2.generator())
    return verify_non_interactive_proof(GT,generator, Y ,disclosure_proof.proof,commitment, message=message) 

