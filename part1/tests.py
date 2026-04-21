import pytest
from typing import List, Tuple
import hashlib
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element

from credential import (
    Attribute, AttributeMap, SecretKey, PublicKey, Signature, ZKProof,
    generate_key, sign, verify, 
    create_issue_request, sign_issue_request, obtain_credential,
    create_disclosure_proof, verify_disclosure_proof,
    non_interactive_proof, verify_non_interactive_proof
)

from stroll import Client, Server
import jsonpickle

# helper function to decode serialized data
def decode_data(data: bytes):
    return jsonpickle.decode(data.decode())


class TestPSSignature:
    """Test suite for PS signature functionality"""
    
    def test_key_generation(self):
        """Test key generation and key structure"""
        attributes = [
            Attribute(label="attr1", value=b"value1"),
            Attribute(label="attr2", value=b"value2"),
            Attribute(label="attr3", value=b"value3")
        ]
        
        sk, pk = generate_key(attributes)
        
        # check secret key
        assert isinstance(sk, SecretKey)
        assert isinstance(sk.x, Bn)
        assert isinstance(sk.X, G1Element)
        assert len(sk.y) == len(attributes)
        
        # check X = g^x and Xtilde = g_tilde^x
        assert sk.X == G1.generator() ** sk.x
        assert pk.Xtilde == G2.generator() ** sk.x
        
        # check public key
        assert isinstance(pk, PublicKey)
        assert isinstance(pk.Xtilde, G2Element)
        assert len(pk.Y) == len(attributes)
        assert len(pk.Ytilde) == len(attributes)
        
        for i in range(len(attributes)):
            assert pk.Y[i] == G1.generator() ** sk.y[i]
            assert pk.Ytilde[i] == G2.generator() ** sk.y[i]
        
        assert pk.attribute_labels == [attr.label for attr in attributes]
    
    def test_sign_verify(self):
        """Test signing and verification"""
        attributes = [
            Attribute(label="attr1", value=b"value1"),
            Attribute(label="attr2", value=b"value2"),
            Attribute(label="attr3", value=b"value3")
        ]
        
        sk, pk = generate_key(attributes)
        
        messages = [attr.label.encode() + attr.value for attr in attributes]
        signature = sign(sk, messages)
        
        # verify signature
        assert verify(pk, signature, messages)
        
        # verification with wrong message should fail
        wrong_messages = messages.copy()
        wrong_messages[1] = b"wrong_label"+b"wrong_value"
        assert not verify(pk, signature, wrong_messages)


class TestCredentialSystem:
    """Test suite for the attribute-based credential (ABC) system"""
    
    @pytest.fixture
    def setup_credential_system(self):
        """Basic setup for credential tests"""
        attributes = [
            Attribute(label="user secret key", value=b"secret_value"),
            Attribute(label="restaurant", value=b"subscription"),
            Attribute(label="gym", value=b"subscription"),
            Attribute(label="dojo", value=b"subscription")
        ]
        
        sk, pk = generate_key(attributes)
        
        user_attributes = [attributes[0]]  # secret key
        issuer_attributes = attributes[1:]  # subscriptions
        
        user_map = AttributeMap(attributes=attributes, user_attributes=user_attributes)
        issuer_map = AttributeMap(attributes=attributes, issuer_attributes=issuer_attributes)
        
        return {
            'attributes': attributes,
            'sk': sk,
            'pk': pk,
            'user_map': user_map,
            'issuer_map': issuer_map
        }
    
    def test_issue_request_creation(self, setup_credential_system):
        """Test creation of an issuance request with value verification"""
        setup = setup_credential_system
        
        issue_request, user_state = create_issue_request(setup['pk'], setup['user_map'])
        
        # basic structure checks
        assert issue_request is not None
        assert user_state is not None
        assert isinstance(issue_request.commitment, G1Element)
        assert isinstance(issue_request.proof, ZKProof)
        assert issue_request.public_attributes is not None
        
        # ZK proof structure checks
        assert isinstance(issue_request.proof.c, Bn)
        assert isinstance(issue_request.proof.st, Bn)
        assert isinstance(issue_request.proof.sa, list)
        
        # verify that public attributes have correct structure
        public_attrs = issue_request.public_attributes.attributes
        assert len(public_attrs) == len(setup['attributes'])
        
        # check that user attribute value is hidden (empty) in public attributes
        user_attr_found = False
        for attr in public_attrs:
            if attr.label == "user secret key":
                assert attr.value == b''  # should be hidden
                user_attr_found = True
            elif attr.label in ["restaurant", "gym", "dojo"]:
                # issuer attributes should have their values
                assert attr.value in [b'subscription', b'not subscribed']
        assert user_attr_found
        
        # verify that ZK proof is valid
        user_attr_indices = [0]
        Y_for_proof = [setup['pk'].Y[i] for i in user_attr_indices]
        assert verify_non_interactive_proof(
            G1, G1.generator(), Y_for_proof, 
            issue_request.proof, issue_request.commitment
        )
    
    def test_issue_request_signing(self, setup_credential_system):
        """Test signing of an issuance request with correctness verification"""
        setup = setup_credential_system
        
        issue_request, user_state = create_issue_request(setup['pk'], setup['user_map'])
        
        blind_signature = sign_issue_request(
            setup['sk'], setup['pk'], issue_request, setup['issuer_map']
        )
        
        # basic structure checks
        assert blind_signature is not None
        assert isinstance(blind_signature.h, G1Element)
        assert isinstance(blind_signature.htilde, G1Element)
        
        # verify that a valid credential can be obtained from blind signature
        credential = obtain_credential(
            setup['pk'], blind_signature, user_state, setup['user_map']
        )
        
        # test the obtained credential to have a valid signature
        all_attr_bytes = [attr.label.encode() + attr.value for attr in setup['attributes']]
        assert verify(setup['pk'], credential.signature, all_attr_bytes)
        
        # verify credential structure
        assert credential.attributes.attributes == setup['attributes']
    
    def test_non_interactive_proof(self):
        """Test zero-knowledge (ZK) proof generation and verification"""
        
        # setup for ZK proof
        t = G1.order().random()
        attributes = [b"test1", b"test2"]
        
        # generate group elements for testing
        Y = [G1.generator() ** G1.order().random() for _ in range(len(attributes))]
        commitment = G1.generator() ** t
        for i in range(len(attributes)):
            commitment *= Y[i] ** (int.from_bytes(attributes[i], 'big') % G1.order())
        
        # proof creation
        witness = (t, attributes)
        proof = non_interactive_proof(G1, G1.generator(), Y, witness, commitment)
        
        # proof verification
        assert verify_non_interactive_proof(G1, G1.generator(), Y, proof, commitment)
        
        # check that proof fails with wrong commitment
        wrong_commitment = G1.generator() ** G1.order().random()
        assert not verify_non_interactive_proof(G1, G1.generator(), Y, proof, wrong_commitment)
        

class TestSecretStrollIntegration:
    """Test suite for the SecretStroll integration"""
    
    def test_server_generate_ca(self):
        """Test server's CA generation"""
        subscriptions = ["restaurant", "gym", "dojo"]
        
        # generate CA
        sk_bytes, pk_bytes = Server.generate_ca(subscriptions)
        
        # check that we have valid serialized data
        assert isinstance(sk_bytes, bytes)
        assert isinstance(pk_bytes, bytes)
        assert len(sk_bytes) > 0
        assert len(pk_bytes) > 0
        
        # decode and check structure
        sk = decode_data(sk_bytes)
        pk = decode_data(pk_bytes)
        
        assert isinstance(sk, SecretKey)
        assert isinstance(pk, PublicKey)
        
        # check key correctness
        expected_attributes = ["user secret key"] + subscriptions
        assert pk.attribute_labels == expected_attributes
        assert len(sk.y) == len(expected_attributes)
        assert len(pk.Y) == len(expected_attributes)
        assert len(pk.Ytilde) == len(expected_attributes)
        
        # verify keys
        assert sk.X == G1.generator() ** sk.x
        assert pk.Xtilde == G2.generator() ** sk.x
        
        for i in range(len(expected_attributes)):
            assert pk.Y[i] == G1.generator() ** sk.y[i]
            assert pk.Ytilde[i] == G2.generator() ** sk.y[i]
        
        # test signing and verification with keys
        test_messages = [b"test"] * len(expected_attributes)
        test_signature = sign(sk, test_messages)
        assert verify(pk, test_signature, test_messages)
    
    def test_client_prepare_registration(self):
        """Test client's registration preparation"""
        subscriptions = ["restaurant", "gym", "dojo"]
        username = "alice"
        user_subscriptions = ["gym", "dojo"]
        
        _, pk_bytes = Server.generate_ca(subscriptions)
        
        # registration preparation by client
        client = Client()
        request, client_state = client.prepare_registration(
            pk_bytes, 
            username, 
            user_subscriptions
        )
        
        # basic checks
        assert isinstance(request, bytes)
        assert client_state is not None
        assert len(request) > 0
        
        # decode and check request content
        issue_request = decode_data(request)
        pk = decode_data(pk_bytes)
        
        # verify issuance request structure
        assert isinstance(issue_request.commitment, G1Element)
        assert issue_request.commitment != G1.neutral_element()
        
        # check client state
        assert isinstance(client_state.t, Bn)
        assert client_state.t != Bn(0)
        assert len(client_state.attributes.attributes) == len(subscriptions) + 1  # +1 for user secret key
        
        # verify attribute values in client state
        attrs = client_state.attributes.attributes
        secret_key_found = False
        for attr in attrs:
            if attr.label == "user secret key":
                assert attr.value == client.secret_key.encode()
                secret_key_found = True
            elif attr.label in user_subscriptions:
                assert attr.value == b"subscription"
            elif attr.label in subscriptions:
                assert attr.value == b"not subscribed"
        assert secret_key_found
        
        # verify that ZK proof in the request is valid
        user_attr_indices = [0]  # user secret key
        Y_for_proof = [pk.Y[i] for i in user_attr_indices]
        assert verify_non_interactive_proof(
            G1, G1.generator(), Y_for_proof,
            issue_request.proof, issue_request.commitment
        )
    
    def test_server_process_registration(self):
        """Test server's registration processing"""
        subscriptions = ["restaurant", "gym", "dojo"]
        username = "alice"
        
        sk_bytes, pk_bytes = Server.generate_ca(subscriptions)
        
        client = Client()
        pk = decode_data(pk_bytes)
        attributes = []
        
        attributes.append(Attribute(label="user secret key", value=client.secret_key.encode()))
        
        for subscription in subscriptions:
            if subscription in ["gym", "dojo"]:
                attributes.append(Attribute(label=subscription, value=b"subscription"))
            else:
                attributes.append(Attribute(label=subscription, value=b"not subscribed"))
        
        user_map = AttributeMap(attributes=attributes, user_attributes=[attributes[0]])
        issuer_map = AttributeMap(attributes=attributes, issuer_attributes=attributes[1:])
        
        # creating issue request
        issue_request, user_state = create_issue_request(pk, user_map)
        request = jsonpickle.encode(issue_request).encode()
        
        # process registration
        sk = decode_data(sk_bytes)
        issue_req = decode_data(request)
        
        blind_sig = sign_issue_request(sk, pk, issue_req, issuer_map)
        response = jsonpickle.encode(blind_sig).encode()
        
        assert isinstance(response, bytes)
        assert len(response) > 0
        
        # decode and verify blind signature
        blind_sig_decoded = decode_data(response)
        assert isinstance(blind_sig_decoded.h, G1Element)
        assert isinstance(blind_sig_decoded.htilde, G1Element)
        assert blind_sig_decoded.h != G1.neutral_element()
        assert blind_sig_decoded.htilde != G1.neutral_element()
        
        # check if we can obtain a valid credential
        credential = obtain_credential(pk, blind_sig_decoded, user_state, user_map)
        
        # test credential validity
        all_attr_bytes = [attr.label.encode() + attr.value for attr in attributes]
        assert verify(pk, credential.signature, all_attr_bytes)
        
        # check if credential can be used for disclosure
        message = b"test_location"
        disclosed_attrs = [attributes[1]]  # restaurant subscription
        disclosure_proof = create_disclosure_proof(pk, credential, disclosed_attrs, message)
        assert verify_disclosure_proof(pk, disclosure_proof, attributes, message)
    
    def test_location_query(self):
        """Test location query with value verification"""
        subscriptions = ["restaurant", "gym", "dojo"]
        
        sk_bytes, pk_bytes = Server.generate_ca(subscriptions)
        
        server = Server()
        
        location = b"46.52345, 6.57890"
        revealed_subscriptions = ["gym"]
        
        client = Client()
        pk = decode_data(pk_bytes)
        sk = decode_data(sk_bytes)
        
        attributes = []
        attributes.append(Attribute(label="user secret key", value=client.secret_key.encode()))
        
        for subscription in subscriptions:
            attributes.append(Attribute(label=subscription, value=b"subscription"))
        
        user_map = AttributeMap(attributes=attributes, user_attributes=[attributes[0]])
        issuer_map = AttributeMap(attributes=attributes, issuer_attributes=attributes[1:])
        
        issue_request, user_state = create_issue_request(pk, user_map)
        blind_signature = sign_issue_request(sk, pk, issue_request, issuer_map)
        credential = obtain_credential(pk, blind_signature, user_state, user_map)
        
        # test credential validity
        all_attr_bytes = [attr.label.encode() + attr.value for attr in attributes]
        assert verify(pk, credential.signature, all_attr_bytes)
        
        # creating disclosure proof
        disclosed_attrs = [attr for attr in attributes if attr.label in revealed_subscriptions]
        # should find exactly gym subscription
        assert len(disclosed_attrs) == 1
        assert disclosed_attrs[0].label == "gym"
        assert disclosed_attrs[0].value == b"subscription"
        
        disclosure_proof = create_disclosure_proof(pk, credential, disclosed_attrs, location)
        signature = jsonpickle.encode(disclosure_proof).encode()

        # check disclosure proof structure
        decoded_disclosure = decode_data(signature)
        assert isinstance(decoded_disclosure.signature.h, G1Element)
        assert isinstance(decoded_disclosure.signature.htilde, G1Element)
        assert decoded_disclosure.signature.h != G1.neutral_element()
        assert decoded_disclosure.signature.htilde != G1.neutral_element()
        assert len(decoded_disclosure.attributes) == 1
        assert decoded_disclosure.attributes[0].label == "gym"
        assert decoded_disclosure.attributes[0].value == b"subscription"

        # signature verification
        assert server.check_request_signature(
            pk_bytes,
            location,
            revealed_subscriptions,
            signature
        )
        
        # test that verification actually works by verifying disclosure proof
        assert verify_disclosure_proof(pk, decoded_disclosure, attributes, location)
        
        # try with an invalid request, wrong subscription
        assert not server.check_request_signature(
            pk_bytes,
            location,
            ["museum"],
            signature
        )


class TestFailureConditions:
    """Test suite for failure conditions"""
    
    def test_invalid_credential_parameters(self):
        """Test handling of invalid credential parameters"""
        attributes = [
            Attribute(label="attr1", value=b"value1"),
            Attribute(label="attr2", value=b"value2")
        ]
        
        sk, pk = generate_key(attributes)
        
        # try to sign with wrong number of messages but have keys for 2 attributes
        with pytest.raises(ValueError):
            sign(sk, [b"only one message"])
    
    def test_verify_with_invalid_signature(self):
        """Test verification with invalid signature"""
        attributes = [
            Attribute(label="attr1", value=b"value1"),
            Attribute(label="attr2", value=b"value2")
        ]
        
        sk, pk = generate_key(attributes)
        
        # create an invalid signature
        invalid_signature = Signature(G1.generator(), G1.generator())
        
        assert not verify(pk, invalid_signature, [attr.value for attr in attributes])

    
    def test_tampered_proof_challenge(self):
        """Test detection of tampering with the challenge in a ZK proof"""
        attributes = [
            Attribute(label="secret", value=b"secret_value"),
            Attribute(label="attr1", value=b"value1")
        ]
        
        sk, pk = generate_key(attributes)
        
        user_map = AttributeMap(attributes=attributes, user_attributes=[attributes[0]])
        issuer_map = AttributeMap(attributes=attributes, issuer_attributes=[attributes[1]])
        
        issue_request, user_state = create_issue_request(pk, user_map)
        
        # tamper the ZK proof's challenge by setting it to arbitrary value
        original_challenge = issue_request.proof.c
        issue_request.proof.c = Bn(42)
        
        # tampered proof should be rejected by issuer
        with pytest.raises(ValueError):
            sign_issue_request(sk, pk, issue_request, issuer_map)
    
    def test_disclosure_with_invalid_attributes(self):
        """Test disclosure proof with attributes that are not in credential"""
        attributes = [
            Attribute(label="user secret key", value=b"secret_value"),
            Attribute(label="restaurant", value=b"subscription")
        ]
        
        sk, pk = generate_key(attributes)
        user_map = AttributeMap(attributes=attributes, user_attributes=[attributes[0]])
        issuer_map = AttributeMap(attributes=attributes, issuer_attributes=[attributes[1]])
        
        # create credential
        issue_request, user_state = create_issue_request(pk, user_map)
        blind_signature = sign_issue_request(sk, pk, issue_request, issuer_map)
        credential = obtain_credential(pk, blind_signature, user_state, user_map)
        
        # disclosing attribute not in credential
        fake_attribute = Attribute(label="gym", value=b"subscription")
        message = b"test_message"
        
        with pytest.raises(ValueError):
            create_disclosure_proof(pk, credential, [fake_attribute], message)
    
    def test_verify_disclosure_with_wrong_message(self):
        """Test that disclosure verification fails with wrong message"""
        attributes = [
            Attribute(label="user secret key", value=b"secret_value"),
            Attribute(label="restaurant", value=b"subscription")
        ]
        
        sk, pk = generate_key(attributes)
        user_map = AttributeMap(attributes=attributes, user_attributes=[attributes[0]])  
        issuer_map = AttributeMap(attributes=attributes, issuer_attributes=[attributes[1]])
        
        # create credential
        issue_request, user_state = create_issue_request(pk, user_map)
        blind_signature = sign_issue_request(sk, pk, issue_request, issuer_map)
        credential = obtain_credential(pk, blind_signature, user_state, user_map)
        
        # create disclosure proof with one message
        message1 = b"original_message"
        disclosure_proof = create_disclosure_proof(pk, credential, [attributes[1]], message1)
        
        # try to verify with different message
        message2 = b"different_message"
        assert not verify_disclosure_proof(pk, disclosure_proof, attributes, message2)


class TestCompleteCredentialLifecycle:
    """Test complete credential lifecycle from key generation to disclosure"""
    
    def test_full_credential_flow(self):
        """Test the complete credential flow end-to-end"""
        # setup attributes and generate keys
        attributes = [
            Attribute(label="user secret key", value=b"my_secret"),
            Attribute(label="restaurant", value=b"subscription"),
            Attribute(label="gym", value=b"subscription")
        ]
        
        sk, pk = generate_key(attributes)
        
        # create attribute maps
        user_map = AttributeMap(attributes=attributes, user_attributes=[attributes[0]])
        issuer_map = AttributeMap(attributes=attributes, issuer_attributes=attributes[1:])
        
        # credential issuance
        issue_request, user_state = create_issue_request(pk, user_map)
        blind_signature = sign_issue_request(sk, pk, issue_request, issuer_map) 
        credential = obtain_credential(pk, blind_signature, user_state, user_map)
        
        # create disclosure proof, show only restaurant subscription
        message = b"location query"
        disclosed_attrs = [attributes[1]]  # restaurant subscription
        disclosure_proof = create_disclosure_proof(pk, credential, disclosed_attrs, message)
        
        # verify disclosure proof
        assert verify_disclosure_proof(pk, disclosure_proof, attributes, message)
        
        # verify that disclosing different attributes works correctly
        # gym subscription instead of restaurant
        wrong_attrs = [attributes[2]]
        wrong_disclosure = create_disclosure_proof(pk, credential, wrong_attrs, message)
        
        # test that verification succeeds for the correct attributes
        assert verify_disclosure_proof(pk, wrong_disclosure, attributes, message)