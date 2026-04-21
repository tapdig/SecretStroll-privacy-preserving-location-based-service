"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple

# Optional import
from serialization import jsonpickle
from credential import *
import random
import string

# Type aliases
class State:
    def __init__(self, t: G1, attributes: AttributeMap):
        self.t = t
        self.attributes = attributes
    
    def __repr__(self):
        return f'State(t={self.t}, attributes={self.attributes})'


class Server:
    """Server"""
    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.issuer = None


    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """

        attributes = [
            Attribute(label='user secret key'), 
        ]
        for subscription in subscriptions:
            attributes.append(
                Attribute(label = subscription)
            )
        sk, pk = generate_key(attributes)

        return jsonpickle.encode(sk).encode(), jsonpickle.encode(pk).encode()


    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            server_pk: the server's public key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes

        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        
        # decode the received values
        server_sk = jsonpickle.decode(server_sk.decode())
        server_pk = jsonpickle.decode(server_pk.decode())
        issuance_request = jsonpickle.decode(issuance_request.decode())

        # username check
        public_attributes = issuance_request.public_attributes.attributes
        public_attributes_labels = [attr.label for attr in public_attributes]
        try:
            index_username = public_attributes_labels.index('username')
            username_attribute = public_attributes[index_username]
            if username_attribute.value != username.encode():
                raise ValueError('username does not match the username in issuance request')
        except ValueError:
            raise ValueError('issuance request does not contain username attribute')

        # check if subsctriptions are in the issuance request
        for subscription in subscriptions:
            if subscription in public_attributes_labels:
                index_subscription = public_attributes_labels.index(subscription)
                subscription_attribute = public_attributes[index_subscription]
                if subscription_attribute.value != b'subscription':
                    raise ValueError(f'user is not subscribed to {subscription}')
            else:
                raise ValueError(f'subscription {subscription} is not contained in issuance request')


        blind_sig = sign_issue_request(
            server_sk,
            server_pk,
            issuance_request,
            issuance_request.public_attributes,
        )
        
        return jsonpickle.encode(blind_sig).encode()


    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
    ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """

        # deserialize
        server_pk = jsonpickle.decode(server_pk.decode())
        signature = jsonpickle.decode(signature.decode())

        # check that all claimed attributes are found in the signature
        disclosed_attr_labels = [attr.label for attr in signature.attributes]
        for revealed_attr in revealed_attributes:
            if revealed_attr not in disclosed_attr_labels:
                # claimed an attribute that wasn't disclosed
                return False

        # verify that all attributes in the signature are in revealed_attributes
        for sig_attr in signature.attributes:
            if sig_attr.label not in revealed_attributes:
                # signature includes attribute we didn't ask for
                return False

        server_attribute_labels = server_pk.attribute_labels
        attributes_with_values = []
        for i in range(len(server_attribute_labels)):
            if server_attribute_labels[i] in revealed_attributes:
                
                # find the attribute in the signature
                for j in range(len(signature.attributes)):
                    if server_attribute_labels[i] == signature.attributes[j].label:
                        attributes_with_values.append( Attribute(
                            label = server_attribute_labels[i],
                            value = signature.attributes[j].value
                        ))                           
                        break
                
            else:
                attributes_with_values.append(
                    Attribute(
                        label = server_attribute_labels[i],
                        value = b''
                    ))

        return verify_disclosure_proof(
            server_pk,
            signature,
            attributes_with_values,
            message
        )



class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """

        self.secret_key = ''.join(random.choices(
            population = string.ascii_letters + string.digits,
            k=16))

    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to process_registration_response.
                You need to design the state yourself.
        """
        # decode the received values
        server_pk = jsonpickle.decode(server_pk.decode())

        attributes_server = server_pk.attribute_labels

        attributes = []
        for i in range(len(attributes_server)):

            if attributes_server[i] == 'user secret key':
                attributes.append(Attribute(
                    label=attributes_server[i],
                    value=self.secret_key.encode()
                ))
            elif attributes_server[i] == 'username':
                attributes.append(Attribute(
                    label=attributes_server[i],
                    value=username.encode()
                ))
            elif attributes_server[i] in subscriptions:
                attributes.append(
                    Attribute(
                        label=attributes_server[i],
                        value=b'subscription'
                    )
                )
            else:
                attributes.append(
                    Attribute(
                        label=attributes_server[i],
                        value=b'not subscribed'
                    )
                )

        # generate attribute map
        at = AttributeMap(attributes, user_attributes=attributes[:1])

        issuance_request, t = create_issue_request(server_pk, at)

        state = State(t, at)

        return jsonpickle.encode(issuance_request).encode(), state

    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """

        server_pk = jsonpickle.decode(server_pk.decode())
        server_response = jsonpickle.decode(server_response.decode())

        cred = obtain_credential(
            server_pk,
            server_response,
            private_state.t,
            private_state.attributes
        )

        return jsonpickle.encode(cred).encode()


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """

        server_pk = jsonpickle.decode(server_pk.decode())
        credentials = jsonpickle.decode(credentials.decode())

        at = credentials.attributes.attributes

        disclosed_attributes = []
        for i in range(len(at)):
            if at[i].label in types:
                disclosed_attributes.append(at[i])

        disclosure_proof = create_disclosure_proof(
            server_pk,
            credentials,
            disclosed_attributes,
            message)
        
        return jsonpickle.encode(disclosure_proof).encode()