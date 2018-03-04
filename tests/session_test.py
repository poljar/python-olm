from olm.account import Account
from olm.session import InboundSession, OutboundSession, Session


class TestClass(object):
    def _create_session(self):
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        id_key = bob.identity_keys()['curve25519']
        one_time = list(bob.one_time_keys()["curve25519"].values())[0]
        session = OutboundSession(alice, id_key, one_time)
        return alice, bob, session

    def test_session_create(self):
        self._create_session()

    def test_session_pickle(self):
        alice, bob, session = self._create_session()
        Session.from_pickle(session.pickle())

    def test_encrypt(self):
        plaintext = "It's a secret to everybody"
        alice, bob, session = self._create_session()
        message = session.encrypt(plaintext)
        bob_session = InboundSession(bob, message)
        assert plaintext == bob_session.decrypt(message)
