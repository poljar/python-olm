from builtins import int

import pytest

from olm.account import Account, OlmAccountError


class TestClass(object):
    def test_account_creation(self):
        alice = Account()
        assert alice.identity_keys()
        assert len(alice.identity_keys()) == 2

    def test_account_pickle(self):
        alice = Account()
        pickle = alice.pickle()
        assert (alice.identity_keys() ==
                Account.from_pickle(pickle).identity_keys())

    def test_passphrase_pickle(self):
        alice = Account()
        passphrase = "It's a secret to everybody"
        pickle = alice.pickle(passphrase)
        assert (alice.identity_keys() ==
                Account.from_pickle(pickle, passphrase).identity_keys())

    def test_wrong_passphrase_pickle(self):
        alice = Account()
        passphrase = "It's a secret to everybody"
        pickle = alice.pickle(passphrase)

        with pytest.raises(OlmAccountError):
            Account.from_pickle(pickle, "")

    def test_one_time_keys(self):
        alice = Account()
        alice.generate_one_time_keys(10)
        one_time_keys = alice.one_time_keys()
        assert one_time_keys
        assert len(one_time_keys["curve25519"]) == 10

    def test_max_one_time_keys(self):
        alice = Account()
        assert isinstance(alice.max_one_time_keys(), int)

    def test_clear(self):
        alice = Account()
        alice.clear()

        assert not alice._account
        assert not alice._buf
