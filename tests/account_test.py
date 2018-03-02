from olm.account import Account


class TestClass(object):
    def test_account_creation(self):
        alice = Account()
        assert alice.identity_keys()

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

    def test_one_time_keys(self):
        alice = Account()
        assert alice.identity_keys()
