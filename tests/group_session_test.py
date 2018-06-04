from builtins import str

import pytest
from olm import InboundGroupSession, OlmGroupSessionError, OutboundGroupSession


class TestClass(object):
    def test_session_create(self):
        OutboundGroupSession()

    def test_session_id(self):
        session = OutboundGroupSession()
        assert isinstance(session.id, str)

    def test_session_index(self):
        session = OutboundGroupSession()
        assert isinstance(session.message_index, int)
        assert session.message_index == 0

    def test_outbound_pickle(self):
        session = OutboundGroupSession()
        pickle = session.pickle()

        assert (session.id == OutboundGroupSession.from_pickle(
            pickle).id)

    def test_inbound_create(self):
        outbound = OutboundGroupSession()
        InboundGroupSession(outbound.session_key)

    def test_inbound_pickle(self):
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        pickle = inbound.pickle()
        InboundGroupSession.from_pickle(pickle)

    def test_inbound_export(self):
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        imported = InboundGroupSession.import_session(
            inbound.export_session(inbound.first_known_index)
        )
        assert "Test" == imported.decrypt(outbound.encrypt("Test"))

    def test_encrypt(self, benchmark):
        benchmark.weave(OutboundGroupSession.encrypt, lazy=True)
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        assert "Test" == inbound.decrypt(outbound.encrypt("Test"))

    def test_decrypt(self, benchmark):
        benchmark.weave(InboundGroupSession.decrypt, lazy=True)
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        assert "Test" == inbound.decrypt(outbound.encrypt("Test"))

    def test_decrypt_failure(self):
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        eve_outbound = OutboundGroupSession()
        with pytest.raises(OlmGroupSessionError):
            inbound.decrypt(eve_outbound.encrypt("Test"))

    def test_id(self):
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        assert outbound.id == inbound.id

    def test_inbound_fail(self):
        with pytest.raises(ValueError):
            InboundGroupSession()

    def test_oubtound_pickle_fail(self):
        outbound = OutboundGroupSession()
        pickle = outbound.pickle("Test")

        with pytest.raises(OlmGroupSessionError):
            OutboundGroupSession.from_pickle(pickle)
