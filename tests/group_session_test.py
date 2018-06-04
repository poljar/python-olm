from builtins import str

import pytest
from olm.group_session import (InboundGroupSession, OlmGroupSessionError,
                               OutboundGroupSession)


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

    def test_encrypt(self):
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        assert "Test" == inbound.decrypt(outbound.encrypt("Test"))
