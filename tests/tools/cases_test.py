"""Tests for the EMR case inbox (Firestore mocked)."""

import os
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError

from ads_mcp.tools import cases


class FakeDoc:
    def __init__(self, store, doc_id):
        self.store, self.id = store, doc_id

    def get(self):
        snap = mock.Mock()
        snap.exists = self.id in self.store
        snap.to_dict = lambda: dict(self.store.get(self.id, {}))
        return snap

    def update(self, data):
        self.store[self.id].update(data)

    def delete(self):
        self.store.pop(self.id, None)


class FakeCollection:
    def __init__(self):
        self.store, self.n = {}, 0
        self._filter = None

    def add(self, doc):
        self.n += 1
        doc_id = f"f{self.n}"
        self.store[doc_id] = dict(doc)
        return None, mock.Mock(id=doc_id)

    def document(self, doc_id):
        return FakeDoc(self.store, doc_id)

    def where(self, field, op, value):
        c = FakeCollection(); c.store, c._filter = self.store, (field, value); return c

    def limit(self, n):
        return self

    def stream(self):
        for k, v in self.store.items():
            if self._filter and v.get(self._filter[0]) != self._filter[1]:
                continue
            yield mock.Mock(id=k, to_dict=lambda v=v: dict(v))


class CasesTest(unittest.TestCase):
    def setUp(self):
        self.col = FakeCollection()
        os.environ.pop("EMR_FALL_ENTSCHEIDER", None)
        for p in (mock.patch.object(cases, "_collection", return_value=self.col),):
            p.start(); self.addCleanup(p.stop)

    def _melden(self, user="chantal@emr-unternehmensberatung.de"):
        with mock.patch.object(cases, "_current_user", return_value=user):
            return cases.fall_melden("Apriori 642-644-3333", "P", "V", "U", "F")

    def test_report_and_list(self):
        fid = self._melden()["fall_id"]
        rows = cases.faelle_anzeigen()
        self.assertEqual(rows[0]["fall_id"], fid)
        self.assertEqual(rows[0]["gemeldet_von"], "chantal@emr-unternehmensberatung.de")

    def test_only_deciders_can_decide(self):
        fid = self._melden()["fall_id"]
        with mock.patch.object(cases, "_current_user", return_value="chantal@emr-unternehmensberatung.de"):
            with self.assertRaises(ToolError):
                cases.fall_entscheiden(fid, "E", "B")

    def test_decide_then_close_keeps_record(self):
        fid = self._melden()["fall_id"]
        with mock.patch.object(cases, "_current_user", return_value="a.e@emr-unternehmensberatung.de"):
            with self.assertRaises(ToolError):
                cases.fall_abschliessen(fid)
            cases.fall_entscheiden(fid, "Ausschließen", "DIY-Suchen")
            self.assertEqual(cases.faelle_anzeigen("entschieden")[0]["entscheidung"], "Ausschließen")
            cases.fall_abschliessen(fid)
        self.assertEqual(cases.faelle_anzeigen("offen"), [])
        self.assertEqual(cases.faelle_anzeigen("entschieden"), [])
        kept = cases.faelle_anzeigen("abgeschlossen")[0]
        self.assertEqual(kept["entscheidung"], "Ausschließen")
        self.assertEqual(kept["abgeschlossen_von"], "a.e@emr-unternehmensberatung.de")


if __name__ == "__main__":
    unittest.main()
