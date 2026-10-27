# EMR extension: case inbox for difficult Google Ads cases.
#
# Claude reports cases the skill does not cover. Arman decides them, his rule
# is added to the google-ads-platin-emr skill, and the case is then deleted. The
# database only holds open work, the knowledge lives in the skill.

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import Tool
from mcp.types import ToolAnnotations

import ads_mcp.utils as utils
from ads_mcp.tools.write import _current_user

faelle_mcp = FastMCP("faelle")

_COLLECTION = "faelle"
_DEFAULT_DECIDERS = "a.e@emr-unternehmensberatung.de,p.b@emr-unternehmensberatung.de"


def _collection():
    project = os.environ.get("GOOGLE_ADS_MCP_STORAGE_FIRESTORE_PROJECT")
    if not project:
        raise ToolError("Der Fall-Eingang ist nur über den EMR-Connector (Cloud Run) verfügbar.")
    from google.cloud import firestore

    return firestore.Client(project=project).collection(_COLLECTION)


def _deciders() -> List[str]:
    raw = os.environ.get("EMR_FALL_ENTSCHEIDER", _DEFAULT_DECIDERS)
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


def _require_decider(user: str) -> None:
    if user.lower() not in _deciders():
        raise ToolError(
            "Fälle entscheiden und abschließen dürfen nur: " + ", ".join(_deciders()) + "."
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fall_melden(
    konto: str,
    problem: str,
    vorschlag: str,
    unsicherheit: str,
    frage_an_arman: str,
) -> Dict[str, Any]:
    """Reports a difficult Google Ads case to Arman's inbox.

    Use when the google-ads-platin-emr skill does not cover a decision, several solutions
    are plausible, a check fails and the skill has no answer, or the user asks for
    expert help. Describe the case without personal data of end customers.

    Args:
        konto: Account name and ID, e.g. "Apriori Cleaning 642-644-3333".
        problem: What happened or what needs deciding, in plain language.
        vorschlag: Claude's proposed solution.
        unsicherheit: Why Claude is not sure.
        frage_an_arman: The concrete question Arman should answer.
    """
    doc = {
        "konto": konto,
        "problem": problem,
        "vorschlag": vorschlag,
        "unsicherheit": unsicherheit,
        "frage": frage_an_arman,
        "gemeldet_von": _current_user(),
        "gemeldet_am": _now(),
        "status": "offen",
    }
    _, ref = _collection().add(doc)
    return {"fall_id": ref.id, "status": "offen", "hinweis": "Der Fall liegt jetzt in Armans Eingang."}


def faelle_anzeigen(status: str = "offen", limit: int = 50) -> List[Dict[str, Any]]:
    """Lists reported cases, oldest first.

    Args:
        status: "offen" (default), "entschieden" (decided, rule not yet in the skill) or "alle".
        limit: Maximum number of cases.
    """
    col = _collection()
    query = col if status == "alle" else col.where("status", "==", status)
    rows = [{"fall_id": d.id, **d.to_dict()} for d in query.limit(limit).stream()]
    return sorted(rows, key=lambda r: r.get("gemeldet_am", ""))


def fall_entscheiden(fall_id: str, entscheidung: str, begruendung: str) -> Dict[str, Any]:
    """Records Arman's decision on a case (only for the decision makers).

    After deciding, draft the generalised rule as an addition to the google-ads-emr
    skill (without client details, with status [B]/[N]/[C] and the target reference file).

    Args:
        fall_id: ID from faelle_anzeigen.
        entscheidung: What should be done.
        begruendung: Why, so the rule can be written into the skill.
    """
    user = _current_user()
    _require_decider(user)
    ref = _collection().document(fall_id)
    if not ref.get().exists:
        raise ToolError(f"Fall {fall_id} gibt es nicht.")
    ref.update({
        "status": "entschieden",
        "entscheidung": entscheidung,
        "begruendung": begruendung,
        "entschieden_von": user,
        "entschieden_am": _now(),
    })
    return {"fall_id": fall_id, "status": "entschieden"}


def fall_abschliessen(fall_id: str) -> Dict[str, Any]:
    """Deletes a decided case once its rule is in the google-ads-platin-emr skill (only for the decision makers).

    Args:
        fall_id: ID of a case with status "entschieden".
    """
    user = _current_user()
    _require_decider(user)
    ref = _collection().document(fall_id)
    snap = ref.get()
    if not snap.exists:
        raise ToolError(f"Fall {fall_id} gibt es nicht.")
    if snap.to_dict().get("status") != "entschieden":
        raise ToolError("Nur entschiedene Fälle können abgeschlossen werden. Erst fall_entscheiden.")
    ref.delete()
    utils.logger.info(f"ads_mcp.faelle abgeschlossen {fall_id} von {user}")
    return {"fall_id": fall_id, "geloescht": True}


faelle_mcp.add_tool(Tool.from_function(fall_melden, annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False)))
faelle_mcp.add_tool(Tool.from_function(faelle_anzeigen, annotations=ToolAnnotations(readOnlyHint=True)))
faelle_mcp.add_tool(Tool.from_function(fall_entscheiden, annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False)))
faelle_mcp.add_tool(Tool.from_function(fall_abschliessen, annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True)))
