# EMR extension: guarded write access to the Google Ads API.
#
# One generic tool (`mutate`) that runs GoogleAdsService.Mutate with a fixed
# set of safeguards that a prompt cannot switch off:
#   * every change must first run as a dry run (validate_only); the real run
#     needs the confirmation token returned by that dry run for the exact same
#     operations,
#   * only client accounts under the configured manager account (MCC) can be
#     changed, never the MCC itself,
#   * billing, user access and account links are blocked,
#   * new campaigns are always created PAUSED and campaigns cannot be enabled,
#   * daily budgets are capped and budget increases are limited per change,
#   * every real change is written to an audit log.

import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import Tool
from google.ads.googleads.errors import GoogleAdsException
from google.protobuf import json_format
from mcp.types import ToolAnnotations

import ads_mcp.utils as utils

write_mcp = FastMCP("write")

# Operation types (oneof field names of MutateOperation) that are never allowed.
BLOCKED_OPERATIONS = {
    "customer_operation",
    "customer_user_access_operation",
    "customer_user_access_invitation_operation",
    "customer_client_link_operation",
    "customer_manager_link_operation",
    "billing_setup_operation",
    "account_budget_proposal_operation",
    "account_link_operation",
    "product_link_operation",
    "product_link_invitation_operation",
    "data_link_operation",
    "conversion_action_operation",
    "conversion_custom_variable_operation",
    "conversion_goal_campaign_config_operation",
    "conversion_value_rule_operation",
    "conversion_value_rule_set_operation",
    "custom_conversion_goal_operation",
    "customer_conversion_goal_operation",
    "campaign_conversion_goal_operation",
}

_TOKEN_TTL_SECONDS = 30 * 60
_PROCESS_SECRET = secrets.token_bytes(32)


def _max_daily_budget_micros() -> int:
    return int(float(os.environ.get("EMR_MAX_DAILY_BUDGET_EUR", "100")) * 1_000_000)


def _max_increase_pct() -> float:
    return float(os.environ.get("EMR_MAX_BUDGET_INCREASE_PCT", "50"))


def _signing_key() -> bytes:
    key = os.environ.get("GOOGLE_ADS_MCP_JWT_SIGNING_KEY")
    return key.encode() if key else _PROCESS_SECRET


def _current_user() -> str:
    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
        if token is not None:
            claims = getattr(token, "claims", None) or {}
            return claims.get("email") or claims.get("sub") or token.client_id or "unbekannt"
    except Exception:
        pass
    return "lokal"


def _canonical(customer_id: str, operations: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {"customer_id": customer_id, "operations": operations},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _make_token(user: str, customer_id: str, operations: List[Dict[str, Any]]) -> str:
    issued = str(int(time.time()))
    msg = f"{user}|{issued}|{_canonical(customer_id, operations)}".encode()
    sig = hmac.new(_signing_key(), msg, hashlib.sha256).hexdigest()[:32]
    return f"{issued}.{sig}"


def _check_token(token: str | None, user: str, customer_id: str, operations: List[Dict[str, Any]]) -> None:
    if not token or "." not in token:
        raise ToolError(
            "Keine Bestätigung vorhanden. Führe die Änderung zuerst mit validate_only=true aus, "
            "zeige dem Nutzer die Zusammenfassung und übergib danach den confirmation_token."
        )
    issued, sig = token.split(".", 1)
    if not issued.isdigit() or time.time() - int(issued) > _TOKEN_TTL_SECONDS:
        raise ToolError("Die Bestätigung ist abgelaufen (30 Minuten). Bitte den Probelauf wiederholen.")
    msg = f"{user}|{issued}|{_canonical(customer_id, operations)}".encode()
    expected = hmac.new(_signing_key(), msg, hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        raise ToolError(
            "Die Bestätigung passt nicht zu diesen Operationen. Die Änderung muss exakt der "
            "Probelauf-Version entsprechen. Bitte den Probelauf mit den geänderten Operationen wiederholen."
        )


def _ensure_client_account(customer_id: str) -> None:
    mcc = utils._get_login_customer_id()
    if not mcc:
        return
    if customer_id == mcc:
        raise ToolError("Das Verwaltungskonto (MCC) selbst darf nicht geändert werden. Nur Kundenkonten.")
    ga = utils.get_googleads_service("GoogleAdsService")
    query = (
        "SELECT customer_client.id FROM customer_client "
        f"WHERE customer_client.id = {customer_id} AND customer_client.manager = false"
    )
    try:
        rows = [row for batch in ga.search_stream(customer_id=mcc, query=query) for row in batch.results]
    except GoogleAdsException as ex:
        raise ToolError(_format_ads_error(ex))
    if not rows:
        raise ToolError(f"Konto {customer_id} ist kein Kundenkonto unter dem Verwaltungskonto {mcc}.")


def _current_budget_micros(customer_id: str, resource_name: str) -> int | None:
    ga = utils.get_googleads_service("GoogleAdsService")
    query = (
        "SELECT campaign_budget.amount_micros FROM campaign_budget "
        f"WHERE campaign_budget.resource_name = '{resource_name}'"
    )
    for batch in ga.search_stream(customer_id=customer_id, query=query):
        for row in batch.results:
            return int(row.campaign_budget.amount_micros)
    return None


def _check_operations(customer_id: str, parsed: List[Any]) -> List[str]:
    """Applies the safeguards. Mutates create operations where needed and
    returns notes describing automatic adjustments."""
    client = utils.get_googleads_client()
    status_enum = client.enums.CampaignStatusEnum
    notes: List[str] = []
    max_budget = _max_daily_budget_micros()
    max_pct = _max_increase_pct()

    for i, op in enumerate(parsed, start=1):
        kind = op._pb.WhichOneof("operation")
        if kind is None:
            raise ToolError(f"Operation {i} ist leer.")
        if kind in BLOCKED_OPERATIONS:
            raise ToolError(
                f"Operation {i} ({kind}) ist gesperrt. Abrechnung, Nutzer und Zugriffe, "
                "Kontoverknüpfungen und Conversion-Einstellungen ändert der Agent nicht."
            )
        sub = getattr(op, kind)
        action = sub._pb.WhichOneof("operation")
        mask = list(sub.update_mask.paths) if "update_mask" in sub else []

        if kind == "campaign_operation":
            if action == "create":
                if sub.create.status != status_enum.PAUSED:
                    sub.create.status = status_enum.PAUSED
                    notes.append(f"Operation {i}: neue Kampagne wird pausiert angelegt.")
            elif action == "update" and "status" in mask and sub.update.status == status_enum.ENABLED:
                raise ToolError(
                    f"Operation {i}: Kampagnen schaltet der Agent nicht ein. "
                    "Das macht ein Mitarbeiter nach der Prüfung in Google Ads."
                )

        if kind == "campaign_budget_operation" and action in ("create", "update"):
            budget = sub.create if action == "create" else sub.update
            touches_amount = action == "create" or "amount_micros" in mask
            if touches_amount:
                amount = int(budget.amount_micros)
                if amount > max_budget:
                    raise ToolError(
                        f"Operation {i}: Tagesbudget {amount / 1e6:.2f} € liegt über der Grenze "
                        f"von {max_budget / 1e6:.2f} €."
                    )
                if action == "update":
                    current = _current_budget_micros(customer_id, budget.resource_name)
                    if current and amount > current * (1 + max_pct / 100):
                        raise ToolError(
                            f"Operation {i}: Erhöhung von {current / 1e6:.2f} € auf {amount / 1e6:.2f} € "
                            f"ist mehr als {max_pct:.0f} % auf einmal."
                        )
    return notes


def _summarize(ops: List[Dict[str, Any]]) -> List[str]:
    lines = []
    for i, op in enumerate(ops, start=1):
        kind = next(iter(op))
        body = op[kind]
        action = next((a for a in ("create", "update", "remove") if a in body), "?")
        detail = body.get(action)
        lines.append(f"{i}. {kind.replace('_operation', '')}: {action} {json.dumps(detail, ensure_ascii=False)[:300]}")
    return lines


def _format_ads_error(ex: GoogleAdsException) -> str:
    msgs = [f"Google Ads API Error: {e.message}" for e in ex.failure.errors]
    return f"Request ID: {ex.request_id}\n" + "\n".join(msgs)


def _audit(entry: Dict[str, Any]) -> None:
    utils.logger.info("ads_mcp.write audit " + json.dumps(entry, ensure_ascii=False, default=str))
    project = os.environ.get("GOOGLE_ADS_MCP_STORAGE_FIRESTORE_PROJECT")
    if not project:
        return
    try:
        from google.cloud import firestore

        firestore.Client(project=project).collection("aenderungsprotokoll").add(entry)
    except Exception as e:
        utils.logger.error(f"Audit-Log konnte nicht in Firestore geschrieben werden: {e}")


def mutate(
    customer_id: str | int,
    operations: List[Dict[str, Any]],
    validate_only: bool = True,
    confirmation_token: str | None = None,
) -> Dict[str, Any]:
    """Changes a Google Ads client account (campaigns, budgets, ad groups, keywords, ads, bids, targeting).

    ALWAYS work in two steps:
      1. Call with validate_only=true. Google checks the change without saving it.
         The result contains a summary and a confirmation_token.
      2. Show the user, in plain language, exactly what will change and in which account.
         Only after the user explicitly agrees, call again with the IDENTICAL operations,
         validate_only=false and the confirmation_token.

    Args:
        customer_id: Client account ID without dashes, e.g. 6426443333. Must be under the EMR manager account.
        operations: List of Google Ads API MutateOperation objects as JSON, e.g.
            [{"campaign_criterion_operation": {"create": {"campaign": "customers/6426443333/campaigns/123",
              "negative": true, "keyword": {"text": "fliesen reinigen", "match_type": "PHRASE"}}}}]
            Use temporary negative IDs (e.g. customers/{id}/campaignBudgets/-1) to create linked
            objects (budget -> campaign -> ad group -> keywords/ads) in one call.
            Updates need "update_mask", e.g. {"campaign_operation": {"update": {...}, "update_mask": "name"}}.
        validate_only: true = dry run (default). false = real change, needs confirmation_token.
        confirmation_token: Token from the dry run of exactly these operations (valid 30 minutes).

    Safeguards enforced by the server: only client accounts under the MCC; billing, users,
    account links and conversion settings are blocked; new campaigns are created paused and
    campaigns cannot be enabled; daily budgets are capped and budget increases per change are limited.
    """
    customer_id = utils.clean_customer_id(customer_id)
    if not operations:
        raise ToolError("Keine Operationen übergeben.")
    user = _current_user()

    client = utils.get_googleads_client()
    parsed = []
    for i, op in enumerate(operations, start=1):
        msg = client.get_type("MutateOperation")
        try:
            json_format.ParseDict(op, msg._pb)
        except json_format.ParseError as e:
            raise ToolError(f"Operation {i} ist kein gültiges MutateOperation-JSON: {e}")
        parsed.append(msg)

    _ensure_client_account(customer_id)
    notes = _check_operations(customer_id, parsed)
    effective_ops = [
        json_format.MessageToDict(p._pb, preserving_proto_field_name=True) for p in parsed
    ]

    if not validate_only:
        _check_token(confirmation_token, user, customer_id, effective_ops)

    ga = utils.get_googleads_service("GoogleAdsService")
    request = client.get_type("MutateGoogleAdsRequest")
    request.customer_id = customer_id
    request.mutate_operations.extend(parsed)
    request.validate_only = validate_only
    request.partial_failure = False

    try:
        response = ga.mutate(request=request)
    except GoogleAdsException as ex:
        if not validate_only:
            _audit({
                "zeit": datetime.now(timezone.utc).isoformat(), "nutzer": user,
                "konto": customer_id, "ergebnis": "fehler", "operationen": effective_ops,
                "fehler": _format_ads_error(ex),
            })
        raise ToolError(_format_ads_error(ex))

    summary = _summarize(effective_ops)
    if validate_only:
        return {
            "probelauf": True,
            "gueltig": True,
            "konto": customer_id,
            "zusammenfassung": summary,
            "hinweise": notes,
            "confirmation_token": _make_token(user, customer_id, effective_ops),
            "naechster_schritt": "Zusammenfassung dem Nutzer zeigen. Erst nach ausdrücklichem Ja mit "
                                 "validate_only=false, identischen Operationen und diesem Token erneut aufrufen.",
        }

    results = [
        utils.format_output_value(r) for r in response.mutate_operation_responses
    ]
    _audit({
        "zeit": datetime.now(timezone.utc).isoformat(), "nutzer": user, "konto": customer_id,
        "ergebnis": "ausgefuehrt", "operationen": effective_ops, "antwort": results,
    })
    return {"ausgefuehrt": True, "konto": customer_id, "zusammenfassung": summary, "hinweise": notes, "ergebnis": results}


write_mcp.add_tool(
    Tool.from_function(
        mutate,
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
    )
)
