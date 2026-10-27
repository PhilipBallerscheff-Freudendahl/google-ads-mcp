"""Tests for the EMR write tool safeguards (no real API calls)."""

import os
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from google.ads.googleads.client import GoogleAdsClient

from ads_mcp.tools import write

MCC = "6410607198"
CLIENT = "6426443333"


def _real_client():
    return GoogleAdsClient(credentials=mock.Mock(), use_proto_plus=True)


class WriteToolTest(unittest.TestCase):
    def setUp(self):
        os.environ["GOOGLE_ADS_LOGIN_CUSTOMER_ID"] = MCC
        os.environ["EMR_MAX_DAILY_BUDGET_EUR"] = "100"
        os.environ["EMR_MAX_BUDGET_INCREASE_PCT"] = "50"
        os.environ.pop("GOOGLE_ADS_MCP_STORAGE_FIRESTORE_PROJECT", None)
        self.client = _real_client()
        self.ga = mock.Mock()
        self.ga.search_stream.return_value = [mock.Mock(results=[mock.Mock()])]
        self.ga.mutate.return_value = mock.Mock(mutate_operation_responses=[])
        patches = [
            mock.patch.object(write.utils, "get_googleads_client", return_value=self.client),
            mock.patch.object(write.utils, "get_googleads_service", return_value=self.ga),
            mock.patch.object(write, "_has_primary_conversion", return_value=True),
            mock.patch.object(write, "_campaign_running", return_value=True),
            mock.patch.object(write, "_ad_group_running", return_value=True),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _negative_kw(self):
        return [{"campaign_criterion_operation": {"create": {
            "campaign": f"customers/{CLIENT}/campaigns/1",
            "negative": True,
            "keyword": {"text": "fliesen reinigen", "match_type": "PHRASE"}}}}]

    def test_dry_run_returns_token_and_validates_only(self):
        res = write.mutate(CLIENT, self._negative_kw())
        self.assertTrue(res["probelauf"])
        self.assertIn("confirmation_token", res)
        self.assertTrue(self.ga.mutate.call_args.kwargs["request"].validate_only)

    def test_real_run_needs_token(self):
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, self._negative_kw(), validate_only=False)
        self.ga.mutate.assert_not_called()

    def test_real_run_with_matching_token(self):
        token = write.mutate(CLIENT, self._negative_kw())["confirmation_token"]
        res = write.mutate(CLIENT, self._negative_kw(), validate_only=False, confirmation_token=token)
        self.assertTrue(res["ausgefuehrt"])
        self.assertFalse(self.ga.mutate.call_args.kwargs["request"].validate_only)

    def test_token_does_not_fit_other_operations(self):
        token = write.mutate(CLIENT, self._negative_kw())["confirmation_token"]
        other = self._negative_kw()
        other[0]["campaign_criterion_operation"]["create"]["keyword"]["text"] = "etwas anderes"
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, other, validate_only=False, confirmation_token=token)

    def test_mcc_itself_is_blocked(self):
        with self.assertRaises(ToolError):
            write.mutate(MCC, self._negative_kw())

    def test_account_outside_mcc_is_blocked(self):
        self.ga.search_stream.return_value = [mock.Mock(results=[])]
        with self.assertRaises(ToolError):
            write.mutate("4347121950", self._negative_kw())

    def test_blocked_operation_types(self):
        ops = [{"customer_user_access_operation": {"remove": f"customers/{CLIENT}/customerUserAccesses/1"}}]
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, ops)
        ops = [{"conversion_action_operation": {"remove": f"customers/{CLIENT}/conversionActions/1"}}]
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, ops)

    def test_new_campaign_forced_paused(self):
        ops = [{"campaign_operation": {"create": {
            "name": "Test", "status": "ENABLED", "advertising_channel_type": "SEARCH",
            "campaign_budget": f"customers/{CLIENT}/campaignBudgets/-1"}}}]
        res = write.mutate(CLIENT, ops)
        sent = self.ga.mutate.call_args.kwargs["request"].mutate_operations[0]
        self.assertEqual(sent.campaign_operation.create.status.name, "PAUSED")
        self.assertTrue(res["hinweise"])

    def _enable_campaign(self, mask=True):
        op = {"campaign_operation": {"update": {
            "resource_name": f"customers/{CLIENT}/campaigns/1", "status": "ENABLED"}}}
        if mask:
            op["campaign_operation"]["update_mask"] = "status"
        return op

    def test_enabling_campaign_alone_is_marked_activation(self):
        res = write.mutate(CLIENT, [self._enable_campaign()])
        self.assertTrue(res["aktivierung"])
        self.assertIn("GTM-Vorschaumodus", res["naechster_schritt"])

    def test_activation_mixed_with_other_changes_refused(self):
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, [self._enable_campaign()] + self._negative_kw())

    def test_activation_without_primary_conversion_refused(self):
        with mock.patch.object(write, "_has_primary_conversion", return_value=False):
            with self.assertRaises(ToolError):
                write.mutate(CLIENT, [self._enable_campaign()])

    def test_new_keyword_in_running_campaign_is_activation(self):
        ops = [{"ad_group_criterion_operation": {"create": {
            "ad_group": f"customers/{CLIENT}/adGroups/5", "status": "ENABLED",
            "keyword": {"text": "grundreinigung", "match_type": "PHRASE"}}}}]
        self.assertTrue(write.mutate(CLIENT, ops)["aktivierung"])

    def test_new_keyword_in_paused_ad_group_is_no_activation(self):
        ops = [{"ad_group_criterion_operation": {"create": {
            "ad_group": f"customers/{CLIENT}/adGroups/5", "status": "ENABLED",
            "keyword": {"text": "grundreinigung", "match_type": "PHRASE"}}}}]
        with mock.patch.object(write, "_ad_group_running", return_value=False):
            self.assertFalse(write.mutate(CLIENT, ops)["aktivierung"])

    def test_negative_keyword_in_ad_group_is_no_activation(self):
        ops = [{"ad_group_criterion_operation": {"create": {
            "ad_group": f"customers/{CLIENT}/adGroups/5", "negative": True,
            "keyword": {"text": "fliesen", "match_type": "PHRASE"}}}}]
        self.assertFalse(write.mutate(CLIENT, ops)["aktivierung"])

    def test_new_campaign_with_ad_groups_in_one_batch_is_no_activation(self):
        ops = [
            {"campaign_budget_operation": {"create": {
                "resource_name": f"customers/{CLIENT}/campaignBudgets/-1", "name": "B",
                "amount_micros": "20000000", "delivery_method": "STANDARD"}}},
            {"campaign_operation": {"create": {
                "resource_name": f"customers/{CLIENT}/campaigns/-2", "name": "Neu",
                "advertising_channel_type": "SEARCH", "campaign_budget": f"customers/{CLIENT}/campaignBudgets/-1"}}},
            {"ad_group_operation": {"create": {
                "resource_name": f"customers/{CLIENT}/adGroups/-3", "name": "AG",
                "campaign": f"customers/{CLIENT}/campaigns/-2", "status": "ENABLED"}}},
            {"ad_group_criterion_operation": {"create": {
                "ad_group": f"customers/{CLIENT}/adGroups/-3", "status": "ENABLED",
                "keyword": {"text": "grundreinigung", "match_type": "PHRASE"}}}},
        ]
        with mock.patch.object(write, "_campaign_running", wraps=lambda c, rn: "/-" not in rn), \
             mock.patch.object(write, "_ad_group_running", wraps=lambda c, rn, new: False):
            res = write.mutate(CLIENT, ops)
        self.assertFalse(res["aktivierung"])

    def test_recommendation_subscription_blocked(self):
        ops = [{"recommendation_subscription_operation": {"create": {"type": "KEYWORD"}}}]
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, ops)

    def test_update_mask_snake_case_and_list(self):
        for mask in ("amount_micros", ["amount_micros"], "amountMicros"):
            ops = [{"campaign_budget_operation": {"update": {
                "resource_name": f"customers/{CLIENT}/campaignBudgets/1", "amount_micros": "20000000"},
                "update_mask": mask}}]
            with mock.patch.object(write, "_current_budget_micros", return_value=20_000_000):
                res = write.mutate(CLIENT, ops)
            self.assertTrue(res["gueltig"])
            sent = self.ga.mutate.call_args.kwargs["request"].mutate_operations[0]
            self.assertEqual(list(sent.campaign_budget_operation.update_mask.paths), ["amount_micros"])

    def test_pausing_campaign_allowed(self):
        ops = [{"campaign_operation": {"update": {
            "resource_name": f"customers/{CLIENT}/campaigns/1", "status": "PAUSED"},
            "update_mask": "status"}}]
        self.assertTrue(write.mutate(CLIENT, ops)["gueltig"])

    def test_budget_cap(self):
        ops = [{"campaign_budget_operation": {"create": {
            "name": "B", "amount_micros": "150000000", "delivery_method": "STANDARD"}}}]
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, ops)

    def test_budget_increase_limit(self):
        current_row = mock.Mock()
        current_row.campaign_budget.amount_micros = 20_000_000
        self.ga.search_stream.side_effect = [
            [mock.Mock(results=[mock.Mock()])],
            [mock.Mock(results=[current_row])],
        ]
        ops = [{"campaign_budget_operation": {"update": {
            "resource_name": f"customers/{CLIENT}/campaignBudgets/1", "amount_micros": "40000000"},
            "update_mask": "amount_micros"}}]
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, ops)


    def test_shared_negative_list_operations(self):
        ops = [
            {"shared_set_operation": {"create": {
                "resource_name": f"customers/{CLIENT}/sharedSets/-1",
                "name": "EMR Ausschluss DIY", "type": "NEGATIVE_KEYWORDS"}}},
            {"shared_criterion_operation": {"create": {
                "shared_set": f"customers/{CLIENT}/sharedSets/-1",
                "keyword": {"text": "fliesen reinigen", "match_type": "PHRASE"}}}},
            {"campaign_shared_set_operation": {"create": {
                "campaign": f"customers/{CLIENT}/campaigns/1",
                "shared_set": f"customers/{CLIENT}/sharedSets/-1"}}},
        ]
        res = write.mutate(CLIENT, ops)
        self.assertTrue(res["gueltig"])
        self.assertEqual(len(res["zusammenfassung"]), 3)

    def test_shared_criterion_remove(self):
        ops = [{"shared_criterion_operation": {"remove": f"customers/{CLIENT}/sharedCriteria/1~2"}}]
        self.assertTrue(write.mutate(CLIENT, ops)["gueltig"])

    def test_update_without_mask_on_campaign(self):
        ops = [{"campaign_operation": {"update": {
            "resource_name": f"customers/{CLIENT}/campaigns/1", "name": "Neu"}}}]
        self.assertTrue(write.mutate(CLIENT, ops)["gueltig"])


    def test_enabling_campaign_without_mask_is_still_activation(self):
        res = write.mutate(CLIENT, [self._enable_campaign(mask=False)])
        self.assertTrue(res["aktivierung"])

    def test_budget_update_without_mask_checked(self):
        ops = [{"campaign_budget_operation": {"update": {
            "resource_name": f"customers/{CLIENT}/campaignBudgets/1", "amount_micros": "500000000"}}}]
        with self.assertRaises(ToolError):
            write.mutate(CLIENT, ops)


if __name__ == "__main__":
    unittest.main()
