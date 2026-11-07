"""Tests for Aegis currency presentation and Indian numbering system formatting."""

from decimal import Decimal
import pytest

from simulation.currency import (
    DEMONSTRATION_RATES,
    DEMONSTRATION_DISCLAIMER,
    calculate_inr_equivalent,
    format_dual_presentation,
    format_inr,
    format_native_currency,
    get_demonstration_rate,
)


class TestIndianNumberingSystem:
    """Verifies Indian digit grouping ('en-IN', e.g. ₹10,40,234.16)."""

    def test_standard_indian_digit_grouping(self):
        # Alex Morgan source account balance in INR
        assert format_inr(Decimal("1040234.16")) == "₹10,40,234.16"
        assert format_inr("1040234.16") == "₹10,40,234.16"

    def test_crore_and_lakh_grouping(self):
        # 1 Crore = 1,00,00,000.00
        assert format_inr(10000000.00) == "₹1,00,00,000.00"
        # 10 Lakh = 10,00,000.00
        assert format_inr(1000000.00) == "₹10,00,000.00"
        # 5 Lakh 75 Thousand 77 and 13 paise
        assert format_inr(575077.13) == "₹5,75,077.13"

    def test_thousand_and_hundreds_grouping(self):
        # 2,100.00 (Planned transfer in INR)
        assert format_inr(2100.00) == "₹2,100.00"
        assert format_inr(100.50) == "₹100.50"
        assert format_inr(25.00) == "₹25.00"

    def test_zero_formatting(self):
        assert format_inr(0) == "₹0.00"
        assert format_inr(Decimal("0.00")) == "₹0.00"

    def test_negative_formatting(self):
        assert format_inr(-4200.50) == "-₹4,200.50"
        assert format_inr(Decimal("-2100.00")) == "-₹2,100.00"

    def test_null_and_invalid_inputs(self):
        assert format_inr(None) == "—"
        assert format_inr("invalid-number") == "—"


class TestDemonstrationRatesAndConversions:
    """Verifies fixed demonstration reference rates (84.00 USD, 108.50 GBP)."""

    def test_demonstration_rates_constants(self):
        assert DEMONSTRATION_RATES["USD"] == Decimal("84.00")
        assert DEMONSTRATION_RATES["GBP"] == Decimal("108.50")
        assert DEMONSTRATION_RATES["INR"] == Decimal("1.00")

    def test_get_demonstration_rate(self):
        assert get_demonstration_rate("USD") == Decimal("84.00")
        assert get_demonstration_rate("gbp") == Decimal("108.50")
        assert get_demonstration_rate("INR") == Decimal("1.00")
        assert get_demonstration_rate("EUR") is None
        assert get_demonstration_rate("") is None

    def test_calculate_usd_to_inr_equivalent(self):
        # Planned transfer: 25.00 USD * 84.00 = 2100.00 INR
        result = calculate_inr_equivalent(Decimal("25.00"), "USD")
        assert result is not None
        inr_amt, rate, label = result
        assert inr_amt == Decimal("2100.00")
        assert rate == Decimal("84.00")
        assert "1 USD = ₹84.00" in label

        # Alex Morgan preflight balance: 12383.74 USD * 84.00 = 1040234.16 INR
        result = calculate_inr_equivalent(Decimal("12383.74"), "USD")
        assert result is not None
        assert result[0] == Decimal("1040234.16")

    def test_calculate_gbp_to_inr_equivalent(self):
        # Sam Taylor balance: 5300.25 GBP * 108.50 = 575077.125 -> 575077.13
        result = calculate_inr_equivalent(Decimal("5300.25"), "GBP")
        assert result is not None
        assert result[0] == Decimal("575077.13")

    def test_unsupported_currency_returns_none(self):
        assert calculate_inr_equivalent(Decimal("100.00"), "EUR") is None
        assert calculate_inr_equivalent(Decimal("100.00"), "JPY") is None

    def test_none_and_invalid_amount_returns_none(self):
        assert calculate_inr_equivalent(None, "USD") is None
        assert calculate_inr_equivalent("not-a-number", "USD") is None


class TestDualPresentationAndNativeFormatting:
    """Verifies dual presentation transparency and native currency formatting."""

    def test_format_native_currency(self):
        assert format_native_currency(Decimal("12383.74"), "USD") == "$12,383.74"
        assert format_native_currency(Decimal("5300.25"), "GBP") == "£5,300.25"
        assert format_native_currency(Decimal("1040234.16"), "INR") == "₹10,40,234.16"
        assert format_native_currency(Decimal("-25.00"), "USD") == "-$25.00"

    def test_format_dual_presentation_usd(self):
        dual = format_dual_presentation(Decimal("25.00"), "USD")
        assert "$25.00 USD" in dual
        assert "₹2,100.00 INR" in dual
        assert "demonstration rate 84.00" in dual

    def test_format_dual_presentation_gbp(self):
        dual = format_dual_presentation(Decimal("5300.25"), "GBP")
        assert "£5,300.25 GBP" in dual
        assert "₹5,75,077.13 INR" in dual
        assert "demonstration rate 108.50" in dual

    def test_format_dual_presentation_native_inr(self):
        dual = format_dual_presentation(Decimal("1040234.16"), "INR")
        assert dual == "₹10,40,234.16 INR"

    def test_format_dual_presentation_unsupported(self):
        dual = format_dual_presentation(Decimal("100.00"), "EUR")
        assert "100.00 EUR" in dual
        assert "No FX demonstration rate" in dual

    def test_disclaimer_preserves_safety_invariant(self):
        assert "Demonstration reference equivalent" in DEMONSTRATION_DISCLAIMER
        assert "Not an actual ledger balance" in DEMONSTRATION_DISCLAIMER
