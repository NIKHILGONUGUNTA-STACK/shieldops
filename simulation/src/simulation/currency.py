"""Financial currency presentation and Indian numbering system formatting for Aegis.

Provides INR (₹) preferred presentation using standard Indian digit grouping
('en-IN', e.g. ₹10,40,234.16) and fixed demonstration reference exchange rates:
- USD -> INR: 84.00
- GBP -> INR: 108.50

Under FinTech core banking safety invariants, native transaction amounts and
account balances remain immutable. Reference INR equivalents are strictly
informational and do not represent actual ledger balances or executed FX conversions.
"""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Any


# Fixed demonstration reference exchange rates (fixed demonstration, not live FX)
DEMONSTRATION_RATES: dict[str, Decimal] = {
    "USD": Decimal("84.00"),
    "GBP": Decimal("108.50"),
    "INR": Decimal("1.00"),
}

DEMONSTRATION_DISCLAIMER: str = (
    "Demonstration reference equivalent. Not an actual ledger balance or executed conversion."
)


def format_inr(amount: Decimal | float | int | str) -> str:
    """Formats an amount into Indian numbering system INR (₹10,40,234.16).

    Follows Indian digit grouping: first 3 digits from right, then groups of 2.
    """
    if amount is None:
        return "—"

    try:
        dec = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        return "—"

    is_negative = dec < 0
    abs_dec = abs(dec)
    str_val = f"{abs_dec:.2f}"
    int_part, dec_part = str_val.split(".")

    if len(int_part) <= 3:
        grouped = int_part
    else:
        last3 = int_part[-3:]
        rem = int_part[:-3]
        groups = []
        while rem:
            groups.append(rem[-2:])
            rem = rem[:-2]
        grouped = ",".join(reversed(groups)) + "," + last3

    prefix = "-₹" if is_negative else "₹"
    return f"{prefix}{grouped}.{dec_part}"


def format_native_currency(amount: Decimal | float | int | str, currency: str) -> str:
    """Formats an amount in its native currency."""
    if amount is None:
        return "—"

    try:
        dec = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        return f"{amount} {currency}"

    curr = (currency or "USD").upper().strip()
    is_neg = dec < 0
    abs_val = abs(dec)

    if curr == "USD":
        # Standard US grouping
        val_str = f"{abs_val:,.2f}"
        return f"-${val_str}" if is_neg else f"${val_str}"
    elif curr == "GBP":
        val_str = f"{abs_val:,.2f}"
        return f"-£{val_str}" if is_neg else f"£{val_str}"
    elif curr == "INR":
        return format_inr(dec)
    else:
        return f"{dec:.2f} {curr}"


def get_demonstration_rate(currency: str) -> Decimal | None:
    """Returns the fixed demonstration reference rate for the specified currency."""
    if not currency:
        return None
    return DEMONSTRATION_RATES.get(currency.upper().strip())


def calculate_inr_equivalent(
    amount: Decimal | float | int | str,
    from_currency: str,
) -> tuple[Decimal, Decimal, str] | None:
    """Calculates the reference INR equivalent using fixed demonstration rates.

    Returns:
        tuple of (inr_amount, rate, rate_label) or None if currency is unsupported.
    """
    if amount is None:
        return None

    try:
        dec = Decimal(str(amount))
    except Exception:
        return None

    curr = (from_currency or "USD").upper().strip()
    rate = get_demonstration_rate(curr)
    if rate is None:
        return None

    inr_amount = (dec * rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    rate_label = f"1 {curr} = ₹{rate:.2f} (Demonstration Rate)"
    return inr_amount, rate, rate_label


def format_dual_presentation(
    amount: Decimal | float | int | str,
    currency: str,
) -> str:
    """Formats an amount with dual-currency transparency.

    Example for USD:
        "$25.00 USD (≈ ₹2,100.00 INR @ demonstration rate 84.00)"
    Example for INR:
        "₹10,40,234.16 INR"
    """
    curr = (currency or "USD").upper().strip()
    native_str = format_native_currency(amount, curr)

    if curr == "INR":
        return f"{native_str} INR"

    equiv = calculate_inr_equivalent(amount, curr)
    if equiv is None:
        return f"{native_str} {curr} (No FX demonstration rate)"

    inr_amount, rate, _ = equiv
    inr_formatted = format_inr(inr_amount)
    return f"{native_str} {curr} (≈ {inr_formatted} INR @ demonstration rate {rate:.2f})"
