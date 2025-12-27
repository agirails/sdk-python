"""
Simulate Command - Dry-run commands without executing.

Agent-first feature: Preview what a command would do
without actually executing it. Perfect for:
- Testing scripts before running on mainnet
- Understanding fee calculations
- Validating input parameters

PARITY: Matches TypeScript SDK's cli/commands/simulate.ts
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import typer

from agirails.cli.main import get_global_options
from agirails.cli.utils.client import load_config, get_default_address
from agirails.cli.utils.output import (
    print_error,
    print_info,
    print_success,
    print_warning,
    print_json,
    format_usdc,
)
from agirails.adapters.base import BaseAdapter

# Create the simulate command group
simulate_app = typer.Typer(
    name="simulate",
    help="Dry-run a command without executing (agent-first feature)",
)


# ============================================================================
# Fee Calculation (1% with $0.05 minimum)
# ============================================================================

def calculate_fee(amount_wei: int) -> Dict[str, Any]:
    """
    Calculate platform fee based on AGIRAILS fee model.

    - 1% of transaction amount
    - $0.05 minimum

    Args:
        amount_wei: Amount in USDC wei (6 decimals)

    Returns:
        Dictionary with fee calculation details
    """
    # 1% fee
    percent_fee = amount_wei // 100

    # $0.05 minimum in wei (6 decimals)
    minimum_fee_wei = 50_000

    # Apply minimum
    fee = max(percent_fee, minimum_fee_wei)
    minimum_applied = percent_fee < minimum_fee_wei

    # Calculate what provider receives (amount minus fee)
    provider_receives = amount_wei - fee

    # Calculate effective rate
    effective_rate_percent = (fee / amount_wei) * 100 if amount_wei > 0 else 0
    effective_rate = f"{effective_rate_percent:.2f}%"

    return {
        "fee": fee,
        "provider_receives": provider_receives,
        "effective_rate": effective_rate,
        "minimum_applied": minimum_applied,
    }


def format_usdc_amount(wei: int) -> str:
    """Format wei amount as USDC string."""
    usdc = wei / 1_000_000
    return f"{usdc:.2f}"


# ============================================================================
# Simulation Adapter (for validation without execution)
# ============================================================================

class SimulationAdapter(BaseAdapter):
    """Extended adapter for simulation purposes."""

    def __init__(self, requester_address: str):
        from agirails.runtime.mock_runtime import MockRuntime
        # Create a minimal mock runtime for simulation
        runtime = MockRuntime()
        super().__init__(runtime, requester_address)

    def validate_payment(
        self,
        to: str,
        amount: str,
        deadline: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate payment parameters without executing.

        Returns:
            Dictionary with validation results
        """
        errors: List[str] = []
        warnings: List[str] = []
        parsed_amount: Optional[int] = None
        parsed_deadline: Optional[int] = None

        # Validate address
        try:
            self.validate_address(to, "to")
        except Exception as e:
            errors.append(str(e))

        # Validate amount
        try:
            parsed_amount = int(self.parse_amount(amount))

            # Check for small amount warning
            if parsed_amount < 5_000_000:  # Less than $5
                warnings.append("Amount is below $5 - minimum fee ($0.05) will apply")
        except Exception as e:
            errors.append(str(e))

        # Validate deadline
        try:
            import time
            current_time = int(time.time())
            parsed_deadline = self.parse_deadline(deadline, current_time)

            if parsed_deadline <= current_time:
                errors.append("Deadline must be in the future")
            else:
                # Check for short deadline warning
                hours_until_deadline = (parsed_deadline - current_time) / 3600
                if hours_until_deadline < 1:
                    warnings.append("Deadline is less than 1 hour from now")
        except Exception as e:
            errors.append(str(e))

        # Check self-payment
        if to.lower() == self._requester_address.lower():
            errors.append("Cannot pay yourself")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "parsed_amount": parsed_amount,
            "parsed_deadline": parsed_deadline,
        }

    def parse_amount_public(self, amount: str) -> int:
        """Public access to parse_amount for fee calculation."""
        return int(self.parse_amount(amount))


# ============================================================================
# simulate pay
# ============================================================================

@simulate_app.command(name="pay")
def simulate_pay(
    to: str = typer.Argument(..., help="Provider address"),
    amount: str = typer.Argument(..., help="Amount to pay"),
    deadline: str = typer.Option("+24h", "--deadline", "-d", help="Deadline (+24h, +7d, or Unix timestamp)"),
) -> None:
    """
    Simulate a payment transaction.

    Shows what would happen if you executed the pay command,
    including fee calculations and validation results.

    Examples:

        $ actp simulate pay 0x123... 100

        $ actp simulate pay 0x123... 100 --deadline +7d

        $ actp simulate pay 0x123... 100 --json
    """
    global_opts = get_global_options()

    try:
        # Load config
        config = load_config(global_opts.directory)
        requester_address = config.get("address", get_default_address())

        # Create simulation adapter
        adapter = SimulationAdapter(requester_address)

        # Validate inputs
        validation = adapter.validate_payment(to, amount, deadline)

        if not validation["valid"]:
            if global_opts.json_output:
                print_json({
                    "valid": False,
                    "errors": validation["errors"],
                })
            else:
                print_error("Validation failed:")
                for error in validation["errors"]:
                    print(f"  - {error}")
            raise typer.Exit(code=1)

        # Calculate fee
        amount_wei = validation["parsed_amount"]
        fee_calc = calculate_fee(amount_wei)

        result = {
            "valid": True,
            "simulation": {
                "action": "CREATE_AND_FUND_TRANSACTION",
                "provider": to.lower(),
                "requester": requester_address.lower(),
                "amount": f"{format_usdc_amount(amount_wei)} USDC",
                "amountWei": str(amount_wei),
                "deadline": datetime.fromtimestamp(validation["parsed_deadline"]).isoformat(),
                "deadlineUnix": validation["parsed_deadline"],
            },
            "fees": {
                "platformFee": f"{format_usdc_amount(fee_calc['fee'])} USDC",
                "platformFeeWei": str(fee_calc["fee"]),
                "feeRate": fee_calc["effective_rate"],
                "providerReceives": f"{format_usdc_amount(fee_calc['provider_receives'])} USDC",
                "minimumApplied": fee_calc["minimum_applied"],
            },
            "requirements": {
                "requiredBalance": f"{format_usdc_amount(amount_wei + fee_calc['fee'])} USDC",
                "mode": config.get("mode", "mock"),
            },
            "warnings": validation["warnings"],
        }

        if global_opts.json_output:
            print_json(result)
        else:
            print("\n=== Simulation Results ===\n")

            print("Transaction Details:")
            print(f"  Action:   Create and fund transaction")
            print(f"  Provider: {to}")
            print(f"  Amount:   {result['simulation']['amount']}")
            print(f"  Deadline: {result['simulation']['deadline']}")

            print("\nFee Breakdown (1% + $0.05 min):")
            print(f"  Platform Fee:      {result['fees']['platformFee']}")
            print(f"  Effective Rate:    {result['fees']['feeRate']}")
            print(f"  Provider Receives: {result['fees']['providerReceives']}")
            if fee_calc["minimum_applied"]:
                print_warning("  (Minimum fee applied - amount < $5)")

            print("\nRequirements:")
            print(f"  Required Balance: {result['requirements']['requiredBalance']}")
            print(f"  Mode:             {result['requirements']['mode']}")

            if validation["warnings"]:
                print("\nWarnings:")
                for warning in validation["warnings"]:
                    print_warning(f"  - {warning}")

            print()
            print_success("Simulation complete - no transaction created")

    except typer.Exit:
        raise
    except Exception as e:
        if global_opts.json_output:
            print_json({"error": {"code": "ERROR", "message": str(e)}})
        else:
            print_error(str(e))
        raise typer.Exit(code=1)


# ============================================================================
# simulate fee
# ============================================================================

@simulate_app.command(name="fee")
def simulate_fee(
    amount: str = typer.Argument(..., help="Amount to calculate fee for"),
) -> None:
    """
    Calculate fee for a given amount.

    Shows the fee breakdown for any transaction amount
    based on the 1% + $0.05 minimum fee model.

    Examples:

        $ actp simulate fee 100

        $ actp simulate fee 1.50 --json
    """
    global_opts = get_global_options()

    try:
        # Parse amount
        adapter = SimulationAdapter("0x" + "0" * 40)
        parsed_amount = adapter.parse_amount_public(amount)

        fee_calc = calculate_fee(parsed_amount)

        result = {
            "amount": f"{format_usdc_amount(parsed_amount)} USDC",
            "amountWei": str(parsed_amount),
            "fee": f"{format_usdc_amount(fee_calc['fee'])} USDC",
            "feeWei": str(fee_calc["fee"]),
            "effectiveRate": fee_calc["effective_rate"],
            "providerReceives": f"{format_usdc_amount(fee_calc['provider_receives'])} USDC",
            "totalRequired": f"{format_usdc_amount(parsed_amount + fee_calc['fee'])} USDC",
            "minimumApplied": fee_calc["minimum_applied"],
        }

        if global_opts.json_output:
            print_json(result)
        else:
            print("\n=== Fee Calculation ===\n")
            print(f"  Amount:            {result['amount']}")
            print(f"  Platform Fee:      {result['fee']}")
            print(f"  Effective Rate:    {result['effectiveRate']}")
            print(f"  Provider Receives: {result['providerReceives']}")
            print(f"  Total Required:    {result['totalRequired']}")

            if fee_calc["minimum_applied"]:
                print()
                print_info("Minimum fee ($0.05) applied because amount < $5")

    except Exception as e:
        if global_opts.json_output:
            print_json({"error": {"code": "ERROR", "message": str(e)}})
        else:
            print_error(str(e))
        raise typer.Exit(code=1)


__all__ = ["simulate_app"]
