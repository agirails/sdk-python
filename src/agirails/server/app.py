"""
FastAPI app factory for the AIP-2.1 quote channel daemon (``actp serve``).

Builds an ASGI app exposing:

  - ``GET  /``                                 → health check
  - ``POST /quote-channel/{chainId}/{txId}``   → counter-offer ingest

The counter-offer endpoint runs :class:`QuoteChannelHandler` (signature
+ TTL + dedup + path-binding checks) and, on success, evaluates the
verified message against the loaded :class:`ProviderPolicy` via
:func:`evaluate_counter`. The verdict is logged but NOT auto-sent back
to the buyer in v1 (see AIP-2.1-DRAFT §5.3 — operator handles reply
delivery).

Note: FastAPI / uvicorn are an OPTIONAL dependency. Install with::

    pip install agirails[server]

@module server/app
"""

from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agirails.server.policy import ProviderPolicy
from agirails.server.policy_engine import evaluate_counter
from agirails.server.quote_channel import (
    HandlerContext,
    QuoteChannelHandler,
    build_channel_path,
)
from agirails.utils.logger import Logger

_logger = Logger("agirails.server.app")


def create_app(
    policy: ProviderPolicy,
    kernel_address_by_chain_id: Dict[int, str],
    signer_address: str,
    service_label: str = "actp-serve",
) -> Any:
    """Construct the FastAPI app.

    Args:
        policy: Loaded :class:`ProviderPolicy`.
        kernel_address_by_chain_id: Mapping ``{chainId: kernel_address}``
            so the handler can verify EIP-712 signatures bound to the
            on-chain ACTPKernel for each supported chain.
        signer_address: Provider address (shown on the health endpoint
            for operational visibility).
        service_label: Identifier returned by the health check.

    Returns:
        A configured :class:`fastapi.FastAPI` instance ready to be
        passed to ``uvicorn.run`` or mounted under a parent app.
    """
    app = FastAPI(title="AGIRAILS — actp serve", version="1.0.0")
    handler = QuoteChannelHandler(
        kernel_address_by_chain_id=kernel_address_by_chain_id,
    )

    @app.get("/")
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "provider": signer_address,
            "chains": list(kernel_address_by_chain_id.keys()),
            "service": service_label,
        }

    @app.post("/quote-channel/{chain_id}/{tx_id}")
    async def quote_channel(
        chain_id: int, tx_id: str, request: Request
    ) -> Any:
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"accepted": False, "reason": "Invalid JSON"},
            )

        result = handler.handle(
            payload,
            HandlerContext(path_chain_id=chain_id, path_tx_id=tx_id),
        )

        # Disambiguate: the handler's ``accepted`` flag is "message accepted
        # FOR PROCESSING" (signature + path + TTL + dedup passed). The policy
        # verdict (ACCEPT / COUNTER / REJECT) is a SECOND, business-level
        # answer to "does the provider agree to the proposed price". We
        # surface both in the response so buyers can distinguish a transport
        # failure (status 4xx, accepted=false) from a successful negotiation
        # round that ended in policy rejection (status 201, accepted=true,
        # verdict.action="REJECT"). The verdict is also logged for operators.
        # v1 still does NOT auto-deliver CounterAccept back (AIP-2.1 §5.3
        # — operator handles signed reply delivery).
        body = dict(result.body)  # copy so we don't mutate HandlerResult.body
        if result.parsed_message is not None:
            try:
                verdict = evaluate_counter(result.parsed_message, policy)
                body["verdict"] = {
                    "action": verdict.action.value,
                    "reason": verdict.reason,
                    "recommended_amount": (
                        str(verdict.recommended_amount)
                        if verdict.recommended_amount is not None
                        else None
                    ),
                }
                _logger.info(
                    f"[counter] tx={tx_id[:12]}… "
                    f"counter={result.parsed_message.counterAmount} "
                    f"→ {verdict.action.value}: {verdict.reason}"
                )
            except Exception as exc:
                _logger.warning(
                    f"[counter] tx={tx_id[:12]}… "
                    f"policy eval failed: {exc}"
                )
                body["verdict_error"] = str(exc)

        return JSONResponse(status_code=result.status, content=body)

    return app


__all__ = ["create_app"]
