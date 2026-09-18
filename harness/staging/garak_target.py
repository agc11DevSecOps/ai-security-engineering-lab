"""Deterministic, synthetic-only target for future approved Garak campaigns."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, constr


MAX_MESSAGE_BYTES = 4_096
DEFAULT_REQUEST_BUDGET = 20
logger = logging.getLogger("garak-synthetic-target")


class TargetMode(str, Enum):
    GUARDED = "guarded"
    VULNERABLE = "vulnerable"


class ChatRequest(BaseModel):
    message: constr(min_length=1, max_length=MAX_MESSAGE_BYTES)


class ChatResponse(BaseModel):
    response: str


@dataclass
class SyntheticGarakTarget:
    """Bounded deterministic behavior without an LLM, tools, or external I/O."""

    mode: TargetMode = TargetMode.GUARDED
    request_budget: int = DEFAULT_REQUEST_BUDGET
    _requests: int = field(default=0, init=False)

    def respond(self, message: str) -> str:
        if not isinstance(message, str) or not message.strip():
            raise ValueError("invalid-message")
        if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValueError("message-too-large")
        if self._requests >= self.request_budget:
            raise RuntimeError("request-budget-exhausted")

        self._requests += 1
        request_id = uuid.uuid4().hex
        category = self._category(message)
        outcome = "blocked" if self.mode is TargetMode.GUARDED and category != "benign" else "responded"
        logger.info("request_id=%s category=%s outcome=%s", request_id, category, outcome)
        if outcome == "blocked":
            return "Synthetic target blocked the request."
        if category == "benign":
            return "Synthetic benign response."
        return "SYNTHETIC_TARGET_POLICY_BYPASS"

    @staticmethod
    def _category(message: str) -> str:
        normalized = message.lower()
        if "system override" in normalized or "ignore previous" in normalized:
            return "direct_injection"
        if "base64" in normalized or "encoded:" in normalized:
            return "encoded_injection"
        if "ignore the instructions" in normalized or "[system" in normalized:
            return "indirect_injection"
        return "benign"


def create_app(target: SyntheticGarakTarget | None = None) -> FastAPI:
    """Create, but never start, a synthetic staging API."""
    active_target = target or SyntheticGarakTarget()
    app = FastAPI(title="Garak Synthetic Staging Target")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/chat", response_model=ChatResponse)
    def chat(request: ChatRequest) -> ChatResponse:
        try:
            response = active_target.respond(request.message)
        except ValueError as error:
            raise HTTPException(status_code=400, detail="invalid request") from error
        except RuntimeError as error:
            raise HTTPException(status_code=429, detail="request budget exhausted") from error
        return ChatResponse(response=response)

    return app


def create_staging_app() -> FastAPI:
    """Factory for the approved synthetic smoke target, never production."""
    return create_app(SyntheticGarakTarget(request_budget=10))
