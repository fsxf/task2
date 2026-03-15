from __future__ import annotations

import json
import socket
import time
from urllib import error, request

from .config import AppConfig
from .models import CaseContext, LLMReview, StaticEvidence
from .prompting import build_messages
from .tokenizer import estimate_text_tokens


class DeepSeekReviewer:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def review(self, context: CaseContext, evidence: StaticEvidence) -> LLMReview:
        system_prompt, user_prompt = build_messages(context, evidence)
        prompt_tokens = estimate_text_tokens(system_prompt) + estimate_text_tokens(user_prompt)

        if not self._config.deepseek_enabled:
            raise RuntimeError(
                "DeepSeek API key is not configured. Edit config/runtime_config.local.json or set DEEPSEEK_API_KEY."
            )

        last_error = None
        for attempt in range(3):
            try:
                return self._online_review(evidence, system_prompt, user_prompt, prompt_tokens)
            except (error.URLError, error.HTTPError, socket.timeout, TimeoutError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt == 2:
                    break
                time.sleep(2 * (attempt + 1))
        raise RuntimeError("DeepSeek online review failed: {0}".format(last_error))

    def _online_review(
        self,
        evidence: StaticEvidence,
        system_prompt: str,
        user_prompt: str,
        prompt_tokens: int,
    ) -> LLMReview:
        payload = {
            "model": self._config.deepseek_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,
        }
        req = request.Request(
            f"{self._config.deepseek_base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._config.deepseek_api_key}",
            },
            method="POST",
        )

        with request.urlopen(req, timeout=self._config.deepseek_timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))

        message = body["choices"][0]["message"]["content"]
        parsed = _extract_json_object(message)
        usage = body.get("usage", {})
        completion_tokens = int(usage.get("completion_tokens") or estimate_text_tokens(message))
        used_prompt_tokens = int(usage.get("prompt_tokens") or prompt_tokens)
        total_tokens = int(usage.get("total_tokens") or used_prompt_tokens + completion_tokens)

        return LLMReview(
            verdict=bool(parsed["verdict"]),
            confidence=float(parsed.get("confidence", evidence.confidence)),
            reason=str(parsed.get("reason", "")).strip() or "DeepSeek-R1 reviewed the compressed evidence.",
            prompt_tokens=used_prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            model=self._config.deepseek_model,
            mode="deepseek-r1",
        )


def _extract_json_object(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Model response does not contain a JSON object.")
    return json.loads(text[start : end + 1])
