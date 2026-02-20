"""Robust JSON parsing utilities for Gemini CLI output."""

import json
import re
from typing import Any, Tuple

from geminicli.logger import get_logger

logger = get_logger(__name__)


def parse_json_with_fallbacks(text: str, context: str = "") -> Tuple[bool, Any]:
    """Parse JSON with multiple fallback strategies.

    Tries to extract valid JSON from text that may contain surrounding prose,
    markdown code blocks, or other non-JSON content.

    Args:
        text: Text that may contain JSON
        context: Description for logging

    Returns:
        Tuple of (success, parsed_object)
    """
    if not text or not text.strip():
        logger.warning(f"Empty text in {context}")
        return False, None

    # Strategy 1: Direct JSON parse
    try:
        result = json.loads(text.strip())
        return True, result
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract JSON from markdown code blocks
    code_block_patterns = [
        r"```json\s*([\s\S]*?)\s*```",
        r"```\s*([\s\S]*?)\s*```",
    ]
    for pattern in code_block_patterns:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            candidate = match.group(1).strip()
            try:
                result = json.loads(candidate)
                logger.debug(f"Parsed JSON from code block in {context}")
                return True, result
            except json.JSONDecodeError:
                pass

    # Strategy 3: Find the largest JSON object/array in the text
    for start_char, end_char in [('{', '}'), ('[', ']')]:
        start_idx = text.find(start_char)
        if start_idx == -1:
            continue

        # Try progressively from the first occurrence to the last
        depth = 0
        in_string = False
        escape_next = False

        for i in range(start_idx, len(text)):
            char = text[i]

            if escape_next:
                escape_next = False
                continue

            if char == '\\' and in_string:
                escape_next = True
                continue

            if char == '"' and not escape_next:
                in_string = not in_string
                continue

            if in_string:
                continue

            if char == start_char:
                depth += 1
            elif char == end_char:
                depth -= 1
                if depth == 0:
                    candidate = text[start_idx:i + 1]
                    try:
                        result = json.loads(candidate)
                        logger.debug(f"Parsed JSON by bracket matching in {context}")
                        return True, result
                    except json.JSONDecodeError:
                        break

    logger.warning(f"Failed to parse JSON from {context}: {text[:200]}...")
    return False, None
