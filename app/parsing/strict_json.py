"""Lossless JSON preflight for artifact transformations and advisory assessment."""

import json
import math


def require_unambiguous_json(text):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Ambiguous duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError("Non-JSON number")

    def finite_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("JSON number cannot be represented as a finite value")
        return parsed

    return json.loads(text, object_pairs_hook=unique_pairs, parse_constant=reject_constant, parse_float=finite_float)
