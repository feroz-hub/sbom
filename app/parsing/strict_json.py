"""Lossless JSON preflight for artifact transformations and advisory assessment."""

import json


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

    return json.loads(text, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
