"""SSE wire conversion using the already authorized request-local Run mapping."""

import json


def run_payload(value, cache):
    if isinstance(value, list):
        return [run_payload(item, cache) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key == "run_id" and type(item) is int:
            identity = cache.get(("analysis_run", item))
            if identity is None:
                raise RuntimeError("Unresolvable streamed public Run identity")
            result[key] = identity
        else:
            result[key] = run_payload(item, cache)
    return result


async def translate_run_stream(iterator, cache):
    # Starlette accepts strings or bytes. Buffer complete SSE frames, including
    # fragmented UTF-8, without changing event names or provider/task identities.
    pending = b""
    async for chunk in iterator:
        pending += chunk.encode() if isinstance(chunk, str) else chunk
        if len(pending) > 1024 * 1024:
            raise RuntimeError("Oversized analysis event")
        while b"\n\n" in pending:
            frame, pending = pending.split(b"\n\n", 1)
            lines = []
            for line in frame.decode("utf-8").split("\n"):
                if line.startswith("data:"):
                    payload = json.loads(line[5:].strip())
                    line = "data: " + json.dumps(run_payload(payload, cache), separators=(",", ":"))
                lines.append(line)
            yield ("\n".join(lines) + "\n\n").encode()
    if pending.strip():
        raise RuntimeError("Incomplete analysis event")
