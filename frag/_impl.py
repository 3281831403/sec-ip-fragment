def parse_fragment(packet) -> dict:
    raise NotImplementedError()

def offset_bytes(fragment) -> int:
    raise NotImplementedError()

def add_fragment(state, fragment, policy) -> dict:
    raise NotImplementedError()

def coverage(state) -> list:
    raise NotImplementedError()

def is_complete(state) -> bool:
    raise NotImplementedError()

def assemble(state) -> bytes:
    raise NotImplementedError()

def expire(state, now, ttl) -> int:
    raise NotImplementedError()

def reassembly_batch(packets, policy, now) -> dict:
    raise NotImplementedError()
