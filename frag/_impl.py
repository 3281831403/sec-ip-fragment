DEFAULT_MAX_BYTES = 4096
DEFAULT_MAX_FRAGMENTS = 64


def parse_fragment(packet) -> dict:
    """把线上分片归一化为重组记录，偏移字段保持 8 字节单位，同时算出字节起点。"""
    offset = int(packet["offset"])
    payload = packet.get("payload", b"") or b""
    start = offset_bytes({"offset": offset})  # 缺陷 1：偏移以 8 字节为单位
    return {
        "id": packet.get("id"),
        "offset": offset,
        "mf": bool(packet.get("mf", False)),
        "payload": payload,
        "length": len(payload),
        "start": start,
        "end": start + len(payload),
        "arrived": float(packet.get("arrived", 0.0)),
    }


def offset_bytes(fragment) -> int:
    # 缺陷 1 修复：IP 分片偏移的单位是 8 字节，必须乘 8，不能直接当字节偏移。
    return int(fragment["offset"]) * 8


def add_fragment(state, fragment, policy) -> dict:
    # 兼容原始 packet 与 parse_fragment 产出的归一化记录。
    if "start" not in fragment:
        fragment = parse_fragment(fragment)

    payload = fragment.get("payload", b"") or b""
    start = int(fragment["start"])
    length = int(fragment.get("length", len(payload)))
    end = int(fragment.get("end", start + length))
    arrived = float(fragment.get("arrived", 0.0))
    record = {
        "id": fragment.get("id"),
        "offset": fragment.get("offset", start // 8),
        "mf": bool(fragment.get("mf", False)),
        "payload": payload,
        "length": length,
        "start": start,
        "end": end,
        "arrived": arrived,
    }

    state.setdefault("id", fragment.get("id"))
    fragments = state.setdefault("fragments", [])
    state.setdefault("last_fragment_seen", False)
    state.setdefault("total_length", None)
    state.setdefault("max_bytes", DEFAULT_MAX_BYTES)
    state.setdefault("max_fragments", DEFAULT_MAX_FRAGMENTS)
    state.setdefault("last_update", arrived)

    # 缺陷 2 修复：做完整的区间相交判定，而不是只比较起始偏移。
    # 半开区间 [start, end)：端点相接（end == next_start）不算重叠。
    for existing in fragments:
        ex_start = int(existing["start"])
        ex_end = int(existing.get("end", ex_start + len(existing.get("payload", b""))))
        if start < ex_end and ex_start < end:
            # 缺陷 3 修复：发现任何重叠都整包丢弃“后到的分片”，
            # 保留先到内容，绝不允许后到分片覆盖已到达字节。
            return state

    # 缺陷 9 修复：内存预算按已缓存载荷的总字节数计算，而不是分片个数。
    used_bytes = sum(len(item.get("payload", b"")) for item in fragments)
    if len(fragments) >= int(state["max_fragments"]):
        return state
    if used_bytes + length > int(state["max_bytes"]):
        return state

    fragments.append(record)

    if not record["mf"]:
        state["last_fragment_seen"] = True
        state["total_length"] = end

    # last_update 只在有新分片正常到达时推进；expire 清理绝不重置它。
    state["last_update"] = max(float(state["last_update"]), arrived)
    return state


def coverage(state) -> list:
    """返回按起点排序、合并所有相交/相邻区间后的覆盖集合 [[start, end], ...]。"""
    intervals = []
    for fragment in state.get("fragments", []):
        start = int(fragment["start"])
        end = int(fragment.get("end", start + len(fragment.get("payload", b""))))
        intervals.append((start, end))
    intervals.sort()

    merged = []
    for start, end in intervals:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            # 缺陷 4 修复：start <= 当前末尾时，相邻与相交都要合并，
            # 并把右端扩展到较大值，避免覆盖集合里残留相交区间。
            if end > merged[-1][1]:
                merged[-1][1] = end
    return merged


def is_complete(state) -> bool:
    # 缺陷 5 修复：不能只看末片（mf=False）是否到达，
    # 还必须让覆盖集合恰好是完整的 [0, total_length]，即中间没有任何缺口。
    if not state.get("last_fragment_seen"):
        return False
    total_length = state.get("total_length")
    if total_length is None:
        return False
    return coverage(state) == [[0, int(total_length)]]


def assemble(state) -> bytes:
    # 缺陷 7 修复：缺片/不完整时必须抛异常，不能返回被截断的载荷。
    if not is_complete(state):
        raise ValueError("incomplete fragment set: missing fragments or terminal fragment")

    total_length = int(state["total_length"])
    # 缺陷 6 修复：严格按字节偏移排序后再拼接，而不是按到达顺序。
    ordered = sorted(state.get("fragments", []), key=lambda item: int(item["start"]))

    buffer = bytearray(total_length)
    for fragment in ordered:
        start = int(fragment["start"])
        payload = fragment.get("payload", b"")
        # 完整性保证覆盖区间恰好铺满 [0, total_length] 且互不重叠。
        buffer[start:start + len(payload)] = payload
    return bytes(buffer)


def expire(state, now, ttl) -> int:
    """清理超过 ttl 仍未完成重组的分片，返回本次移除的分片数。"""
    fragments = state.get("fragments", [])
    kept = []
    removed = 0

    # 缺陷 8 修复：年龄只由原始到达时间决定；清理过程中不回写、
    # 不重置任何到达时间/last_update，否则周期性扫描会让状态永不过期。
    for fragment in fragments:
        arrived = float(fragment.get("arrived", state.get("last_update", now)))
        if now - arrived >= ttl:
            removed += 1
        else:
            kept.append(fragment)

    if removed:
        state["fragments"] = kept
        if not kept:
            state["last_fragment_seen"] = False
            state["total_length"] = None
    return removed


def reassembly_batch(packets, policy, now) -> dict:
    # 缺陷 10 修复：每个标识符使用独立的重组状态（独立缓冲），
    # 不能让第二个 id 的分片落进第一个 id 的同一缓冲。
    states = {}
    insertion_order = []
    for packet in packets:
        fragment = parse_fragment(packet)
        identifier = fragment["id"]
        if identifier not in states:
            states[identifier] = {}
            insertion_order.append(identifier)
        add_fragment(states[identifier], fragment, policy)

    result = {}
    for identifier in insertion_order:
        state = states[identifier]
        if is_complete(state):
            result[identifier] = assemble(state)
    return result
