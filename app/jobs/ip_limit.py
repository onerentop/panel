"""PasarGuard 同时在线 IP 数限制插件。

部署方式：只读挂载到面板容器 ``/code/app/jobs/ip_limit.py``。
面板启动时 ``app/jobs/__init__.py`` 会自动 import 本模块，模块随即：

* 注册一个 5 秒一次的调度任务（真正的处理周期由 settings.interval 决定）；
* 在 on_startup 时挂上 ``/api/ip-limit/*`` 接口，并给 dashboard 的 HTML 注入 UI 脚本。

封禁靠节点的热路由规则（``user + source -> blackhole``），不重启 core。
节点只能把规则追加到末尾，所以每次变更都会把原有规则整体换代
（追加新一代 -> 从后往前删除旧一代），详见 design.md §3。

本文件的纯逻辑部分（decide / plan_ops / inject_html / Store）不依赖面板，
面板相关的 import 全部延迟进行，方便本地单测。
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field

DATA_DIR = os.environ.get("IPLIMIT_DATA_DIR", "/var/lib/pasarguard/ip-limit")
UI_JS_PATH = os.environ.get(
    "IPLIMIT_UI_JS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_limit_assets", "ip_limit_ui.js")
)
API_PREFIX = "/api/ip-limit"

BAN_PREFIX = "iplimit-"
GEN_SEP = "#iplg"
NODE_CALL_TIMEOUT = 8
TICK_SECONDS = 5
EVENTS_KEEP = 500
ONLINE_QUERY_CONCURRENCY = 16

DEFAULT_SETTINGS = {
    "enabled": 1,  # 0 = 完全停用（并清理节点上的封禁规则）
    "dry_run": 1,  # 1 = 只判定和记录，不下发规则（首次上线先观察）
    "interval": 10,  # 处理周期（秒）
    "ban_ttl": 300,  # 封禁时长（秒）
    "offline_grace": 60,  # 多久没再被节点报告就算下线（秒）
}
SETTING_BOUNDS = {
    "enabled": (0, 1),
    "dry_run": (0, 1),
    "interval": (5, 600),
    "ban_ttl": (30, 86400),
    "offline_grace": (20, 3600),
}

logger = logging.getLogger("ip-limit")


# --------------------------------------------------------------------------- #
# 纯逻辑：超限判定
# --------------------------------------------------------------------------- #


@dataclass
class Decision:
    seen: dict  # ip -> [first_seen, last_seen]
    bans: dict  # ip -> expires_at
    events: list = field(default_factory=list)  # (ip, action)


def decide(limit, reported, seen, bans, now, ban_ttl, grace):
    """计算某个用户这一轮的在线集合与封禁集合。

    - reported：本轮各节点报告的在线 IP（已合并去重）
    - seen：上一轮的 {ip: [first_seen, last_seen]}，不含被封的 IP
    - bans：上一轮的 {ip: expires_at}
    规则：按 first_seen 先到先得，前 limit 个保留；其余新增 IP 封禁 ban_ttl 秒。
    被封 IP 不占名额，也不保留 first_seen，解封后按新 IP 重新排队。
    """
    events = []
    bans = dict(bans)
    for ip, exp in list(bans.items()):
        if exp <= now:
            del bans[ip]
            events.append((ip, "unban-expired"))

    new_seen = {ip: list(v) for ip, v in seen.items() if ip not in bans}
    for ip in reported:
        if ip in bans:
            continue
        if ip in new_seen:
            new_seen[ip][1] = now
        else:
            new_seen[ip] = [now, now]
    for ip in [ip for ip, (_, last) in new_seen.items() if now - last > grace]:
        del new_seen[ip]

    if not limit or limit <= 0:
        for ip in bans:
            events.append((ip, "unban-nolimit"))
        return Decision(new_seen, {}, events)

    active = sorted(new_seen, key=lambda ip: (new_seen[ip][0], ip))
    for ip in active[limit:]:
        bans[ip] = now + ban_ttl
        del new_seen[ip]
        events.append((ip, "ban"))
    return Decision(new_seen, bans, events)


# --------------------------------------------------------------------------- #
# 纯逻辑：节点规则收敛
# --------------------------------------------------------------------------- #


def find_block_tag(config):
    for ob in config.get("outbounds", []) or []:
        if ob.get("protocol") == "blackhole" and ob.get("tag"):
            return ob["tag"]
    return ""


def split_tail(config):
    """返回 (tail_rules, block_tag, problems, head_tags)。

    head = routing.rules 开头连续 outboundTag==block_tag 的规则（保持原位，不参与换代）；
    tail = 其余规则，每条必须有唯一的 ruleTag，否则记录在 problems 里，调用方应拒绝下发。
    head_tags = head 里非空的 ruleTag（节点上出现它们是正常的）。
    """
    rules = (config.get("routing") or {}).get("rules") or []
    block_tag = find_block_tag(config)
    i = 0
    while i < len(rules) and block_tag and rules[i].get("outboundTag") == block_tag:
        i += 1
    tail = rules[i:]
    head_tags = [r.get("ruleTag") for r in rules[:i] if r.get("ruleTag")]
    problems = []
    if not block_tag:
        problems.append("core config 没有 blackhole 出站")
    tags = [r.get("ruleTag") for r in tail]
    for idx, t in enumerate(tags):
        if not t:
            problems.append(f"第 {i + idx} 条规则没有 ruleTag")
        elif t.startswith(BAN_PREFIX) or GEN_SEP in t:
            problems.append(f"ruleTag {t!r} 使用了保留前缀")
    named = [t for t in tags if t] + head_tags
    if len(set(named)) != len(named):
        problems.append("ruleTag 有重复")
    return tail, block_tag, problems, head_tags


def ban_hash(ips):
    return hashlib.sha1(",".join(sorted(ips)).encode()).hexdigest()[:8]


def ban_tag(uid, ips, gen):
    return f"{BAN_PREFIX}u{uid}-{ban_hash(ips)}-g{gen}"


_BAN_RE = re.compile(r"^" + re.escape(BAN_PREFIX) + r"u(\d+)-([0-9a-f]{8})-g(\d+)$")


def classify(tag, tail_bases):
    """('B', uid, hash, gen) | ('T', base, gen) | None"""
    m = _BAN_RE.match(tag or "")
    if m:
        return ("B", int(m.group(1)), m.group(2), int(m.group(3)))
    if tag in tail_bases:
        return ("T", tag, 0)
    if tag and GEN_SEP in tag:
        base, _, g = tag.rpartition(GEN_SEP)
        if base in tail_bases and g.isdigit():
            return ("T", base, int(g))
    return None


# pg-node 在规则表最前面自动插入：无 tag 的 API 规则 + 这条守卫规则（pg-node backend/xray/config.go）
NODE_HEAD_TAGS = frozenset({"PG_NODE_MALFORMED_DOMAIN_GUARD"})


@dataclass
class NodePlan:
    ops: list  # [("add", rule_dict) | ("remove", tag)]
    status: str  # ok | unban | cleanup | rotate | repair | skip
    reason: str = ""
    gen: int = 0
    keep_b: list = field(default_factory=list)  # 目标状态里的封禁规则 tag
    keep_t: list = field(default_factory=list)  # 目标状态里的 T 链 tag（按 config 顺序）


def build_ban_rule(uid, ips, gen, block_tag):
    return {
        "type": "field",
        "ruleTag": ban_tag(uid, ips, gen),
        "user": [str(uid)],
        "source": sorted(ips),
        "outboundTag": block_tag,
    }


def build_tail_copy(rule, gen):
    r = dict(rule)
    r["ruleTag"] = rule["ruleTag"] if gen == 0 else f"{rule['ruleTag']}{GEN_SEP}{gen}"
    return r


def chain_intact(tags, keep_b, keep_t):
    """目标链是否完整就位：keep_t 全在且按顺序，keep_b 全在且都排在 keep_t 之前。"""
    pos = {t: i for i, t in enumerate(tags)}
    if any(t not in pos for t in keep_b + keep_t):
        return False
    tp = [pos[t] for t in keep_t]
    if tp != sorted(tp):
        return False
    return not keep_t or all(pos[b] < tp[0] for b in keep_b)


def plan_ops(current_tags, tail, desired, block_tag, head_tags=()):
    """根据节点当前的规则 tag 序列，算出收敛到目标状态需要的操作（纯函数）。

    desired：{uid: [ip, ...]}，空 dict 表示不需要任何封禁。
    目标状态：[节点头部规则..] + B(g) + T(g)，T(g) 完整、唯一、按 config 顺序，
    B(g) 与 desired 一致且全部位于 T(g) 之前。

    路径（按代价从低到高）：
    - skip：节点上有 config 里不认识的规则（config 改了但 core 还没重启），不动它；
    - 先删「完整新一代之前的旧 T」（换代删除阶段中断后的收尾，删掉只会让流量落到等价的新链上）；
    - unban：只需删除多余的封禁规则；
    - rotate：追加 B(g') 和 T(g')，再从后往前删旧 T，最后删旧 B；
    - repair：节点上没有任何完整的一代（例如换代中途 core 重启又被删了一部分），追加一整代后清理。
    """
    bases = [r["ruleTag"] for r in tail]
    base_set = set(bases)
    allowed_head = set(head_tags) | NODE_HEAD_TAGS
    want = {uid: ban_hash(ips) for uid, ips in desired.items() if ips}
    want_ips = {uid: sorted(ips) for uid, ips in desired.items() if ips}

    t_items = []  # (pos, base, gen, tag)
    b_items = []  # (pos, uid, hash, gen, tag)
    first_cls = None
    for pos, tag in enumerate(current_tags):
        c = classify(tag, base_set)
        if c is None:
            if tag.startswith(BAN_PREFIX) or GEN_SEP in tag:
                return NodePlan([], "skip", f"节点上有无法识别的插件规则 {tag!r}")
            if first_cls is not None or (tag and tag not in allowed_head):
                return NodePlan([], "skip", f"节点规则 {tag or '(无 tag)'!r} 不在 core config 里（可能改了配置还没重启），暂不下发")
            continue
        if first_cls is None:
            first_cls = pos
        if c[0] == "T":
            t_items.append((pos, c[1], c[2], tag))
        else:
            b_items.append((pos, c[1], c[2], c[3], tag))

    by_gen = {}
    for pos, base, gen, _ in t_items:
        by_gen.setdefault(gen, []).append(base)
    complete = sorted(g for g, seq in by_gen.items() if seq == bases)  # 完整且顺序正确
    max_gen = max([x[2] for x in t_items] + [x[3] for x in b_items], default=0)

    # remove 操作带上自己的守卫：执行前节点上这条链必须完整就位（chain_intact），否则中止
    def remove_t(items, keep_b, keep_t):
        return [("remove", x[3], keep_b, keep_t) for x in sorted(items, reverse=True)]

    def remove_b(items, keep_b, keep_t):
        return [("remove", x[4], keep_b, keep_t) for x in sorted(items, reverse=True)]

    def full_rotation(status):
        g2 = max_gen + 1
        new_b = [build_ban_rule(uid, want_ips[uid], g2, block_tag) for uid in sorted(want)]
        new_t = [build_tail_copy(r, g2) for r in tail]
        kb, kt = [r["ruleTag"] for r in new_b], [r["ruleTag"] for r in new_t]
        ops = [("add", r) for r in new_b + new_t] + remove_t(t_items, kb, kt) + remove_b(b_items, kb, kt)
        return NodePlan(ops, status, gen=g2, keep_b=kb, keep_t=kt)

    if bases and not complete:
        return full_rotation("repair")

    g = complete[-1] if complete else 0
    t_g = [x for x in t_items if x[2] == g]
    keep_t = [x[3] for x in t_g]
    old_t = [x for x in t_items if x[2] != g]

    # 换代删除阶段中断后：新一代 T 已完整且排在所有旧 T 之后 -> 先删旧 T（只要 T(g) 完整就安全），
    # 再对剩下的状态继续规划
    if old_t and t_g and max(x[0] for x in old_t) < min(x[0] for x in t_g):
        pre = remove_t(old_t, [], keep_t)
        removed = {x[3] for x in old_t}
        sub = plan_ops([t for t in current_tags if t not in removed], tail, desired, block_tag, head_tags)
        return NodePlan(pre + sub.ops, "cleanup" if sub.status == "ok" else sub.status, sub.reason, sub.gen,
                        sub.keep_b, sub.keep_t)

    first_t = min((x[0] for x in t_g), default=len(current_tags))
    good_b = [x for x in b_items if x[3] == g and x[0] < first_t and want.get(x[1]) == x[2]]
    good_uids = [x[1] for x in good_b]
    if len(set(good_uids)) != len(good_uids):  # 同一用户出现两条（不应发生），整体重做
        good_b, good_uids = [], []
    extra_b = [x for x in b_items if x not in good_b]

    if not old_t and set(good_uids) == set(want):
        keep_b = [x[4] for x in good_b]
        if not extra_b:
            return NodePlan([], "ok", gen=g, keep_b=keep_b, keep_t=keep_t)
        return NodePlan(remove_b(extra_b, keep_b, keep_t), "unban", gen=g, keep_b=keep_b, keep_t=keep_t)

    return full_rotation("rotate")




# --------------------------------------------------------------------------- #
# 纯逻辑：HTML 注入
# --------------------------------------------------------------------------- #

UI_SNIPPET = f'<script src="{API_PREFIX}/ui.js"></script>'.encode()


def inject_html(html, snippet=UI_SNIPPET):
    if snippet in html:
        return html
    low = html.lower()
    for marker in (b"<head>", b"</head>", b"</body>"):
        i = low.find(marker)
        if i >= 0:
            if marker == b"<head>":
                i += len(marker)
            return html[:i] + snippet + html[i:]
    return html + snippet


class HtmlInjectASGI:
    """包住 dashboard 的静态文件 Mount：只给 200 的 text/html 响应注入脚本。"""

    def __init__(self, app, snippet=UI_SNIPPET):
        self.app = app
        self.snippet = snippet

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") not in ("GET",):
            return await self.app(scope, receive, send)

        state = {"start": None, "body": [], "inject": False}

        async def _send(msg):
            if msg["type"] == "http.response.start":
                headers = dict((k.lower(), v) for k, v in msg.get("headers", []))
                ctype = headers.get(b"content-type", b"")
                if msg.get("status") == 200 and ctype.startswith(b"text/html") and b"content-encoding" not in headers:
                    state["inject"] = True
                    state["start"] = msg
                    return
                return await send(msg)
            if msg["type"] == "http.response.body" and state["inject"]:
                state["body"].append(msg.get("body", b""))
                if msg.get("more_body"):
                    return
                body = inject_html(b"".join(state["body"]), self.snippet)
                start = state["start"]
                headers = [
                    (k, v) for k, v in start.get("headers", []) if k.lower() not in (b"content-length", b"etag")
                ]
                headers.append((b"content-length", str(len(body)).encode()))
                await send({**start, "headers": headers})
                return await send({"type": "http.response.body", "body": body, "more_body": False})
            return await send(msg)

        return await self.app(scope, receive, _send)


# --------------------------------------------------------------------------- #
# 存储
# --------------------------------------------------------------------------- #


class Store:
    def __init__(self, path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS policy(user_id INTEGER PRIMARY KEY, ip_limit INTEGER NOT NULL,
                    updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS seen(user_id INTEGER, ip TEXT, first_seen REAL, last_seen REAL,
                    PRIMARY KEY(user_id, ip));
                CREATE TABLE IF NOT EXISTS ban(user_id INTEGER, ip TEXT, created_at REAL, expires_at REAL,
                    reason TEXT, PRIMARY KEY(user_id, ip));
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, user_id INTEGER,
                    ip TEXT, action TEXT);
                """
            )

    def _q(self, sql, args=()):
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # settings
    def settings(self):
        s = dict(DEFAULT_SETTINGS)
        for k, v in self._q("SELECT key, value FROM settings"):
            if k in s:
                s[k] = int(v)
        return s

    def set_settings(self, values):
        clean = {}
        for k, v in values.items():
            if k not in DEFAULT_SETTINGS:
                raise ValueError(f"unknown setting {k}")
            v = int(v)
            lo, hi = SETTING_BOUNDS[k]
            if not lo <= v <= hi:
                raise ValueError(f"{k} 必须在 {lo}..{hi} 之间")
            clean[k] = v
        with self._lock:
            for k, v in clean.items():
                self._db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, v))
        return self.settings()

    # policy
    def policies(self):
        return {uid: lim for uid, lim in self._q("SELECT user_id, ip_limit FROM policy")}

    def set_policy(self, uid, limit):
        limit = int(limit)
        if limit < 0 or limit > 1000:
            raise ValueError("ip_limit 必须在 0..1000 之间")
        with self._lock:
            if limit == 0:
                self._db.execute("DELETE FROM policy WHERE user_id=?", (uid,))
            else:
                self._db.execute(
                    "INSERT OR REPLACE INTO policy(user_id, ip_limit, updated_at) VALUES(?, ?, ?)",
                    (uid, limit, time.time()),
                )

    # seen / ban
    def load_user(self, uid):
        seen = {ip: [f, last] for ip, f, last in self._q("SELECT ip, first_seen, last_seen FROM seen WHERE user_id=?", (uid,))}
        bans = {ip: e for ip, e in self._q("SELECT ip, expires_at FROM ban WHERE user_id=?", (uid,))}
        return seen, bans

    def save_user(self, uid, seen, bans, now):
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute("DELETE FROM seen WHERE user_id=?", (uid,))
                self._db.executemany(
                    "INSERT INTO seen(user_id, ip, first_seen, last_seen) VALUES(?, ?, ?, ?)",
                    [(uid, ip, f, last) for ip, (f, last) in seen.items()],
                )
                old = {ip for (ip,) in self._db.execute("SELECT ip FROM ban WHERE user_id=?", (uid,))}
                for ip in old - set(bans):
                    self._db.execute("DELETE FROM ban WHERE user_id=? AND ip=?", (uid, ip))
                for ip, exp in bans.items():
                    if ip in old:
                        self._db.execute("UPDATE ban SET expires_at=? WHERE user_id=? AND ip=?", (exp, uid, ip))
                    else:
                        self._db.execute(
                            "INSERT INTO ban(user_id, ip, created_at, expires_at, reason) VALUES(?, ?, ?, ?, ?)",
                            (uid, ip, now, exp, "limit"),
                        )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def all_bans(self):
        out = {}
        for uid, ip, created, exp in self._q("SELECT user_id, ip, created_at, expires_at FROM ban"):
            out.setdefault(uid, {})[ip] = (created, exp)
        return out

    def all_seen(self):
        out = {}
        for uid, ip, f, last in self._q("SELECT user_id, ip, first_seen, last_seen FROM seen"):
            out.setdefault(uid, {})[ip] = (f, last)
        return out

    def unban(self, uid, ip=None):
        with self._lock:
            if ip is None:
                self._db.execute("DELETE FROM ban WHERE user_id=?", (uid,))
            else:
                self._db.execute("DELETE FROM ban WHERE user_id=? AND ip=?", (uid, ip))

    def clear_bans(self):
        with self._lock:
            self._db.execute("DELETE FROM ban")

    def add_events(self, rows):
        if not rows:
            return
        with self._lock:
            self._db.executemany("INSERT INTO events(ts, user_id, ip, action) VALUES(?, ?, ?, ?)", rows)
            self._db.execute(
                "DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)",
                (EVENTS_KEEP,),
            )

    def events(self, limit=100):
        return self._q("SELECT ts, user_id, ip, action FROM events ORDER BY id DESC LIMIT ?", (limit,))


# --------------------------------------------------------------------------- #
# 运行时（依赖面板）
# --------------------------------------------------------------------------- #


class Runtime:
    def __init__(self, store):
        self.store = store
        self.lock = asyncio.Lock()
        self.last_run = 0.0
        self.force = False
        self.online = {}  # uid -> {ip: [node_id, ...]}
        self.users = {}  # uid -> (username, status)
        self.nodes = {}  # node_id -> {name, status, gen, reason, ts}
        self.last_error = ""
        self.last_tick = 0.0

    # ---- panel 数据 ----
    async def _load_panel(self):
        from sqlalchemy import select

        from app.db import GetDB
        from app.db.models import CoreConfig, Node, User

        async with GetDB() as db:
            users = (await db.execute(select(User.id, User.username, User.status))).all()
            nodes = (await db.execute(select(Node.id, Node.name, Node.core_config_id))).all()
            cfgs = (await db.execute(select(CoreConfig.id, CoreConfig.config))).all()
        self.users = {u.id: (u.username, str(getattr(u.status, "value", u.status))) for u in users}
        cfg_map = {c.id: c.config for c in cfgs}
        return {n.id: (n.name, cfg_map.get(n.core_config_id)) for n in nodes}

    async def _online_ips(self, healthy, uids):
        from PasarGuardNodeBridge import NodeAPIError

        sem = asyncio.Semaphore(ONLINE_QUERY_CONCURRENCY)

        async def one(nid, node, uid):
            async with sem:
                try:
                    r = await asyncio.wait_for(node.get_user_online_ip_list(email=str(uid)), NODE_CALL_TIMEOUT)
                    return nid, uid, dict(r.ips) if r is not None else {}
                except NodeAPIError as e:
                    if getattr(e, "code", None) != 404:
                        logger.debug(f"online ip {uid}@{nid}: {e}")
                except Exception as e:  # noqa: BLE001
                    logger.debug(f"online ip {uid}@{nid}: {e!r}")
                return nid, uid, {}

        res = await asyncio.gather(*[one(nid, node, uid) for nid, node in healthy for uid in uids])
        out = {}
        for nid, uid, ips in res:
            for ip in ips:
                out.setdefault(uid, {}).setdefault(ip, []).append(nid)
        return out

    # ---- 节点规则 ----
    async def _list_tags(self, node):
        resp = await asyncio.wait_for(node.list_routing_rules(), NODE_CALL_TIMEOUT)
        return [r.rule_tag for r in (resp.rules if resp is not None else [])]

    async def _apply_node(self, nid, node, name, config, desired):
        info = {"name": name, "ts": time.time(), "status": "", "reason": "", "gen": 0}
        self.nodes[nid] = info
        try:
            await self._apply_node_inner(nid, node, config, desired, info)
        except Exception as e:  # noqa: BLE001 - 单个节点的意外错误不能影响其他节点
            info.update(status="error", reason=f"内部错误: {e!r}")
            logger.exception(f"node {nid}: apply failed")

    async def _apply_node_inner(self, nid, node, config, desired, info):
        if not config:
            info.update(status="skip", reason="节点没有 core config")
            return
        tail, block_tag, problems, head_tags = split_tail(config)
        if problems:
            info.update(status="error", reason="；".join(problems))
            return
        try:
            tags = await self._list_tags(node)
        except Exception as e:  # noqa: BLE001
            info.update(status="error", reason=f"ListRoutingRules 失败: {e}")
            return
        plan = plan_ops(tags, tail, desired, block_tag, head_tags)
        info.update(status=plan.status, reason=plan.reason, gen=plan.gen)
        if not plan.ops:
            return

        def fail(reason):
            info.update(status="error", reason=reason)
            logger.warning(f"node {nid}: {reason}")

        added = []
        for op in plan.ops:
            kind, arg = op[0], op[1]
            if kind == "add":
                tag = arg["ruleTag"]
                try:
                    await asyncio.wait_for(node.add_routing_rule(json.dumps(arg, ensure_ascii=False)), NODE_CALL_TIMEOUT)
                    added.append(tag)
                except Exception as e:  # noqa: BLE001
                    fail(f"AddRoutingRule({tag}) 失败，回滚本轮已追加的规则: {e}")
                    # 超时的那条可能其实已经加上了，一起尝试删除；新追加的规则都在完整旧链之后，删掉不影响路由
                    for t in reversed(added + [tag]):
                        try:
                            await asyncio.wait_for(node.remove_routing_rule(t), NODE_CALL_TIMEOUT)
                        except Exception as e2:  # noqa: BLE001
                            logger.debug(f"node {nid}: rollback remove {t}: {e2}")
                    return
                continue
            # 删除前重新确认目标链完整就位：换代过程中 core 可能重启（规则表回到 config 原样，
            # 而 gen0 的 tag 与原规则同名），此时继续删会把刚恢复的原规则删掉。
            try:
                cur = await self._list_tags(node)
            except Exception as e:  # noqa: BLE001
                return fail(f"删除前 ListRoutingRules 失败，中止: {e}")
            if not chain_intact(cur, op[2], op[3]):
                return fail("节点规则在换代过程中发生变化（可能 core 重启），中止，下个周期重新规划")
            if arg not in cur:
                return fail(f"要删除的规则 {arg} 已不存在，中止，下个周期重新规划")
            try:
                await asyncio.wait_for(node.remove_routing_rule(arg), NODE_CALL_TIMEOUT)
            except Exception as e:  # noqa: BLE001
                return fail(f"RemoveRoutingRule({arg}) 失败，中止: {e}")
        info["status"] = "ok"
        logger.info(f"node {nid}: {plan.status} -> gen {plan.gen}, {len(plan.ops)} ops")

    # ---- 主循环 ----
    async def tick(self):
        if self.lock.locked():
            return
        async with self.lock:
            s = self.store.settings()
            now = time.time()
            if not self.force and now - self.last_run < s["interval"] - 0.5:
                return
            self.force = False
            self.last_run = now
            try:
                await self._tick(s, now)
                self.last_error = ""
            except Exception as e:  # noqa: BLE001
                self.last_error = repr(e)
                logger.exception("ip-limit tick failed")
            self.last_tick = time.time()

    async def _tick(self, s, now):
        from app.node import node_manager

        node_cfg = await self._load_panel()
        healthy = await node_manager.get_healthy_nodes()
        policies = self.store.policies()
        uids = [uid for uid, (_, st) in self.users.items() if st in ("active", "on_hold")]
        self.online = await self._online_ips(healthy, uids)

        events = []
        if s["enabled"]:
            for uid, limit in policies.items():
                if uid not in self.users:
                    continue
                seen, bans = self.store.load_user(uid)
                d = decide(limit, set(self.online.get(uid, {})), seen, bans, now, s["ban_ttl"], s["offline_grace"])
                self.store.save_user(uid, d.seen, d.bans, now)
                act = "dry-" if s["dry_run"] else ""
                events += [(now, uid, ip, (act + a) if a == "ban" else a) for ip, a in d.events]
            # 已删除的用户：清掉策略（防止 id 复用继承上限）
            for uid in set(policies) - set(self.users):
                self.store.set_policy(uid, 0)
                events.append((now, uid, "*", "user-deleted"))
            # 没有策略（或用户已删除）的残留封禁
            for uid in set(self.store.all_bans()) - (set(policies) & set(self.users)):
                self.store.unban(uid)
                events.append((now, uid, "*", "unban-nolimit"))
        else:
            if self.store.all_bans():
                self.store.clear_bans()
                events.append((now, 0, "*", "unban-disabled"))
        self.store.add_events(events)
        for _, uid, ip, a in events:
            if "ban" in a:
                logger.info(f"user {uid} {ip}: {a}")

        desired = {}
        if s["enabled"] and not s["dry_run"]:
            for uid, ips in self.store.all_bans().items():
                desired[uid] = sorted(ips)

        live = {nid for nid, _ in healthy}
        for nid in list(self.nodes):
            if nid not in live:
                self.nodes[nid].update(status="offline")
        await asyncio.gather(
            *[
                self._apply_node(nid, node, *node_cfg.get(nid, (str(nid), None)), desired)
                for nid, node in healthy
            ],
            return_exceptions=True,
        )

    # ---- 给 UI 的快照 ----
    def snapshot(self):
        s = self.store.settings()
        now = time.time()
        pol = self.store.policies()
        bans = self.store.all_bans()
        seen = self.store.all_seen()
        users = []
        for uid, (username, status) in sorted(self.users.items(), key=lambda x: x[1][0].lower()):
            online = self.online.get(uid, {})
            users.append(
                {
                    "id": uid,
                    "username": username,
                    "status": status,
                    "ip_limit": pol.get(uid, 0),
                    "online": [
                        {
                            "ip": ip,
                            "nodes": sorted(nodes),
                            "first_seen": (seen.get(uid, {}).get(ip) or (None,))[0],
                        }
                        for ip, nodes in sorted(online.items())
                    ],
                    "bans": [
                        {"ip": ip, "created_at": c, "remaining": max(0, int(e - now))}
                        for ip, (c, e) in sorted(bans.get(uid, {}).items())
                    ],
                }
            )
        return {
            "settings": s,
            "users": users,
            "nodes": [{"id": k, **v} for k, v in sorted(self.nodes.items())],
            "events": [
                {"ts": ts, "user_id": uid, "username": self.users.get(uid, ("?",))[0], "ip": ip, "action": a}
                for ts, uid, ip, a in self.store.events(100)
            ],
            "last_tick": self.last_tick,
            "last_error": self.last_error,
            "now": now,
        }


RUNTIME = None


def get_runtime():
    global RUNTIME
    if RUNTIME is None:
        RUNTIME = Runtime(Store(os.path.join(DATA_DIR, "ip_limit.db")))
    return RUNTIME


async def _job():
    await get_runtime().tick()


def build_router():
    from fastapi import APIRouter, Body, Depends, HTTPException
    from fastapi.responses import Response

    from app.routers.authentication import require_scope_all

    router = APIRouter(prefix=API_PREFIX, tags=["IP Limit"])
    can_read = require_scope_all("users", "read")  # 页面列出所有用户的在线 IP，只给能看全部用户的管理员
    can_write = require_scope_all("users", "update")

    @router.get("/state")
    async def ip_limit_state(_=Depends(can_read)):
        return get_runtime().snapshot()

    @router.put("/policy/{user_id}")
    async def ip_limit_set_policy(user_id: int, payload: dict = Body(...), _=Depends(can_write)):
        rt = get_runtime()
        try:
            rt.store.set_policy(user_id, payload.get("ip_limit", 0))
        except (TypeError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        rt.store.add_events([(time.time(), user_id, "*", f"limit={int(payload.get('ip_limit') or 0)}")])
        rt.force = True
        return {"user_id": user_id, "ip_limit": rt.store.policies().get(user_id, 0)}

    @router.delete("/ban/{user_id}")
    async def ip_limit_unban(user_id: int, ip: str | None = None, _=Depends(can_write)):
        rt = get_runtime()
        rt.store.unban(user_id, ip)
        rt.store.add_events([(time.time(), user_id, ip or "*", "unban-manual")])
        rt.force = True
        return {"ok": True}

    @router.put("/settings")
    async def ip_limit_settings(payload: dict = Body(...), _=Depends(can_write)):
        rt = get_runtime()
        try:
            s = rt.store.set_settings(payload)
        except (TypeError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        rt.store.add_events([(time.time(), 0, "*", "settings " + json.dumps(payload, ensure_ascii=False))])
        rt.force = True
        return s

    @router.get("/ui.js")
    async def ip_limit_ui_js():
        try:
            with open(UI_JS_PATH, "rb") as f:
                body = f.read()
        except OSError:
            body = b"console.warn('[ip-limit] ui script missing');"
        return Response(body, media_type="application/javascript", headers={"Cache-Control": "no-cache"})

    return router


def setup(app):
    from starlette.routing import Mount

    from config import dashboard_settings

    app.include_router(build_router())
    path = dashboard_settings.path.rstrip("/")
    wrapped = 0
    for route in app.routes:
        if isinstance(route, Mount) and route.path == path and not isinstance(route.app, HtmlInjectASGI):
            route.app = HtmlInjectASGI(route.app)
            wrapped += 1
    logger.info(f"ip-limit plugin ready (api {API_PREFIX}, dashboard mounts wrapped: {wrapped})")


def _register():
    global logger
    from app import on_startup
    from app.scheduler import scheduler
    from app.utils.logger import get_logger

    logger = get_logger("ip-limit")
    scheduler.add_job(
        _job,
        "interval",
        seconds=TICK_SECONDS,
        coalesce=True,
        max_instances=1,
        id="ip_limit_tick",
        replace_existing=True,
    )
    on_startup(setup)


if __name__.startswith("app.jobs"):
    try:
        _register()
    except Exception:  # noqa: BLE001 - 插件故障不能拖垮面板
        logging.getLogger("ip-limit").exception("ip-limit plugin failed to register")

