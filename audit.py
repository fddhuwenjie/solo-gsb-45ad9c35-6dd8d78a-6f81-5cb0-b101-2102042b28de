"""信号命名一致性审计。

在**不改动任何路由结论**的前提下，复用 ``solver.plan_all`` 得到规划完成后的
物理连通关系（设备内部通路 + 生效常态连接 + 已安装跳线），把用户在设备端口、
插孔对、已规划跳线与路由上填写的**规范信号名**与**别名**沿这些连接传播，
按半常态分流语义归并端点（半常态上插孔插线时常态保持、信号并送，因此
上/下端口仍属同一连通分量，并额外构成一个需要命名的“分流点”），检测四类问题：

  mutex       同一物理连通分量上出现互斥的规范信号名；
  alias-ring  别名指向成环（含同一别名被指向多个不同规范名的分叉声明）；
  unlabeled   承载路由信号的跳线 / 半常态分流点没有任何标签（无标签断点）；
  crosstalk   来自**独立信号源**的已规划路由在同一连通分量汇合（跨路由串线）。

每个问题都给出：

  - 两个命名端点（串线为两组独立源端口）之间的**最短证据路径**
    （多源 BFS，沿无向物理图）；
  - 可采纳的规范名（分量内声明次数最多、并列时取字典序最小者）；
  - 一组**修正预览**（把落败名降级为别名的 rename / 补标签的 add-label），
    仅供前端预览与回填，审计本身不修改路由，也不回写任何配置。

跨路由串线**与名签完全解耦**：判定只依据路由规划与物理连通——
每条已规划路由的信号源即其源端口；同一源端口的路由天然同源；源端口在
有向信号流图（设备内部 in→out、生效常态 上→下、跳线 from→to）上同属一个
强连通分量的合并为一个独立源；能被其他源沿信号方向到达的源（如调音台
混合输出）不是独立源，其路由按上游独立源归属。同一无向物理分量内出现
两个互不衍生的独立源即报串线（覆盖设备内部混合与半常态并送汇合），
**不提供可消警的改名操作**，只有调整路由规划或物理连通才能消除。
"""

from collections import defaultdict, deque

from solver import MODE_LABELS, THROUGH, ConfigError, plan_all

MUTEX = "mutex"
ALIAS_RING = "alias-ring"
UNLABELED = "unlabeled"
CROSSTALK = "crosstalk"

TYPE_TITLES = {
    MUTEX: "互斥名称",
    ALIAS_RING: "别名环",
    UNLABELED: "无标签断点",
    CROSSTALK: "跨路由串线",
}
ISSUE_LIMIT = 24                       # 单类问题最多返回条数，避免极端配置刷屏


class SignalAuditError(ConfigError):
    """命名/标签配置非法。"""

    def __init__(self, message, details=None):
        super().__init__(message, code="LABELS_INVALID", details=details or {})


# ---- 标签解析 -------------------------------------------------------------


def _text(v):
    if v is None:
        return None
    if not isinstance(v, str):
        raise SignalAuditError("规范名与别名必须是字符串")
    t = v.strip()
    return t or None


def _origin_label(kind, key, port=None):
    if kind == "port":
        return f"端口 {port}"
    if kind == "pair":
        return f"插孔对第 {key} 对"
    if kind == "cable":
        return f"跳线 #{key}"
    return f"路由 {key + 1}"


def parse_labels(raw, plan):
    """校验 labels，返回 (decls, rows)。

    decls:  [{node, name(原始), alias(原始), origin(key 元组), originAlias}]
    rows:   {origin key: {"name":..., "alias":...}}（同一 origin 只允许一行）
    一条 pair/cable/route 行的名签会同时挂到其两端端口；route 行的名签
    只参与别名图解析与规范名计数（不参与静态互斥归并，也不再作为
    跨路由串线的判定依据——串线只追溯独立信号源与路由归属）。
    """
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SignalAuditError("labels 必须是 JSON 对象，如 {\"ports\": [...]}")

    solver = plan["solver"]
    devices = plan["devices"]
    pairs = plan["pairs"]
    routes = plan["routes"]
    valid_ports = set()
    for name, d in devices.items():
        for p in d["inputs"] + d["outputs"]:
            valid_ports.add(f"{name}.{p}")
    pair_by_id = {p["id"]: p for p in pairs}
    cable_by_id = {c["id"]: c for c in solver.cables}

    def take(row, ctx):
        if not isinstance(row, dict):
            raise SignalAuditError(f"{ctx}：标签项必须是 JSON 对象")
        name, alias = _text(row.get("name")), _text(row.get("alias"))
        if not name and not alias:
            return None, None
        return name, alias

    decls, rows = [], {}

    def register(kind, key, nodes, name, alias, port=None):
        origin = (kind, key)
        if origin in rows:
            raise SignalAuditError(f"{_origin_label(kind, key, port)} 重复填写标签")
        rows[origin] = {"name": name, "alias": alias}
        for node in nodes:
            decls.append({"node": node, "name": name, "alias": alias,
                          "origin": origin, "originAlias": alias})

    for i, row in enumerate(raw.get("ports") or []):
        name, alias = take(row, f"ports[{i}]")
        if not name and not alias:
            continue
        port = _text(row.get("port"))
        if not port:
            raise SignalAuditError(f"ports[{i}]：缺少 port（设备.端口）")
        if port not in valid_ports:
            raise SignalAuditError(f"ports[{i}]：未知端口 “{port}”")
        register("port", port, [port], name, alias, port=port)

    for i, row in enumerate(raw.get("pairs") or []):
        name, alias = take(row, f"pairs[{i}]")
        if not name and not alias:
            continue
        try:
            pid = int(row.get("id"))
        except (TypeError, ValueError):
            raise SignalAuditError(f"pairs[{i}]：id 必须是插孔对编号整数")
        pair = pair_by_id.get(pid)
        if pair is None:
            raise SignalAuditError(f"pairs[{i}]：插孔对 {pid} 不存在")
        nodes = [f"{pair['top']['device']}.{pair['top']['port']}"] if pair["top"] else []
        if pair["bottom"]:
            nodes.append(f"{pair['bottom']['device']}.{pair['bottom']['port']}")
        register("pair", pid, nodes, name, alias)

    for i, row in enumerate(raw.get("cables") or []):
        name, alias = take(row, f"cables[{i}]")
        if not name and not alias:
            continue
        try:
            cid = int(row.get("id"))
        except (TypeError, ValueError):
            raise SignalAuditError(f"cables[{i}]：id 必须是跳线编号整数")
        cable = cable_by_id.get(cid)
        if cable is None:
            raise SignalAuditError(
                f"cables[{i}]：跳线 #{cid} 不在当前规划的已安装跳线中")
        register("cable", cid, [cable["fromPort"], cable["toPort"]], name, alias)

    for i, row in enumerate(raw.get("routes") or []):
        name, alias = take(row, f"routes[{i}]")
        if not name and not alias:
            continue
        try:
            ridx = int(row.get("index"))
        except (TypeError, ValueError):
            raise SignalAuditError(f"routes[{i}]：index 必须是路由序号整数（从 0 起）")
        if not 0 <= ridx < len(routes):
            raise SignalAuditError(f"routes[{i}]：路由序号 {ridx} 超出范围")
        r = routes[ridx]
        nodes = [f"{r['source']['device']}.{r['source']['port']}",
                 f"{r['target']['device']}.{r['target']['port']}"]
        register("route", ridx, nodes, name, alias)

    return decls, rows


# ---- 别名图：规范名解析与别名环 ------------------------------------------


def build_alias_graph(decls):
    """构造 别名→规范名 有向图（同名忽略）。

    返回 graph: {alias: {canonical: [origin, ...]}}（记录每条声明的来源）。
    """
    graph = defaultdict(lambda: defaultdict(list))
    for d in decls:
        if d["name"] and d["alias"] and d["alias"] != d["name"]:
            graph[d["alias"]][d["name"]].append(d)
    return graph


def _tarjan_scc(nodes, succ):
    """迭代 Tarjan，返回 SCC 列表（每个 SCC 为节点集合）。"""
    index_of, low, stack, onstack = {}, {}, [], set()
    counter = [0]
    sccs = []

    for root in list(nodes):
        if root in index_of:
            continue
        work = [(root, iter(succ.get(root, ())))]
        index_of[root] = low[root] = counter[0]
        counter[0] += 1
        stack.append(root)
        onstack.add(root)
        while work:
            u, it = work[-1]
            advanced = False
            for v in it:
                if v not in index_of:
                    index_of[v] = low[v] = counter[0]
                    counter[0] += 1
                    stack.append(v)
                    onstack.add(v)
                    work.append((v, iter(succ.get(v, ()))))
                    advanced = True
                    break
                if v in onstack:
                    low[u] = min(low[u], index_of[v])
            if advanced:
                continue
            work.pop()
            if work:
                p = work[-1][0]
                low[p] = min(low[p], low[u])
            if low[u] == index_of[u]:
                comp = set()
                while True:
                    w = stack.pop()
                    onstack.discard(w)
                    comp.add(w)
                    if w == u:
                        break
                sccs.append(comp)
    return sccs


def _cycle_in(comp, succ):
    """在一个成环 SCC 中取出一条有向简单环（含自环）。"""
    comp = set(comp)
    for s in comp:
        if s in succ.get(s, ()):
            return [s, s]
    color, parent = {}, {}
    for root in sorted(comp):
        if color.get(root, 0) != 0:
            continue
        color[root] = 1
        stack = [(root, iter(sorted(succ.get(root, ()))))]
        while stack:
            u, it = stack[-1]
            advanced = False
            for v in it:
                if v not in comp or color.get(v, 0) == 2:
                    continue
                if color.get(v, 0) == 1:              # 回到在栈祖先 → 回边
                    cyc, x = [u], u
                    while x != v:
                        x = parent[x]
                        cyc.append(x)
                    cyc.reverse()
                    cyc.append(v)
                    return cyc
                color[v], parent[v] = 1, u
                stack.append((v, iter(sorted(succ.get(v, ())))))
                advanced = True
                break
            if not advanced:
                color[u] = 2
                stack.pop()
    first = min(comp)
    return sorted(comp) + [first]


class NameResolver:
    """把任意名签（规范名或别名）解析为稳定的“代表规范名”。

    - 别名环：环内取“被显式声明为规范名次数最多、并列字典序最小”的成员；
    - 其余名字沿唯一出边收敛到终点；分叉时各终点分别可达。
    """

    def __init__(self, graph, decls):
        self.graph = graph
        succ = {a: set(t) for a, t in graph.items()}
        self.succ = succ
        name_votes = defaultdict(int)
        for d in decls:
            if d["name"]:
                name_votes[d["name"]] += 1
        self.name_votes = name_votes

        self.ring_rep = {}
        self.ring_members = set()
        nodes = set(succ) | {v for ts in succ.values() for v in ts}
        for comp in _tarjan_scc(nodes, succ):
            cyclic = len(comp) > 1 or any(u in succ.get(u, ()) for u in comp)
            if cyclic:
                rep = min(comp, key=lambda n: (-name_votes.get(n, 0), n))
                for n in comp:
                    self.ring_rep[n] = rep
                    self.ring_members.add(n)
        self._cache = {}

    def _resolve(self, name):
        if name in self.ring_rep:
            return self.ring_rep[name]
        seen = set()
        u = name
        while u in self.succ and u not in self.ring_members:
            if u in seen:                      # 理论上不会（非环节点无环）
                return u
            seen.add(u)
            targets = self.succ[u]
            if not targets:
                return u
            u = sorted(targets)[0]            # 分叉时取稳定值；分叉另有问题上报
        return self.ring_rep.get(u, u)

    def resolve(self, name):
        if name is None:
            return None
        if name not in self._cache:
            self._cache[name] = self._resolve(name)
        return self._cache[name]

    def canonicals_of_alias(self, alias):
        """别名沿有向边可达的全部代表规范名（供纯别名端点名采用）。"""
        out = set()
        stack = [alias]
        seen = set()
        while stack:
            u = stack.pop()
            if u in seen:
                continue
            seen.add(u)
            targets = self.succ.get(u)
            if not targets:
                out.add(self.resolve(u))
            else:
                stack.extend(targets)
        return out


# ---- 物理图（无向，规划完成后） -------------------------------------------


def build_physical_graph(plan):
    """设备内部 + 生效常态 + 已安装跳线的无向图。

    返回 adj: {port: [(neighbor, edge), ...]}；edge 为序列化友好的描述。
    """
    solver = plan["solver"]
    pairs = plan["pairs"]
    adj = defaultdict(list)

    def link(a, b, edge):
        adj[a].append((b, edge))
        adj[b].append((a, edge))

    for name, d in plan["devices"].items():
        for i in d["inputs"]:
            for o in d["outputs"]:
                link(f"{name}.{i}", f"{name}.{o}",
                     {"type": "device", "label": f"{name} 内部", "device": name})
    for p in pairs:
        if solver.normal_active(p) and p["top"] and p["bottom"]:
            a = f"{p['top']['device']}.{p['top']['port']}"
            b = f"{p['bottom']['device']}.{p['bottom']['port']}"
            link(a, b, {"type": "normal", "pairId": p["id"],
                        "label": f"{MODE_LABELS[p['mode']]} · 第{p['id']}对"})
    for c in solver.cables:
        link(c["fromPort"], c["toPort"],
             {"type": "cable", "cableId": c["id"], "label": f"跳线 #{c['id']}"})

    # 确保孤立端口也是图节点
    for port in solver.port_dir:
        adj.setdefault(port, [])
    return adj


def build_signal_digraph(plan):
    """有向信号流图：设备内部 in→out、生效常态 上→下、跳线 from→to。

    与 solver.detect_loops 使用同一组有向边，用于追溯路由信号源：
    源端口若能沿信号方向到达另一源端口，后者就不是独立信号源。
    返回 succ: {port: {port, ...}}（含全部端口节点）。
    """
    solver = plan["solver"]
    succ = defaultdict(set)
    for name, d in plan["devices"].items():
        for i in d["inputs"]:
            for o in d["outputs"]:
                succ[f"{name}.{i}"].add(f"{name}.{o}")
    for p in plan["pairs"]:
        if solver.normal_active(p) and p["top"] and p["bottom"]:
            succ[f"{p['top']['device']}.{p['top']['port']}"].add(
                f"{p['bottom']['device']}.{p['bottom']['port']}")
    for c in solver.cables:
        succ[c["fromPort"]].add(c["toPort"])
    for port in solver.port_dir:
        succ.setdefault(port, set())
    return succ


def _union_find(nodes):
    parent = {n: n for n in nodes}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    return find, union


def shortest_path(adj, starts, goals):
    """多源 BFS：starts 中任一端点到 goals 中任一端点的最短无向路径。

    返回端口列表（长度 ≥1）。相邻端口之间的边由调用方经 BFS 前驱重建。
    """
    starts, goals = set(starts), set(goals)
    common = starts & goals
    if common:
        return [next(iter(common))], {}
    prev = {s: (None, None) for s in starts}
    q = deque(starts)
    hit = None
    while q and hit is None:
        u = q.popleft()
        for v, edge in adj.get(u, ()):
            if v in prev:
                continue
            prev[v] = (u, edge)
            if v in goals:
                hit = v
                break
            q.append(v)
    if hit is None:
        return None, prev
    nodes = []
    x = hit
    while x is not None:
        nodes.append(x)
        x, _ = prev[x]
    nodes.reverse()
    return nodes, prev


def edge_between(adj, a, b):
    for v, edge in adj.get(a, ()):
        if v == b:
            return edge
    return None


# ---- 证据序列化 -----------------------------------------------------------


def evidence_items(nodes, adj, plan, node_names):
    """端口序列 → 前端可渲染的 port/edge 交替列表。"""
    solver = plan["solver"]
    items = []
    for i, node in enumerate(nodes):
        items.append({
            "kind": "port", "port": node,
            "jack": solver.port_jack.get(node),
            "names": sorted(node_names.get(node, ())),
        })
        if i + 1 < len(nodes):
            edge = edge_between(adj, node, nodes[i + 1])
            items.append({"kind": "edge", **(edge or {
                "type": "link", "label": "连通"})})
    return items


# ---- 主审计 ---------------------------------------------------------------


def audit_signals(config, labels_raw):
    """对当前规划做信号命名一致性审计，返回结构化报告（不修改任何路由）。"""
    result, plan = plan_all(config)
    solver = plan["solver"]
    pairs = plan["pairs"]

    decls, rows = parse_labels(labels_raw or {}, plan)
    graph = build_alias_graph(decls)
    resolver = NameResolver(graph, decls)
    adj = build_physical_graph(plan)

    ports = list(solver.port_dir)
    find, union = _union_find(ports)
    for u, nbrs in adj.items():
        for v, _ in nbrs:
            if u < v:                       # 每条无向边合并一次
                union(u, v)

    # 路由实际经过的端口 / 常态 / 跳线
    used_normals, used_cables = set(), set()
    routed_ports = set()
    for info in plan["planned"]:
        if not info["ok"]:
            continue
        used_normals |= info["normals"]
        used_cables |= set(info["cableIds"])
        for kind, payload in info["items"]:
            if kind == "port":
                routed_ports.add(payload)
    active_component = {find(p) for p in routed_ports}

    # ---- 名签按端口聚合（仅静态标签；路由行名签只参与别名图与计数） ----
    static_at = defaultdict(list)          # node -> [{canonical, raw, origin}]
    static_labeled = set()                 # 任何静态名签（含纯别名）所在端口
    labeled_nodes = set()
    for d in decls:
        labeled_nodes.add(d["node"])
        if d["origin"][0] != "route":
            if d["name"] or d["alias"]:
                static_labeled.add(d["node"])
        if d["name"] and d["origin"][0] != "route":
            static_at[d["node"]].append({
                "canonical": resolver.resolve(d["name"]),
                "raw": d["name"], "origin": d["origin"],
                "originAlias": d["originAlias"],
            })

    # 每端口所有静态别名沿别名图收敛到的规范名（补全传播）
    alias_resolve_at = defaultdict(set)
    for d in decls:
        if d["origin"][0] == "route" or not d["alias"]:
            continue
        for canon in resolver.canonicals_of_alias(d["alias"]):
            alias_resolve_at[d["node"]].add(canon)

    components = defaultdict(lambda: {"ports": [], "names": defaultdict(list)})
    for p in ports:
        r = find(p)
        components[r]["ports"].append(p)
        for nd in static_at.get(p, ()):
            components[r]["names"][nd["canonical"]].append((p, nd))
        # 纯别名端口（无显式规范名）：别名唯一收敛到某规范名时按该名补全传播；
        # 显式规范名与别名收敛目标不一致属于别名环/分叉类问题，这里不做隐式合并。
        declared = {nd["canonical"] for nd in static_at.get(p, ())}
        if not declared:
            for canon in alias_resolve_at.get(p, ()):
                components[r]["names"][canon]

    issues = []

    def origin_payload(origin):
        kind, key = origin
        return {"kind": kind,
                "port": key if kind == "port" else None,
                "id": key if kind in ("pair", "cable") else None,
                "index": key if kind == "route" else None,
                "label": _origin_label(kind, key, port=key if kind == "port" else None)}

    # ---- 1) 互斥名称：同一物理分量出现多个静态规范名（每分量一条） --------
    for root, comp in components.items():
        names = [n for n, entries in comp["names"].items() if entries]
        if len(names) <= 1:
            continue
        votes = {n: sum(1 for _ in entries)
                 for n, entries in comp["names"].items() if entries}
        preferred = min(names, key=lambda n: (-votes[n], n))
        losers = [n for n in names if n != preferred]

        # 全局最短证据：preferred 名签端口 → 任一落败名签端口
        starts = [p for p, _ in comp["names"][preferred]]
        goals = [p for n in losers for p, _ in comp["names"][n]]
        nodes, _ = shortest_path(adj, starts, goals)
        loser_set = set(losers)
        issues.append({
            "type": MUTEX, "severity": "error",
            "title": TYPE_TITLES[MUTEX],
            "message": f"同一连通分量上出现 {len(names)} 个互斥的规范信号名："
                       f"{('、'.join(f'“{n}”×{votes[n]}' for n in names))}；"
                       f"物理连通意味着这些端点等电位，只能保留一个规范名。"
                       f"建议采纳声明次数最多的 “{preferred}”，其余降级为别名。",
            "component": root,
            "names": sorted(names), "conflictingNames": sorted(loser_set),
            "preferredName": preferred,
            "suggestedName": preferred,
            "evidence": evidence_items(nodes or starts[:1], adj, plan,
                                       _node_label_map(decls)),
            "fixes": _rename_fixes(comp["names"], preferred, loser_set, rows),
        })

    # ---- 2) 别名环（含别名分叉到多个规范名） -----------------------------
    issues += _alias_issues(graph, resolver, decls, adj, plan, rows)

    # ---- 3) 无标签断点：承载路由信号的跳线 / 半常态分流点 ----------------
    component_canonicals = {}
    for root, comp in components.items():
        present = {n for n, e in comp["names"].items() if e}
        component_canonicals[root] = present

    def suggested_for(root):
        present = component_canonicals.get(root, set())
        if len(present) == 1:
            return next(iter(present))
        return None

    # 3a. 已被路由使用、但信号流入端没有任何名签的跳线（无标签断点）。
    # 注：不要求跳线两端都命名——很多跳线的作用就是把已命名信号送入一个
    # 未命名输入（半常态并送/监听），只要“从哪根线流进来”可追踪即可。
    for cid in sorted(used_cables):
        cable = next(c for c in solver.cables if c["id"] == cid)
        a, b = cable["fromPort"], cable["toPort"]
        if ("cable", cid) in rows or a in static_labeled:
            continue
        nodes, _ = shortest_path(adj, [a], [b])
        root = find(a)
        suggested = suggested_for(root)
        issues.append({
            "type": UNLABELED, "severity": "warning",
            "title": TYPE_TITLES[UNLABELED],
            "message": f"跳线 #{cid}（{a} ↔ {b}）承载路由信号，但其自身与源端端口"
                       f"都没有规范名/别名，信号经跳线后无法继续追踪（无标签断点）。"
                       + (f" 分量内已有规范名 “{suggested}”，建议沿用。"
                          if suggested else " 分量内存在多个或零个规范名，需人工命名。"),
            "component": root, "names": sorted(component_canonicals.get(root, set())),
            "suggestedName": suggested,
            "evidence": evidence_items(nodes or [a, b], adj, plan, _node_label_map(decls)),
            "fixes": [{
                "action": "add-label", "target": origin_payload(("cable", cid)),
                "targetLabel": _origin_label("cable", cid),
                "name": suggested,
                "label": f"为跳线 #{cid} 补填规范名"
                         + (f" “{suggested}”" if suggested else "（需人工指定）"),
            }],
        })

    # 3b. 半常态分流点：上插孔插线 → 常态保持并送（且被路由使用）。
    # 只要源端口/插孔对/该跳线三者都无名签，分流出去的信号就无从命名。
    for p in sorted((x for x in pairs if x["mode"] not in (THROUGH,)),
                    key=lambda x: x["id"]):
        t_jack, b_jack = f"{p['id']}T", f"{p['id']}B"
        if not solver.normal_active(p) or t_jack not in solver.plugs:
            continue
        cid_at_t = solver.plugs[t_jack]
        if p["id"] not in used_normals and cid_at_t not in used_cables:
            continue
        t_port = f"{p['top']['device']}.{p['top']['port']}" if p["top"] else None
        b_port = (f"{p['bottom']['device']}.{p['bottom']['port']}"
                  if p["bottom"] else None)
        if ("pair", p["id"]) in rows \
                or ("cable", cid_at_t) in rows \
                or (t_port and t_port in static_labeled):
            continue
        starts = [t_port] if t_port else []
        goals = [b_port] if b_port else []
        nodes, _ = shortest_path(adj, starts, goals) if starts and goals else (None, {})
        root = find(t_port) if t_port else find(b_port)
        suggested = suggested_for(root)
        issues.append({
            "type": UNLABELED, "severity": "warning",
            "title": TYPE_TITLES[UNLABELED],
            "message": f"第 {p['id']} 对半常态插孔在上插孔 {t_jack} 插有跳线 "
                       f"#{cid_at_t}，常态保持、信号并送（分流/监听点），路由同时使用"
                       f"并送支路，但源端口、该插孔对与跳线都没有名签，分流出去的信号"
                       f"无法命名追踪（无标签断点）。"
                       + (f" 建议沿用分量内规范名 “{suggested}”。"
                          if suggested else " 分量内规范名不唯一，需先消歧再命名。"),
            "component": root, "names": sorted(component_canonicals.get(root, set())),
            "suggestedName": suggested,
            "evidence": evidence_items(nodes or [x for x in (t_port, b_port) if x],
                                       adj, plan, _node_label_map(decls)),
            "fixes": [{
                "action": "add-label", "target": origin_payload(("pair", p["id"])),
                "targetLabel": _origin_label("pair", p["id"]),
                "name": suggested,
                "label": f"为第 {p['id']} 对半常态分流点补填规范名"
                         + (f" “{suggested}”" if suggested else "（需人工指定）"),
            }],
        })

    # ---- 4) 跨路由串线：独立信号源的已规划路由汇于同一物理分量 ----------
    # 判定与名签（规范名/别名）完全解耦，只追溯信号源与路由归属：
    #  - 同一源端口的多条路由天然同源；
    #  - 源端口在有向信号流图上同属一个强连通分量（如反馈环两端）合并为
    #    一个独立源；
    #  - 能被其他源沿信号方向到达的源（如调音台的混合输出）不是独立源，
    #    其路由按可到达它的上游独立源归属；
    #  - 同一无向物理分量内出现两个互不衍生的独立源 → 跨路由串线
    #    （设备内部混合、半常态并送汇合均覆盖）。改名/改别名不会改变归属，
    #    只有调整路由规划或物理连通才能消除，因此不提供任何 rename 修正。
    dsucc = build_signal_digraph(plan)
    planned_routes = [(info["index"], info["source"])
                      for info in plan["planned"] if info["ok"]]
    source_ports = {src for _, src in planned_routes}

    sccs = _tarjan_scc(dsucc.keys(), dsucc)
    scc_of = {p: i for i, comp in enumerate(sccs) for p in comp}
    comp_succ = [set() for _ in sccs]
    for u, outs in dsucc.items():
        for v in outs:
            if scc_of[u] != scc_of[v]:
                comp_succ[scc_of[u]].add(scc_of[v])
    source_sccs = {scc_of[p] for p in source_ports}

    def reachable_components(start):
        """有向缩点图上从 start 可达的全部分量（可经非源分量中转）。"""
        seen = {start}
        q = deque([start])
        while q:
            u = q.popleft()
            for v in comp_succ[u]:
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        return seen

    # 源 SCC → 沿信号方向可达（含自身）的全部源 SCC
    reachable_sources = {s: (reachable_components(s) & source_sccs)
                         for s in source_sccs}
    # 独立源（根源 SCC）：没有任何其他源 SCC 能沿信号方向到达它
    root_sccs = {s for s in source_sccs
                 if not any(t != s and s in reachable_sources[t]
                            for t in source_sccs)}
    # 每个源 SCC 归属的独立源集合（自身为根时包含自身；混合点可归属多个）
    owners_of = {s: {t for t in root_sccs if s in reachable_sources[t]}
                 for s in source_sccs}

    routes_from = defaultdict(list)          # 源端口 → 从该端口出发的路由
    for idx, src in planned_routes:
        routes_from[src].append(idx)

    def group_payload(cid):
        ports = sorted(p for p in source_ports if scc_of[p] == cid)
        return {"port": ports[0], "ports": ports,
                "routes": sorted(i for p in ports for i in routes_from[p])}

    # 独立源按其源端口所在的无向物理分量归组（有向可达必在同一无向分量内）
    roots_by_comp = defaultdict(set)
    for cid in root_sccs:
        roots_by_comp[find(group_payload(cid)["port"])].add(cid)

    def desc_group(g):
        rts = "、".join(str(i + 1) for i in g["routes"])
        ports = "、".join(g["ports"])
        return f"源端口 {ports} 的路由 {rts}" if rts else f"源端口 {ports}"

    for uroot, gset in roots_by_comp.items():
        groups = sorted((group_payload(cid) for cid in gset),
                        key=lambda g: g["port"])
        for ai in range(len(groups)):
            for bi in range(ai + 1, len(groups)):
                ga, gb = groups[ai], groups[bi]
                # 证据：两组独立源端口之间的最短无向物理路径（改名不会改变）
                nodes, _ = shortest_path(adj, ga["ports"], gb["ports"])
                if nodes is None:
                    continue
                # 下游混合点：非独立源 SCC 同时由这两个独立源衍生
                # （典型：两路信号进同一台设备，其混合输出再带出一条路由）
                downstream = []
                for s in source_sccs - root_sccs:
                    own = owners_of[s]
                    if scc_of[ga["port"]] in own and scc_of[gb["port"]] in own:
                        g = group_payload(s)
                        if g["routes"]:
                            downstream.append(g)
                downstream.sort(key=lambda g: g["port"])
                rts_all = sorted(set(ga["routes"] + gb["routes"]
                                     + [i for g in downstream for i in g["routes"]]))
                tail = ""
                if downstream:
                    tail = ("；下游混合点 " + "、".join(
                        f"源端口 {g['ports'][0]}（路由 "
                        f"{'、'.join(str(i + 1) for i in g['routes'])}）"
                        for g in downstream)
                        + " 的信号由上述独立源并流而成，这些路由同时归属两个独立源")
                issues.append({
                    "type": CROSSTALK, "severity": "error",
                    "title": TYPE_TITLES[CROSSTALK],
                    "message": f"独立信号源「{desc_group(ga)}」与「{desc_group(gb)}」"
                               f"的已规划路由在同一物理连通分量汇合，两个互不衍生的"
                               f"独立信号在该分量内等电位（覆盖设备内部混合与半常态"
                               f"并送汇合），发生跨路由串线。改名或改别名不会改变"
                               f"信号源归属，无法消除本报警{tail}。只能调整路由规划"
                               f"（取消或改道相关路由）或断开它们之间的物理连通"
                               f"（拔除跳线 / 改变常态模式 / 修改背板接线）后重新规划。",
                    "resolution": "调整路由规划或断开独立源之间的物理连通后重新规划；"
                                  "重命名规范名 / 别名不能消除串线。",
                    "component": uroot,
                    # names 沿用数组结构供排序使用，内容为与标签无关的源端口
                    "names": sorted(ga["ports"] + gb["ports"]),
                    "sources": [{"port": ga["port"], "ports": ga["ports"],
                                 "routes": ga["routes"]},
                                {"port": gb["port"], "ports": gb["ports"],
                                 "routes": gb["routes"]}],
                    "routes": rts_all,
                    "routesBySource": {ga["port"]: ga["routes"],
                                       gb["port"]: gb["routes"]},
                    "downstream": [{"port": g["ports"][0], "ports": g["ports"],
                                    "routes": g["routes"]} for g in downstream],
                    "evidence": evidence_items(nodes, adj, plan,
                                               _node_label_map(decls)),
                    "fixes": [],
                })

    # ---- 排序与编号 ------------------------------------------------------
    order = {MUTEX: 0, CROSSTALK: 1, ALIAS_RING: 2, UNLABELED: 3}
    issues.sort(key=lambda x: (0 if x["severity"] == "error" else 1,
                               order[x["type"]], x["type"],
                               min(x.get("names") or [""])))
    total_counts = {MUTEX: 0, ALIAS_RING: 0, UNLABELED: 0, CROSSTALK: 0}
    for iss in issues:
        total_counts[iss["type"]] += 1
    issue_total_full = len(issues)
    truncated = issue_total_full > ISSUE_LIMIT
    issues = issues[:ISSUE_LIMIT]
    for i, iss in enumerate(issues):
        iss["id"] = i

    # ---- 分量摘要（前端按分量着色） --------------------------------------
    comp_index, comp_out = {}, []
    for root in sorted(components, key=lambda r: (r not in active_component,
                                                  min(components[r]["ports"]))):
        ci = len(comp_out)
        comp_index[root] = ci
        ports_sorted = sorted(components[root]["ports"])
        comp_out.append({
            "id": ci,
            "active": root in active_component,
            "ports": [{"port": p, "jack": solver.port_jack.get(p),
                       "labeled": p in labeled_nodes}
                      for p in ports_sorted],
            "canonicalNames": sorted(n for n, e in components[root]["names"].items() if e),
        })
    for iss in issues:
        iss["component"] = comp_index.get(iss["component"])

    # mutex / alias-ring / crosstalk 均为 error 级，unlabeled 为 warning
    has_error = bool(total_counts[MUTEX] + total_counts[ALIAS_RING]
                     + total_counts[CROSSTALK])

    return {
        "ok": not has_error,
        "planOk": result["ok"],
        "summary": {
            "components": len(comp_out),
            "activeComponents": len(active_component),
            "labeledPorts": len(labeled_nodes),
            "issueCounts": total_counts,
            "issueTotal": issue_total_full,
            "issueShown": len(issues),
            "truncated": truncated,
        },
        "components": comp_out,
        "issues": issues,
        "pairs": result["pairs"],
        "cables": result["cables"],
        "routes": [{
            "index": i,
            "source": f"{r['source']['device']}.{r['source']['port']}",
            "target": f"{r['target']['device']}.{r['target']['port']}",
            "status": ("ok" if plan["planned"][i]["ok"] else "conflict"),
        } for i, r in enumerate(plan["routes"])],
        "auditNote": ("审计只读取规划结果传播名签，不修改任何路由、常态与跳线。"
                      + (f" 问题超过 {ISSUE_LIMIT} 条，仅展示前 {ISSUE_LIMIT} 条。"
                         if truncated else "")),
    }


# ---- 修正预览 -------------------------------------------------------------


def _rename_fix(origin, raw_name, preferred, rows):
    old_alias = (rows.get(origin) or {}).get("alias")
    return {
        "action": "rename",
        "target": {
            "kind": origin[0],
            "port": origin[1] if origin[0] == "port" else None,
            "id": origin[1] if origin[0] in ("pair", "cable") else None,
            "index": origin[1] if origin[0] == "route" else None,
            "label": _origin_label(origin[0], origin[1],
                                   port=origin[1] if origin[0] == "port" else None),
        },
        "targetLabel": _origin_label(origin[0], origin[1],
                                     port=origin[1] if origin[0] == "port" else None),
        "fromName": raw_name, "toName": preferred,
        "name": preferred,
        "alias": raw_name if not old_alias else old_alias,
        "label": f"{_origin_label(origin[0], origin[1], port=origin[1] if origin[0] == 'port' else None)}："
                 f"“{raw_name}” 降级为别名，规范名改为 “{preferred}”",
    }


def _rename_fixes(names_map, preferred, loser_set, rows):
    """把分量内所有落败规范名的声明行整理成去重后的 rename 预览。"""
    fixes, seen = [], set()
    for canon, entries in names_map.items():
        if canon not in loser_set or canon == preferred:
            continue
        for _, nd in entries:
            if nd["origin"] in seen:
                continue
            seen.add(nd["origin"])
            fixes.append(_rename_fix(nd["origin"], nd["raw"], preferred, rows))
    return fixes


def _target_of(origin):
    return {
        "kind": origin[0],
        "port": origin[1] if origin[0] == "port" else None,
        "id": origin[1] if origin[0] in ("pair", "cable") else None,
        "index": origin[1] if origin[0] == "route" else None,
        "label": _origin_label(origin[0], origin[1],
                               port=origin[1] if origin[0] == "port" else None),
    }


def _break_alias_fix(origin, alias, preferred, rows):
    """剪断别名环边：删除该行的别名（保留/统一规范名）。"""
    row = rows.get(origin) or {}
    return {
        "action": "break-alias",
        "target": _target_of(origin),
        "targetLabel": _origin_label(origin[0], origin[1],
                                     port=origin[1] if origin[0] == "port" else None),
        "removedAlias": alias,
        "name": preferred,
        "alias": None,
        "label": f"{_origin_label(origin[0], origin[1], port=origin[1] if origin[0] == 'port' else None)}："
                 f"删除别名 “{alias}”"
                 + (" 以剪断别名环" if (row.get("name") or "") == preferred
                    else f"，规范名改为 “{preferred}”（原 “{row.get('name')}” 降级为别名）"),
    }


# ---- 别名环问题 -----------------------------------------------------------


def _node_label_map(decls):
    m = defaultdict(set)
    for d in decls:
        if d["name"]:
            m[d["node"]].add(d["name"])
        if d["alias"]:
            m[d["node"]].add(d["alias"])
    return m


def _alias_issues(graph, resolver, decls, adj, plan, rows):
    issues = []

    # 2a. 同一别名被声明指向多个不同规范名（分叉）
    for alias in sorted(graph):
        targets = sorted(graph[alias])
        if len(targets) <= 1:
            continue
        votes = {t: resolver.name_votes.get(t, 0) for t in targets}
        preferred = min(targets, key=lambda t: (-votes[t], t))
        fixes, seen = [], set()
        for t in targets:
            if t == preferred:
                continue
            for d in graph[alias][t]:
                if d["origin"] in seen:
                    continue
                seen.add(d["origin"])
                fx = _rename_fix(d["origin"], d["name"], preferred, rows)
                fx["alias"] = alias                 # 保留原别名指向
                fixes.append(fx)
        # 证据：两个分叉声明所在端口之间的最短路径（找不到则只列端点）
        ports_a = [d["node"] for d in graph[alias][targets[0]]]
        ports_b = [d["node"] for d in graph[alias][targets[1]]]
        nodes, _ = shortest_path(adj, ports_a, ports_b)
        trail = " → ".join(targets)
        issues.append({
            "type": ALIAS_RING, "severity": "error",
            "title": TYPE_TITLES[ALIAS_RING],
            "subtype": "diverging",
            "message": f"别名 “{alias}” 同时被声明为 {len(targets)} 个不同规范名的别名"
                       f"（{trail}），指向分叉，无法确定它代表哪条信号。",
            "component": None, "names": [alias] + targets,
            "suggestedName": preferred,
            "evidence": evidence_items(nodes or ports_a[:1] + ports_b[:1],
                                       adj, plan, _node_label_map(decls)),
            "fixes": fixes,
        })

    # 2b. 有向环
    rings_done = set()
    for member in sorted(resolver.ring_members):
        rep = resolver.ring_rep[member]
        if rep in rings_done:
            continue
        rings_done.add(rep)
        comp = {n for n, r in resolver.ring_rep.items() if r == rep}
        cyc = _cycle_in(comp, resolver.succ)
        # 沿取出的环，保留指向采纳名 rep 的环边，其余环边逐边剪断
        fixes, seen = [], set()
        for i in range(len(cyc) - 1):
            alias_lead, canon_target = cyc[i], cyc[i + 1]
            decl_candidates = graph.get(alias_lead, {}).get(canon_target, [])
            for d in decl_candidates:
                if d["origin"] in seen:
                    continue
                seen.add(d["origin"])
                if canon_target == rep and (d.get("name") or "") == rep:
                    continue
                fixes.append(_break_alias_fix(d["origin"], alias_lead, rep, rows))
        # 证据：环上相邻名签的声明端口（取每跳最短路径拼接成本高，直接列出
        # 声明端口与环的文字链；端口都在时给一条最短连通路径作为物理证据）
        anchor_ports = [d["node"] for d in decls if d["name"] in comp or d["alias"] in comp]
        nodes = []
        if len(anchor_ports) >= 2:
            nodes, _ = shortest_path(adj, [anchor_ports[0]],
                                     [p for p in anchor_ports[1:] if p != anchor_ports[0]])
        issues.append({
            "type": ALIAS_RING, "severity": "error",
            "title": TYPE_TITLES[ALIAS_RING],
            "subtype": "cycle",
            "message": f"别名指向形成闭环：{' → '.join(cyc)}，没有任何一个名字是"
                       f"无争议的规范名，名签沿环传播会无限循环。建议采纳 “{rep}”"
                       f"（环内被显式声明为规范名次数最多）。",
            "component": None, "names": sorted(comp),
            "suggestedName": rep,
            "aliasChain": cyc,
            "evidence": evidence_items(nodes or anchor_ports[:2] or sorted(comp)[:1],
                                       adj, plan, _node_label_map(decls)),
            "fixes": fixes,
        })
    return issues
