"""Graph store: Neo4j-first when NEO4J_URI is set, networkx local fallback.

Writes mirror to both backends (best-effort). Reads use Neo4j as the source
of truth whenever it is configured so attribution stays consistent across
replicas; the in-memory graph is a single-replica/local-dev fallback (F8).
"""
import os
from typing import Any
import networkx as nx

G = nx.DiGraph()

# Step 4: bound the ephemeral graph so one flood can't OOM the process.
# Oldest nodes (insertion order) are evicted first.
MAX_GRAPH_NODES = 20000

_neo_driver = None


def _touch() -> None:
    overflow = G.number_of_nodes() - MAX_GRAPH_NODES
    if overflow > 0:
        for n in list(G.nodes)[:overflow]:
            try:
                G.remove_node(n)
            except Exception:
                pass


def _neo():
    global _neo_driver
    uri = os.environ.get("NEO4J_URI", "")
    if not uri:
        return None
    try:
        from neo4j import GraphDatabase
        if _neo_driver is None:
            _neo_driver = GraphDatabase.driver(uri, auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "")))
        return _neo_driver
    except Exception:
        return None


def close_neo() -> None:
    """Release the Neo4j driver (called from lifespan shutdown)."""
    global _neo_driver
    drv, _neo_driver = _neo_driver, None
    if drv is not None:
        try:
            drv.close()
        except Exception:
            pass


def graph_consistency_note() -> str | None:
    """Warn when the ephemeral graph would diverge (multi-replica, no Neo4j)."""
    from ...config import get_settings

    settings = get_settings()
    uri = os.environ.get("NEO4J_URI", "") or settings.neo4j_uri
    if not uri and getattr(settings, "expected_replicas", 1) > 1:
        return ("NEO4J_URI is unset with expected_replicas>1: the in-memory graph "
                "is per-replica and attribution will diverge — configure Neo4j.")
    return None


def _node_id(labels: list, props: dict) -> str | None:
    label = labels[0] if labels else ""
    if label == "Email_Address" and props.get("address"):
        return f"email:{props['address']}"
    if label == "IP_Address" and props.get("ip"):
        return f"ip:{props['ip']}"
    if label == "Domain" and props.get("name"):
        return f"domain:{props['name']}"
    if label == "Threat_Campaign" and props.get("name"):
        return f"campaign:{props['name']}"
    return None


def _node_kind(labels: list) -> str:
    return labels[0] if labels else "Unknown"


def _neo_related(value: str, depth: int) -> dict[str, Any] | None:
    """Read the neighbourhood from Neo4j. None => fall back to networkx."""
    drv = _neo()
    if not drv:
        return None
    depth = max(1, min(int(depth), 5))
    root_filter = "toLower(coalesce(n.address, n.ip, n.name, '')) = toLower($v)"
    try:
        with drv.session() as s:
            roots = list(s.run(
                f"MATCH (n) WHERE {root_filter} "
                "RETURN labels(n) AS labels, properties(n) AS props LIMIT 1",
                {"v": value}))
            if not roots:
                return {"nodes": [], "edges": []}
            node_rows = list(s.run(
                f"MATCH p=(n)-[*1..{depth}]-(m) WHERE {root_filter} "
                "UNWIND nodes(p) AS x "
                "RETURN DISTINCT labels(x) AS labels, properties(x) AS props LIMIT 500",
                {"v": value}))
            rel_rows = list(s.run(
                f"MATCH p=(n)-[*1..{depth}]-(m) WHERE {root_filter} "
                "UNWIND relationships(p) AS r RETURN DISTINCT type(r) AS t, "
                "labels(startNode(r)) AS slab, properties(startNode(r)) AS sprops, "
                "labels(endNode(r)) AS elab, properties(endNode(r)) AS eprops LIMIT 500",
                {"v": value}))
    except Exception:
        return None
    nodes: dict[str, dict] = {}
    for r in roots + node_rows:
        nid = _node_id(list(r["labels"] or []), dict(r["props"] or {}))
        if nid and nid not in nodes:
            labels = list(r["labels"] or [])
            nodes[nid] = {"id": nid, "kind": _node_kind(labels),
                          **{k: v for k, v in dict(r["props"] or {}).items()
                             if k in ("address", "ip", "name", "country", "is_malicious")}}
    edges = []
    seen = set()
    for r in rel_rows:
        a = _node_id(list(r["slab"] or []), dict(r["sprops"] or {}))
        b = _node_id(list(r["elab"] or []), dict(r["eprops"] or {}))
        if a and b and (a, b, r["t"]) not in seen and a in nodes and b in nodes:
            seen.add((a, b, r["t"]))
            edges.append({"source": a, "target": b, "rel": r["t"]})
    return {"nodes": list(nodes.values()), "edges": edges}


def _neo_find_campaigns(min_shared: int) -> list[dict[str, Any]] | None:
    drv = _neo()
    if not drv:
        return None
    try:
        with drv.session() as s:
            rows = list(s.run(
                "MATCH (i:IP_Address)-[:HOSTS]->(d:Domain) "
                "WITH i, collect(DISTINCT d.name) AS domains "
                "WHERE size(domains) >= $min "
                "RETURN i.ip AS ip, domains, size(domains) AS size "
                "ORDER BY size DESC LIMIT 50",
                {"min": min_shared}))
            return [{"ip": r["ip"], "domains": list(r["domains"]), "size": r["size"]} for r in rows]
    except Exception:
        return None


def remove_email_graph(email_addr: str) -> None:
    """Best-effort removal of one email node (retention cascade)."""
    key = f"email:{(email_addr or '').lower()[:320]}"
    try:
        if key in G:
            G.remove_node(key)
    except Exception:
        pass
    drv = _neo()
    if drv:
        try:
            with drv.session() as s:
                s.run("MATCH (e:Email_Address {address:$a}) DETACH DELETE e", a=(email_addr or "").lower()[:320])
        except Exception:
            pass


def upsert_email_graph(email_addr: str, ip: str, domains: list[str], campaign: str = "") -> dict[str, Any]:
    email_addr = (email_addr or "").lower()[:320]
    ip = ip or ""
    e_node = f"email:{email_addr}"
    G.add_node(e_node, kind="Email_Address", address=email_addr)
    if ip:
        i_node = f"ip:{ip}"
        G.add_node(i_node, kind="IP_Address", ip=ip)
        G.add_edge(e_node, i_node, rel="SENT_FROM")
    for d in domains[:20]:
        d = d.lower()
        d_node = f"domain:{d}"
        G.add_node(d_node, kind="Domain", name=d)
        if ip:
            G.add_edge(f"ip:{ip}", d_node, rel="HOSTS")
        if campaign:
            c_node = f"campaign:{campaign}"
            G.add_node(c_node, kind="Threat_Campaign", name=campaign)
            G.add_edge(d_node, c_node, rel="PART_OF")
    # Neo4j mirror best-effort
    drv = _neo()
    if drv:
        try:
            with drv.session() as s:
                s.run("MERGE (e:Email_Address {address:$a})", a=email_addr)
                if ip:
                    s.run("MERGE (i:IP_Address {ip:$ip}) MERGE (e:Email_Address {address:$a}) MERGE (e)-[:SENT_FROM]->(i)", a=email_addr, ip=ip)
                for d in domains[:20]:
                    d_clean = d.lower()
                    s.run("MERGE (d:Domain {name:$d})", d=d_clean)
                    if ip:
                        s.run("MERGE (i:IP_Address {ip:$ip}) MERGE (d:Domain {name:$d}) MERGE (i)-[:HOSTS]->(d)", ip=ip, d=d_clean)
                    if campaign:
                        s.run("MERGE (d:Domain {name:$d}) MERGE (c:Threat_Campaign {name:$c}) MERGE (d)-[:PART_OF]->(c)", d=d_clean, c=campaign)
        except Exception:
            pass
    _touch()
    return {"nodes": G.number_of_nodes(), "edges": G.number_of_edges()}


def related_entities(value: str, depth: int = 2) -> dict[str, Any]:
    """BFS neighbourhood for graph view. Neo4j-first when configured (F8)."""
    neo = _neo_related(value, depth)
    if neo is not None:
        return neo
    key = None
    for prefix in ("email:", "ip:", "domain:", "campaign:"):
        cand = prefix + value.lower()
        if cand in G:
            key = cand
            break
    if key is None:
        # try raw match
        for n in G.nodes:
            if str(n).endswith(":" + value.lower()):
                key = n
                break
    if key is None:
        return {"nodes": [], "edges": []}
    sub = nx.ego_graph(G.to_undirected(), key, radius=depth)
    edges = []
    for u, v in sub.edges:
        data = sub.get_edge_data(u, v) or {}
        edges.append({"source": u, "target": v, "rel": data.get("rel", "")})
    return {
        "nodes": [{"id": n, **G.nodes[n]} for n in sub.nodes],
        "edges": edges,
    }


def find_campaigns(min_shared: int = 2) -> list[dict[str, Any]]:
    """Cluster domains sharing IPs -> candidate campaigns. Neo4j-first (F8)."""
    neo = _neo_find_campaigns(min_shared)
    if neo is not None:
        return neo
    campaigns = []
    for n in list(G.nodes):
        if G.nodes[n].get("kind") == "IP_Address":
            succ = list(G.successors(n))
            if len(succ) >= min_shared:
                campaigns.append({"ip": G.nodes[n].get("ip"), "domains": [G.nodes[d].get("name") for d in succ], "size": len(succ)})
    return sorted(campaigns, key=lambda x: -x["size"])[:50]
