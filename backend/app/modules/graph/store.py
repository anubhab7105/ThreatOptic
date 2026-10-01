"""Graph store: Neo4j-first when NEO4J_URI is set, networkx local fallback.

Writes mirror to both backends (best-effort). Reads use Neo4j as the source
of truth whenever it is configured so attribution stays consistent across
replicas; the in-memory graph is a single-replica/local-dev fallback (F8).

Tenant model (P0): the graph itself is SHARED cross-tenant threat intel
(infra-level IPs/domains/campaigns — no access control at this layer).
Tenant isolation is enforced by CALLERS (routers/api.py, services/
campaigns.py): Email_Address nodes not attributable to the caller's org
are stripped from responses; Admins see all. Never expose raw
related_entities()/find_campaigns() output for one tenant to another
without that filtering.
"""
import os
from typing import Any
import networkx as nx

G = nx.DiGraph()

# Step 4: bound the ephemeral graph so one flood can't OOM the process.
# Oldest nodes (insertion order) are evicted first.
MAX_GRAPH_NODES = 20000

# P0 reliability budgets: paginated hydration, clamped traversals, capped
# read output — none of these paths may load or return unbounded data.
HYDRATE_BATCH_ROWS = 1000
HYDRATE_MAX_ROWS = 5000
NX_MAX_DEPTH = 5
NX_MAX_NODES = 500
NX_MAX_EDGES = 1000

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


def _valid_ip(ip: str) -> bool:
    return bool(ip) and ip not in ("0.0.0.0", "unresolved", "none", "")


def _neo_mirror(email_addr: str, ip: str, domains: list[str], campaign: str) -> None:
    """Mirror one mail to Neo4j in a few batched statements (P0).

    Previously up to ~62 round trips per mail (per-domain/per-edge
    MERGEs). Now: one statement for the email node, one for the IP edge,
    and one UNWIND batch each for domains / HOSTS / campaign edges.
    Best-effort: any failure is swallowed (local graph is authoritative
    for single-replica writes).
    """
    drv = _neo()
    if not drv:
        return
    domains = [d for d in (domains or []) if d][:20]
    try:
        with drv.session() as s:
            s.run("MERGE (e:Email_Address {address:$a})", a=email_addr)
            if _valid_ip(ip):
                s.run("MERGE (i:IP_Address {ip:$ip}) WITH i "
                      "MATCH (e:Email_Address {address:$a}) "
                      "MERGE (e)-[:SENT_FROM]->(i)", a=email_addr, ip=ip)
            if domains:
                s.run("UNWIND $ds AS dname MERGE (d:Domain {name:dname})", ds=domains)
                if _valid_ip(ip):
                    s.run("UNWIND $ds AS dname "
                          "MATCH (i:IP_Address {ip:$ip}), (d:Domain {name:dname}) "
                          "MERGE (i)-[:HOSTS]->(d)", ip=ip, ds=domains)
                if campaign:
                    s.run("UNWIND $ds AS dname "
                          "MATCH (d:Domain {name:dname}) "
                          "MERGE (c:Threat_Campaign {name:$c}) "
                          "MERGE (d)-[:PART_OF]->(c)", ds=domains, c=campaign)
    except Exception:
        pass


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


def _clean_email(raw: str) -> str:
    if not raw:
        return ""
    from email.utils import parseaddr
    import re
    _, addr = parseaddr(raw)
    if not addr:
        m = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", raw)
        addr = m.group(0) if m else raw
    return addr.strip().lower()[:320]


def upsert_email_graph(
    email_addr: str,
    ip: str,
    domains: list[str],
    campaign: str = "",
    recipient: str = "",
) -> dict[str, Any]:
    email_addr = _clean_email(email_addr) or (email_addr or "").lower()[:320]
    ip = (ip or "").strip()
    e_node = f"email:{email_addr}"
    G.add_node(e_node, kind="Email_Address", address=email_addr)

    derived_domains = [d.lower().strip() for d in (domains or []) if d and d.strip()]
    if "@" in email_addr:
        dom = email_addr.split("@")[-1].strip(" <>").lower()
        if dom and dom not in derived_domains:
            derived_domains.append(dom)

    for d in derived_domains[:20]:
        d_node = f"domain:{d}"
        G.add_node(d_node, kind="Domain", name=d)
        G.add_edge(e_node, d_node, rel="FROM_DOMAIN")
        if ip and ip not in ("0.0.0.0", "unresolved", "none", ""):
            G.add_edge(f"ip:{ip}", d_node, rel="HOSTS")
        if campaign:
            c_node = f"campaign:{campaign}"
            G.add_node(c_node, kind="Threat_Campaign", name=campaign)
            G.add_edge(d_node, c_node, rel="PART_OF")

    if ip and ip not in ("0.0.0.0", "unresolved", "none", ""):
        i_node = f"ip:{ip}"
        G.add_node(i_node, kind="IP_Address", ip=ip)
        G.add_edge(e_node, i_node, rel="SENT_FROM")

    if recipient:
        rec_clean = _clean_email(recipient)
        if rec_clean:
            r_node = f"email:{rec_clean}"
            G.add_node(r_node, kind="Email_Address", address=rec_clean)
            G.add_edge(e_node, r_node, rel="SENT_TO")

    # Neo4j mirror best-effort, batched (P0: ~5 round trips, not ~62).
    _neo_mirror(email_addr, ip, derived_domains, campaign)
    _touch()
    return {"nodes": G.number_of_nodes(), "edges": G.number_of_edges()}


def ensure_graph_hydrated(db: Any) -> None:
    """Hydrate in-memory graph from SQLite database if empty.

    P0: paginated batches with a total cap — never .all() unbounded.
    """
    if G.number_of_nodes() > 0 or db is None:
        return
    try:
        from ... import models
        loaded = 0
        offset = 0
        while loaded < HYDRATE_MAX_ROWS:
            rows = (
                db.query(
                    models.EmailRecord.sender_address,
                    models.EmailRecord.recipient_address,
                    models.TraceabilityData.origin_ip,
                    models.AnalysisResult.threat_classification,
                )
                .outerjoin(models.TraceabilityData, models.EmailRecord.id == models.TraceabilityData.email_id)
                .outerjoin(models.AnalysisResult, models.EmailRecord.id == models.AnalysisResult.email_id)
                .order_by(models.EmailRecord.timestamp.desc())
                .limit(min(HYDRATE_BATCH_ROWS, HYDRATE_MAX_ROWS - loaded))
                .offset(offset)
                .all()
            )
            if not rows:
                break
            for sender, recipient, ip, classification in rows:
                if not sender:
                    continue
                clean_s = _clean_email(sender)
                domain = clean_s.split("@")[-1].strip(" <>") if "@" in clean_s else ""
                campaign = classification if (classification and "phishing" in str(classification).lower()) else ""
                upsert_email_graph(clean_s, ip or "", [domain] if domain else [], campaign=campaign, recipient=recipient or "")
            loaded += len(rows)
            offset += len(rows)
            if len(rows) < HYDRATE_BATCH_ROWS:
                break
    except Exception:
        pass


def related_entities(value: str, depth: int = 2, db: Any = None, email_id: str | None = None) -> dict[str, Any]:
    """BFS neighbourhood for graph view. Neo4j-first when configured (F8).

    P0: depth clamped (unbounded radius on a 20k-node graph hangs the
    request) and networkx output capped — same shape, bounded size.
    """
    try:
        depth = max(1, min(int(depth or 2), NX_MAX_DEPTH))
    except (TypeError, ValueError):
        depth = 2
    neo = _neo_related(value, depth)
    if neo is not None:
        return neo

    if db is not None:
        ensure_graph_hydrated(db)

    clean_val = _clean_email(value) or (value or "").lower().strip()
    key = None
    for prefix in ("email:", "ip:", "domain:", "campaign:"):
        cand = prefix + clean_val
        if cand in G:
            key = cand
            break
    if key is None:
        # try raw match or substring match (min length 3 to prevent false positive short matches)
        for n in list(G.nodes):
            n_str = str(n).lower()
            if n_str.endswith(":" + clean_val) or (len(clean_val) >= 3 and clean_val in n_str):
                key = n
                break

    # If still not found and DB is available, hydrate from specific email
    if key is None and db is not None:
        try:
            from ... import models
            email_row = None
            if email_id:
                email_row = db.query(models.EmailRecord).filter(models.EmailRecord.id == email_id).first()
            if not email_row and len(clean_val) >= 3:
                email_row = db.query(models.EmailRecord).filter(models.EmailRecord.sender_address.ilike(f"%{clean_val}%")).first()
            if email_row:
                trace = db.query(models.TraceabilityData).filter(models.TraceabilityData.email_id == email_row.id).first()
                analysis = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id == email_row.id).first()
                sender = _clean_email(email_row.sender_address)
                domain = sender.split("@")[-1].strip(" <>") if "@" in sender else ""
                ip = trace.origin_ip if trace else ""
                campaign = str(analysis.threat_classification) if analysis and "phishing" in str(analysis.threat_classification).lower() else ""
                upsert_email_graph(sender, ip or "", [domain] if domain else [], campaign=campaign, recipient=email_row.recipient_address or "")
                key = f"email:{sender}"
        except Exception:
            pass

    if key is None:
        if "@" in clean_val:
            domain = clean_val.split("@")[-1].strip(" <>")
            upsert_email_graph(clean_val, "", [domain] if domain else [])
            key = f"email:{clean_val}"
    sub = nx.ego_graph(G.to_undirected(), key, radius=depth)
    # P0: cap read output even if the capped radius still covers plenty.
    sub_nodes = list(sub.nodes)[:NX_MAX_NODES]
    keep = set(sub_nodes)
    edges = []
    seen_edges = set()
    for u, v in sub.edges:
        if len(edges) >= NX_MAX_EDGES:
            break
        if u not in keep or v not in keep:
            continue
        data = G.get_edge_data(u, v) or G.get_edge_data(v, u) or sub.get_edge_data(u, v) or {}
        pair = (min(u, v), max(u, v))
        if pair not in seen_edges:
            seen_edges.add(pair)
            edges.append({"source": u, "target": v, "rel": data.get("rel", "")})

    def _enrich_node(n: str, data: dict) -> dict:
        kind = data.get("kind")
        if not kind or kind == "Unknown":
            if str(n).startswith("email:"):
                kind = "Email_Address"
            elif str(n).startswith("ip:"):
                kind = "IP_Address"
            elif str(n).startswith("domain:"):
                kind = "Domain"
            elif str(n).startswith("campaign:"):
                kind = "Threat_Campaign"
            else:
                kind = "Entity"
        return {"id": n, **data, "kind": kind}

    return {
        "nodes": [_enrich_node(n, G.nodes[n]) for n in sub_nodes],
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
