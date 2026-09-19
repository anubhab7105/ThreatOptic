"""Graph store: networkx local (always) + Neo4j mirror when NEO4J_URI set.
Nodes: IP_Address, Domain, Email_Address, Threat_Campaign (per Shema.md)
Edges: SENT_FROM, HOSTS, PART_OF
"""
import os
from typing import Any
import networkx as nx

G = nx.DiGraph()

_neo_driver = None


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
                    s.run("MERGE (d:Domain {name:$d})", d=d.lower())
        except Exception:
            pass
    return {"nodes": G.number_of_nodes(), "edges": G.number_of_edges()}


def related_entities(value: str, depth: int = 2) -> dict[str, Any]:
    """BFS neighbourhood for graph view."""
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
    return {
        "nodes": [{"id": n, **G.nodes[n]} for n in sub.nodes],
        "edges": [{"source": u, "target": v, "rel": G[u][v].get("rel", "")} for u, v in sub.edges],
    }


def find_campaigns(min_shared: int = 2) -> list[dict[str, Any]]:
    """Cluster domains sharing IPs -> candidate campaigns."""
    campaigns = []
    for n in list(G.nodes):
        if G.nodes[n].get("kind") == "IP_Address":
            succ = list(G.successors(n))
            if len(succ) >= min_shared:
                campaigns.append({"ip": G.nodes[n].get("ip"), "domains": [G.nodes[d].get("name") for d in succ], "size": len(succ)})
    return sorted(campaigns, key=lambda x: -x["size"])[:50]
