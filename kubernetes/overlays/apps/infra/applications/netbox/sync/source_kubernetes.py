"""Kubernetes: nodes, LoadBalancer VIPs (+ which hosts Traefik routes on each port),
and selector-less Services that point at hosts outside the cluster."""
from __future__ import annotations

import ipaddress
import logging
import os
import re

from pydantic import BaseModel, ValidationError

from model import Collected, ExtServiceObs, LbPool, SvcObs, VipObs

log = logging.getLogger("kubernetes")
# Traefik entrypoints used by Ingresses with no router.entrypoints annotation
DEFAULT_ENTRYPOINTS = [e for e in os.environ.get("TRAEFIK_DEFAULT_ENTRYPOINTS", "web,websecure").split(",") if e]
EXT_PREFIX = re.compile(r"^external-service-")
HOST_RE = re.compile(r"Host(?:SNI)?\(([^)]*)\)")


class _ObjectMeta(BaseModel):
    namespace: str = ""
    name: str = ""


class _RouteService(BaseModel):
    name: str = ""


class _Route(BaseModel):
    match: str = ""
    services: list[_RouteService] = []


class _IngressRouteSpec(BaseModel):
    entryPoints: list[str] = []
    routes: list[_Route] = []


class IngressRouteRaw(BaseModel):
    metadata: _ObjectMeta = _ObjectMeta()
    spec: _IngressRouteSpec = _IngressRouteSpec()


class _LbBlock(BaseModel):
    start: str | None = None
    stop: str | None = None
    cidr: str | None = None


class _LbPoolSpec(BaseModel):
    disabled: bool = False
    blocks: list[_LbBlock] = []


class CiliumLbPoolRaw(BaseModel):
    metadata: _ObjectMeta = _ObjectMeta()
    spec: _LbPoolSpec = _LbPoolSpec()


def _client():
    from kubernetes import client, config
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api(), client.NetworkingV1Api(), client.DiscoveryV1Api(), client.CustomObjectsApi()


def _routes_by_entrypoint(net, custom) -> dict[str, dict[str, str]]:
    """entrypoint -> {host: 'ns/backend'} from Ingresses and Traefik IngressRoute(TCP)s."""
    out: dict[str, dict[str, str]] = {}
    for ing in net.list_ingress_for_all_namespaces().items:
        if (ing.spec.ingress_class_name or "traefik") != "traefik":
            continue
        ann = (ing.metadata.annotations or {}).get("traefik.ingress.kubernetes.io/router.entrypoints")
        eps = [e.strip() for e in ann.split(",")] if ann else DEFAULT_ENTRYPOINTS
        for rule in ing.spec.rules or []:
            backend = ""
            for p in (rule.http.paths if rule.http else []):
                if p.backend.service:
                    backend = f"{ing.metadata.namespace}/{p.backend.service.name}"
                    break
            for ep in eps:
                out.setdefault(ep, {})[rule.host or "*"] = backend
    for plural in ("ingressroutes", "ingressroutetcps"):
        try:
            items = custom.list_cluster_custom_object("traefik.io", "v1alpha1", plural)["items"]
        except Exception:
            continue
        for raw in items:
            try:
                r = IngressRouteRaw.model_validate(raw)
            except ValidationError as e:
                log.warning("skipping malformed %s %r: %s", plural, raw, e)
                continue
            ns = r.metadata.namespace
            for route in r.spec.routes:
                backend = f"{ns}/{route.services[0].name if route.services else r.metadata.name}"
                hosts = [h.strip("` ") for m in HOST_RE.findall(route.match) for h in m.split(",")] or ["*"]
                for ep in r.spec.entryPoints or DEFAULT_ENTRYPOINTS:
                    for h in hosts:
                        out.setdefault(ep, {})[h] = backend
    return out


def collect(c: Collected) -> None:
    core, net, disc, custom = _client()

    for node in core.list_node().items:
        for a in node.status.addresses or []:
            if a.type == "InternalIP":
                c.k8s_nodes[node.metadata.name] = a.address
        if node.status.node_info and node.status.node_info.os_image:
            c.k8s_node_os[node.metadata.name] = node.status.node_info.os_image
    node_ips = set(c.k8s_nodes.values())

    pod_cidr = os.environ.get("K8S_POD_CIDR", "REDACTED_IP/16")
    svc_cidr = os.environ.get("K8S_SVC_CIDR", "REDACTED_IP/16")
    c.k8s_prefixes = {pod_cidr: "kubernetes pods", svc_cidr: "kubernetes services"}
    in_cluster = [ipaddress.ip_network(pod_cidr), ipaddress.ip_network(svc_cidr)]

    routes = _routes_by_entrypoint(net, custom)

    vips: dict[str, VipObs] = {}
    ext_ports: dict[str, list[str]] = {}
    for svc in core.list_service_for_all_namespaces().items:
        ns_name = f"{svc.metadata.namespace}/{svc.metadata.name}"
        if svc.spec.type == "LoadBalancer":
            for ing in (svc.status.load_balancer.ingress or []) if svc.status.load_balancer else []:
                if not ing.ip:
                    continue
                vip = vips.setdefault(ing.ip, VipObs(ip=ing.ip, owners=[]))
                vip.owners.append(ns_name)
                for p in svc.spec.ports or []:
                    label = p.name or str(p.port)
                    hosts = routes.get(label, {})
                    desc = ", ".join(sorted(h for h in hosts if h != "*")) or ", ".join(sorted(set(hosts.values())))
                    vip.services.append(SvcObs(
                        name=f"{ns_name} {label}", port_mappings=[f"{p.protocol.lower()}/{p.port}"],
                        description=desc,
                        comments="\n".join(f"- `{h}` → {b}" for h, b in sorted(hosts.items()))))
        elif not svc.spec.selector and svc.spec.type in ("ClusterIP", "NodePort"):
            ext_ports[ns_name] = [f"{p.protocol.lower()}/{p.port}" for p in svc.spec.ports or []]

    # Selector-less Services: their EndpointSlices are hand-written and point outside the cluster.
    for es in disc.list_endpoint_slice_for_all_namespaces().items:
        labels = es.metadata.labels or {}
        svc_name = labels.get("kubernetes.io/service-name")
        if not svc_name or labels.get("endpointslice.kubernetes.io/managed-by") == "endpointslice-controller.k8s.io":
            continue
        ns_name = f"{es.metadata.namespace}/{svc_name}"
        if ns_name not in ext_ports:
            continue
        for ep in es.endpoints or []:
            for addr in ep.addresses or []:
                ip = ipaddress.ip_address(addr)
                if addr in node_ips or any(ip in n for n in in_cluster):
                    continue      # the apiserver / kubelet endpoints are the nodes themselves
                c.ext_services.append(ExtServiceObs(
                    ip=addr, name=EXT_PREFIX.sub("", svc_name), k8s_service=ns_name,
                    port_mappings=ext_ports[ns_name]))

    c.vips.extend(sorted(vips.values(), key=lambda v: v.ip))

    # Cilium LoadBalancer IP pools: the ranges those VIPs are handed out from
    try:
        pools = custom.list_cluster_custom_object("cilium.io", "v2", "ciliumloadbalancerippools")["items"]
    except Exception:
        pools = []
    for raw in pools:
        try:
            p = CiliumLbPoolRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed lb pool %r: %s", raw, e)
            continue
        if p.spec.disabled:
            continue
        for b in p.spec.blocks:
            if b.start and b.stop:
                c.lb_pools.append(LbPool(p.metadata.name, b.start, b.stop))
            elif b.cidr:
                net = ipaddress.ip_network(b.cidr)
                c.lb_pools.append(LbPool(p.metadata.name, str(net[0]), str(net[-1])))
