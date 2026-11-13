import json
import re
from random import choice

from app.models.subscription import (
    GRPCTransportConfig,
    SubscriptionInboundData,
    TCPTransportConfig,
    TLSConfig,
    WebSocketTransportConfig,
)

from . import BaseSubscription
from .base import dumps_compact


class SingBoxConfiguration(BaseSubscription):
    def __init__(
        self,
        singbox_template_content: str | None = None,
        user_agent_template_content: str | None = None,
        grpc_user_agent_template_content: str | None = None,
    ):
        super().__init__(
            user_agent_template_content=user_agent_template_content,
            grpc_user_agent_template_content=grpc_user_agent_template_content,
        )
        self.config = json.loads(singbox_template_content) if singbox_template_content else {}
        self.config.setdefault("endpoints", [])
        self.config.setdefault("outbounds", [])

        # Registry for transport handlers
        self.transport_handlers = {
            "http": self._transport_http,
            "ws": self._transport_ws,
            "grpc": self._transport_grpc,
            "gun": self._transport_grpc,
            "httpupgrade": self._transport_httpupgrade,
            "h2": self._transport_http,
            "h3": self._transport_http,
            "raw": self._transport_http,
        }

        # Registry for protocol builders
        self.protocol_handlers = {
            "vmess": self._build_vmess,
            "vless": self._build_vless,
            "trojan": self._build_trojan,
            "shadowsocks": self._build_shadowsocks,
            "hysteria": self._build_hysteria,
            "wireguard": self._build_wireguard,
        }

    def add_outbound(self, outbound_data):
        self.config["outbounds"].append(outbound_data)

    def add_endpoint(self, endpoint_data):
        self.config["endpoints"].append(endpoint_data)

    def render(self):
        self._finalize_config()
        return dumps_compact(self.config)

    def _finalize_config(self):
        urltest_types = ["vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic", "http", "ssh"]
        urltest_tags = [outbound["tag"] for outbound in self.config["outbounds"] if outbound["type"] in urltest_types]
        selector_types = [
            "vmess",
            "vless",
            "trojan",
            "shadowsocks",
            "hysteria2",
            "tuic",
            "http",
            "ssh",
            "urltest",
        ]
        selector_tags = [outbound["tag"] for outbound in self.config["outbounds"] if outbound["type"] in selector_types]
        endpoint_tags = [endpoint["tag"] for endpoint in self.config.get("endpoints", []) if endpoint.get("tag")]
        urltest_tags.extend(endpoint_tags)
        selector_tags.extend(endpoint_tags)

        # [topren patch] 模板已写 outbounds 的组保留原样（对齐 Marzban patches/singbox.py）
        for outbound in self.config["outbounds"]:
            if outbound.get("type") == "urltest" and outbound.get("outbounds") is None:
                outbound["outbounds"] = urltest_tags

        for outbound in self.config["outbounds"]:
            if outbound.get("type") == "selector" and outbound.get("outbounds") is None:
                outbound["outbounds"] = selector_tags

        existing = [o["tag"] for o in self.config["outbounds"] if "tag" in o]
        existing += [e["tag"] for e in self.config.get("endpoints", []) if e.get("tag")]
        existing_set = set(existing)

        def _resolve(ref):
            if not isinstance(ref, str) or ref in existing_set or "{" not in ref:
                return ref
            pattern = re.compile("^" + re.sub(r"\\\{[A-Za-z0-9_]+\\\}", ".+?", re.escape(ref)) + "$")
            for tag in existing:
                if pattern.match(tag):
                    return tag
            return ref

        # [topren patch 2026-10-14] 成员被裁剪到 0 的分组, 整组删除并从所有引用处移除,
        # 而不是退化成 ["direct"]。原因: 像「加州家宽-自动测速」这种纯家宽分组, 对看不到家宽
        # 节点的分享用户会被裁成空组, 若填 direct 则该用户选中它就是明文直连、泄露真实 IP。
        # 迭代是因为删掉一个空组可能让引用它的上层组也变空。
        def _groups():
            return [o for o in self.config["outbounds"]
                    if o.get("type") in ("urltest", "selector") and isinstance(o.get("outbounds"), list)]

        for _ in range(10):
            existing = [o["tag"] for o in self.config["outbounds"] if "tag" in o]
            existing += [e["tag"] for e in self.config.get("endpoints", []) if e.get("tag")]
            existing_set = set(existing)
            empty = set()
            for ob in _groups():
                resolved = []
                for ref in ob["outbounds"]:
                    tag = _resolve(ref)
                    if tag in existing_set and tag not in resolved:
                        resolved.append(tag)
                ob["outbounds"] = resolved
                if not resolved and ob.get("tag"):
                    empty.add(ob["tag"])
            if not empty:
                break
            self.config["outbounds"] = [o for o in self.config["outbounds"]
                                        if o.get("tag") not in empty]
            # 同步清理 route 规则里指向被删组的引用, 否则 sing-box 会因未知 outbound 启动失败。
            # 删整条规则(而非改指向)才是正确语义: 规则的目标没了, 这些流量应落到 route.final,
            # 仍然走代理; 若改指向 direct 就成了明文直连。
            route = self.config.get("route")
            if isinstance(route, dict) and isinstance(route.get("rules"), list):
                route["rules"] = [r for r in route["rules"]
                                  if not (isinstance(r, dict) and r.get("outbound") in empty)]

        # 收尾: 迭代上限兜底(理论上到不了) + 修正 default 指向
        for ob in _groups():
            if not ob["outbounds"]:
                ob["outbounds"] = ["direct"]
            if isinstance(ob.get("default"), str):
                d = _resolve(ob["default"])
                ob["default"] = d if d in ob["outbounds"] else ob["outbounds"][0]

        # [topren patch 2026-10-30] 订阅 dns.strategy=ipv4_only, 节点 server 若是只有 AAAA 的域名(ppf6/hk6.topren.top)
        # 会 "lookup ...: empty result" 连不上。给所有「server 是域名」的代理出站单独指定解析策略 prefer_ipv4:
        # 有 A 记录照旧走 v4(现有节点行为不变), 只有 AAAA 时才用 v6。站点流量的解析仍受全局 ipv4_only 约束。
        import ipaddress as _ip
        _route = self.config.get("route") if isinstance(self.config.get("route"), dict) else {}
        _ddr = _route.get("default_domain_resolver")
        _rsv = _ddr.get("server") if isinstance(_ddr, dict) else (_ddr or "dns-direct")
        for ob in self.config["outbounds"]:
            srv = ob.get("server")
            if not isinstance(srv, str) or not srv or "domain_resolver" in ob:
                continue
            try:
                _ip.ip_address(srv)
                continue
            except ValueError:
                ob["domain_resolver"] = {"server": _rsv, "strategy": "prefer_ipv4"}

        # route.final 若指向被删掉的组, 回退到第一个仍存在的 selector(而不是 direct)
        route = self.config.get("route")
        if isinstance(route, dict) and isinstance(route.get("final"), str):
            tags = set(o.get("tag") for o in self.config["outbounds"] if o.get("tag"))
            if route["final"] not in tags:
                sel = next((o["tag"] for o in self.config["outbounds"]
                            if o.get("type") == "selector" and o.get("tag")), None)
                if sel:
                    route["final"] = sel

    def add(self, remark: str, address: str, inbound: SubscriptionInboundData, settings: dict):
        """Add outbound using registry pattern"""
        # Not supported by sing-box
        if inbound.network in ("kcp", "splithttp", "xhttp"):
            return
        if inbound.network == "quic" and getattr(inbound.transport_config, "header_type", "none") != "none":
            return

        remark = self._remark_validation(remark)
        self.proxy_remarks.append(remark)

        # Get protocol handler from registry
        handler = self.protocol_handlers.get(inbound.protocol)
        if not handler:
            return

        # Build outbound or WireGuard endpoint (sing-box 1.11+)
        built = handler(remark=remark, address=address, inbound=inbound, settings=settings)
        if built:
            if inbound.protocol == "wireguard":
                self.add_endpoint(built)
            else:
                self.add_outbound(built)

    # ========== Transport Handlers ==========

    def _transport_http(self, config: TCPTransportConfig, path: str, network: str) -> dict:
        """Handle HTTP/H2/H3 transport - only gets TCP config"""
        host = config.host if isinstance(config.host, str) else (config.host[0] if config.host else "")

        transport = {
            "type": network if network in ("http", "h2", "h3") else "http",
            "idle_timeout": "15s",
            "ping_timeout": "15s",
            "path": path,
            "host": [host] if host else None,
        }

        if config.header_type == "http" and config.request:
            # Filter out invalid fields for singbox transport
            request_config = {k: v for k, v in config.request.items() if k != "version"}
            transport.update(request_config)
        else:
            transport["headers"] = {k: [v] for k, v in config.http_headers.items()} if config.http_headers else {}

        if config.random_user_agent:
            transport.setdefault("headers", {})["User-Agent"] = choice(self.user_agent_list)

        return self._normalize_and_remove_none_values(transport)

    def _transport_ws(self, config: WebSocketTransportConfig, path: str) -> dict:
        """Handle WebSocket transport - only gets WS config"""
        host = config.host if isinstance(config.host, str) else (config.host[0] if config.host else "")

        # Parse early data from path
        max_early_data = None
        early_data_header_name = None
        if "?ed=" in path:
            path, ed_part = path.split("?ed=")
            max_early_data = int(ed_part.split("/")[0])
            early_data_header_name = "Sec-WebSocket-Protocol"

        transport = {
            "type": "ws",
            "headers": {k: [v] for k, v in config.http_headers.items()} if config.http_headers else {},
            "path": path,
            "max_early_data": max_early_data,
            "early_data_header_name": early_data_header_name,
        }
        transport["headers"]["host"] = [host] if host else None

        if config.random_user_agent:
            transport["headers"]["User-Agent"] = [choice(self.user_agent_list)]

        return self._normalize_and_remove_none_values(transport)

    def _transport_grpc(self, config: GRPCTransportConfig, path: str) -> dict:
        """Handle GRPC transport - only gets GRPC config"""
        return self._normalize_and_remove_none_values(
            {
                "type": "grpc",
                "service_name": path,
                "idle_timeout": f"{config.idle_timeout}s" if config.idle_timeout else "15s",
                "ping_timeout": f"{config.health_check_timeout}s" if config.health_check_timeout else "15s",
                "permit_without_stream": config.permit_without_stream,
            }
        )

    def _transport_httpupgrade(self, config: WebSocketTransportConfig, path: str) -> dict:
        """Handle HTTPUpgrade transport - only gets WS config (similar to WS)"""
        host = config.host if isinstance(config.host, str) else (config.host[0] if config.host else "")
        if "?ed=" in path:
            path, _ = path.split("?ed=")

        transport = {
            "type": "httpupgrade",
            "headers": {k: [v] for k, v in config.http_headers.items()} if config.http_headers else {},
            "host": host,
            "path": path,
        }

        if config.random_user_agent:
            transport["headers"]["User-Agent"] = [choice(self.user_agent_list)]

        return self._normalize_and_remove_none_values(transport)

    def _apply_transport(self, network: str, inbound: SubscriptionInboundData, path: str) -> dict | None:
        """Apply transport settings using registry pattern"""
        # Map network types
        if network in ("tcp", "raw") and getattr(inbound.transport_config, "header_type", "none") == "http":
            network = "http"

        # For pure TCP connections without HTTP headers, don't add transport config
        if network in ("tcp", "raw") and getattr(inbound.transport_config, "header_type", "none") != "http":
            return None

        handler = self.transport_handlers.get(network)
        if not handler:
            return None

        # Pass only the config this transport needs
        if network in ("http", "h2", "h3", "raw", "tcp"):
            return handler(inbound.transport_config, path, network)
        else:
            return handler(inbound.transport_config, path)

    def _apply_tls(self, tls_config: TLSConfig, fragment_settings: dict | None = None) -> dict:
        """Apply TLS settings - receives TLS config and optional fragment settings"""
        fingerprint = "chrome" if tls_config.fingerprint == "unsafe" else tls_config.fingerprint
        ech_config = self._format_ech_config(tls_config.sing_box_ech_config)
        ech_enabled = bool(ech_config or tls_config.sing_box_ech_query_server_name)

        config = {
            "enabled": tls_config.tls in ("tls", "reality"),
            "server_name": tls_config.sni
            if isinstance(tls_config.sni, str)
            else (tls_config.sni[0] if tls_config.sni else None),
            "insecure": tls_config.allowinsecure,
            "certificate_public_key_sha256": [tls_config.pinned_peer_cert_sha256]
            if tls_config.pinned_peer_cert_sha256
            else None,
            "utls": {
                "enabled": bool(fingerprint) or tls_config.tls == "reality",
                "fingerprint": fingerprint,
            }
            if fingerprint or tls_config.tls == "reality"
            else None,
            "alpn": tls_config.alpn_singbox,  # Pre-formatted for sing-box!
            "ech": {
                "enabled": True,
                "config": ech_config,
                # query_server_name was introduced in sing-box 1.13.0. Subscription
                # output is not version-targeted, so configured hosts require 1.13+.
                "query_server_name": tls_config.sing_box_ech_query_server_name,
            }
            if ech_enabled
            else None,
            "reality": {
                "enabled": tls_config.tls == "reality",
                "public_key": tls_config.reality_public_key,
                "short_id": tls_config.reality_short_id,
            }
            if tls_config.tls == "reality"
            else None,
        }

        # Fragment settings (from inbound, not TLS) - sing-box embeds in TLS config
        if fragment_settings and (singbox_fragment := fragment_settings.get("sing_box")):
            config.update(singbox_fragment)

        return self._normalize_and_remove_none_values(config)

    @staticmethod
    def _format_ech_config(ech_config: str | None) -> list[str] | None:
        """Convert a base64 or PEM ECH config to sing-box's PEM line-array format."""
        if not ech_config or not (raw_config := ech_config.strip()):
            return None

        if raw_config.startswith("-----BEGIN"):
            return raw_config.splitlines()

        return ["-----BEGIN ECH CONFIGS-----", raw_config, "-----END ECH CONFIGS-----"]

    # ========== Protocol Builders ==========

    def _build_vmess(self, remark: str, address: str, inbound: SubscriptionInboundData, settings: dict) -> dict:
        """Build VMess outbound"""
        return self._build_outbound(
            protocol_type="vmess",
            remark=remark,
            address=address,
            inbound=inbound,
            user_settings={"uuid": str(settings["id"]), "alter_id": 0},
        )

    def _build_vless(self, remark: str, address: str, inbound: SubscriptionInboundData, settings: dict) -> dict:
        """Build VLESS outbound"""
        # Handle vless-route if needed (only affects ID)
        id = str(settings["id"])
        if inbound.vless_route:
            id = self.vless_route(id, inbound.vless_route)
        user_settings = {"uuid": id}

        if flow := inbound.inbound_flow:
            user_settings["flow"] = flow

        return self._build_outbound(
            protocol_type="vless",
            remark=remark,
            address=address,
            inbound=inbound,
            user_settings=user_settings,
        )

    def _build_trojan(self, remark: str, address: str, inbound: SubscriptionInboundData, settings: dict) -> dict:
        """Build Trojan outbound"""
        return self._build_outbound(
            protocol_type="trojan",
            remark=remark,
            address=address,
            inbound=inbound,
            user_settings={"password": settings["password"]},
        )

    def _build_shadowsocks(self, remark: str, address: str, inbound: SubscriptionInboundData, settings: dict) -> dict:
        """Build Shadowsocks outbound"""
        method, password = self.detect_shadowsocks_2022(
            inbound.is_2022,
            inbound.method,
            settings["method"],
            getattr(inbound, "password", None),
            settings["password"],
        )

        config = {
            "type": "shadowsocks",
            "tag": remark,
            "server": address,
            "server_port": self._select_port(inbound.port),
            "method": method,
            "password": password,
        }

        return self._normalize_and_remove_none_values(config)

    def _build_hysteria(self, remark: str, address: str, inbound: SubscriptionInboundData, settings: dict) -> dict:
        """Build Hysteria outbound"""
        pattern = r"(\d+(?:\.\d+)?)"

        config = {
            "type": "hysteria2",
            "tag": remark,
            "server": address,
            "server_port": self._select_port(inbound.port),
            "password": settings["auth"],
        }
        obfs_password, quic_params = self._get_hysteria_data_from_finalmask(inbound.finalmask)
        if obfs_password:
            config["obfs"] = {
                "type": "salamander",
                "password": obfs_password,
            }
        udp_hop = quic_params.get("udpHop") or {}
        hop_ports = udp_hop.get("ports")
        if hop_ports:
            config["server_ports"] = [hop_ports] if isinstance(hop_ports, str) else hop_ports
            # 2026-10-30: sing-box 端口段写法是 "20000:29999", 写成 "-" 会让整份配置 FATAL(bad port range)。
            config["server_ports"] = [str(x).replace("-", ":") for x in config["server_ports"]]
        hop_iv = udp_hop.get("hopInterval") or udp_hop.get("interval")
        if hop_iv:
            hop_iv = str(hop_iv).rstrip("s")
            config["hop_interval"] = f"{hop_iv}s"
        hop_max = udp_hop.get("hopIntervalMax") or udp_hop.get("hop_interval_max")
        if hop_max:
            hop_max = str(hop_max).rstrip("s")
            config["hop_interval_max"] = f"{hop_max}s"
        bbr_profile = quic_params.get("bbrProfile") or quic_params.get("bbr_profile")
        if bbr_profile:
            config["bbr_profile"] = bbr_profile
        config["brutal_debug"] = quic_params.get("debug", False)
        up = re.search(pattern, str(quic_params.get("brutalUp")))
        down = re.search(pattern, str(quic_params.get("brutalDown")))
        config["up_mbps"] = up.group(1) if up else None
        config["down_mbps"] = down.group(1) if down else None

        # Add TLS
        if inbound.tls_config.tls in ("tls", "reality"):
            config["tls"] = self._apply_tls(inbound.tls_config, inbound.fragment_settings)
            # 2026-10-30: sing-box 的 QUIC 不支持 uTLS(运行时报 unsupported usage for uTLS, 节点不可用), hysteria2 去掉 utls。
            config["tls"].pop("utls", None)

        return self._normalize_and_remove_none_values(config)

    def _build_wireguard(
        self, remark: str, address: str, inbound: SubscriptionInboundData, settings: dict
    ) -> dict | None:
        """Build WireGuard endpoint for sing-box subscriptions (replaces deprecated outbound)."""
        private_key = settings.get("private_key", "")
        peer_ips = list(settings.get("peer_ips") or [])
        public_key = inbound.wireguard_public_key
        if not private_key or not peer_ips or not public_key:
            return None

        selected_port = self._select_port(inbound.port)
        allowed_ips = inbound.wireguard_allowed_ips or ["0.0.0.0/0", "::/0"]
        reserved = self._parse_wireguard_reserved(inbound.wireguard_reserved)

        peer = {
            "address": address,
            "port": selected_port,
            "public_key": public_key,
            "pre_shared_key": inbound.wireguard_pre_shared_key or None,
            "allowed_ips": allowed_ips,
            "persistent_keepalive_interval": inbound.wireguard_keepalive,
            "reserved": reserved,
        }

        endpoint = {
            "type": "wireguard",
            "tag": remark,
            "system": True,
            "name": "wg0",
            "mtu": inbound.wireguard_mtu,
            "address": peer_ips,
            "private_key": private_key,
            "peers": [self._normalize_and_remove_none_values(peer)],
        }

        return self._normalize_and_remove_none_values(endpoint)

    def _build_outbound(
        self,
        protocol_type: str,
        remark: str,
        address: str,
        inbound: SubscriptionInboundData,
        user_settings: dict,
    ) -> dict:
        """Generic outbound builder"""
        network = inbound.network
        path = inbound.transport_config.path

        # Process GRPC path
        if network in ("grpc", "gun"):
            path = self.get_grpc_gun(path)

        # Map network aliases
        if network == "h2":
            network = "http"
            # Override ALPN for h2
            inbound.tls_config.alpn_list = ["h2"]
        elif network == "h3":
            network = "http"
            inbound.tls_config.alpn_list = ["h3"]

        config = {
            "type": protocol_type,
            "tag": remark,
            "server": address,
            "server_port": self._select_port(inbound.port),
            **user_settings,
        }

        # Add transport
        if network in ("http", "tcp", "raw", "ws", "quic", "grpc", "httpupgrade", "h2", "h3"):
            transport = self._apply_transport(network, inbound, path)
            if transport:
                config["transport"] = transport

        # Add TLS
        if inbound.tls_config.tls in ("tls", "reality"):
            config["tls"] = self._apply_tls(inbound.tls_config, inbound.fragment_settings)

        # Add mux
        if inbound.mux_settings and (singbox_mux := inbound.mux_settings.get("sing_box")) and singbox_mux.get("enable"):
            # Filter out the enable field as it's not part of singbox multiplex config
            multiplex_config = {k: v for k, v in singbox_mux.items() if k != "enable"}

            # Add enabled: true to multiplex config
            multiplex_config["enabled"] = True

            # Handle brutal configuration - only include if brutal.enable is True
            if "brutal" in multiplex_config:
                brutal_config = multiplex_config["brutal"]
                if brutal_config and brutal_config.get("enable"):
                    # Add enabled: true to brutal config
                    multiplex_config["brutal"] = {
                        "enabled": True,
                        **{k: v for k, v in brutal_config.items() if k != "enable"},
                    }
                else:
                    # Remove brutal config entirely if enable is False or brutal is None
                    multiplex_config.pop("brutal", None)

            multiplex_config = self._normalize_and_remove_none_values(multiplex_config)
            config["multiplex"] = multiplex_config

        return self._normalize_and_remove_none_values(config)

    def _select_port(self, port: int | str) -> int:
        """Select a random port if multiple are provided"""
        if isinstance(port, str):
            ports = port.split(",")
            return int(choice(ports))
        return port

    @staticmethod
    def _parse_wireguard_reserved(reserved: str | None) -> list[int] | None:
        """Parse WireGuard reserved bytes from common persisted string formats."""
        if not reserved:
            return None

        raw = reserved.strip()
        if not raw:
            return None

        if raw.startswith("[") and raw.endswith("]"):
            raw = raw[1:-1]

        values: list[int] = []
        for part in raw.split(","):
            piece = part.strip()
            if not piece:
                continue
            try:
                values.append(int(piece))
            except ValueError:
                return None

        return values or None
