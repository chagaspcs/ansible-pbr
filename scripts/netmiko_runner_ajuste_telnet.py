#!/usr/bin/env python3
"""
netmiko_runner.py
- Connects to Cisco IOS devices via TELNET using Netmiko
- Implements central_v200 flow with:
  * Pre-checks executed from switches (NOT from the router)
  * Per-block atomic apply + sanity + post-checks + rollback
  * Dry-run support (--dry-run): runs pre-checks and shows planned commands without applying

Hostvars expected (host_vars/R_CENTRAL_X.yml):
  blocks:
    - name: "bloco1" (optional)
      v200_source_ip: "10.115.92.1"
      sw_local: "10.115.92.4"
      mux_local: ["10.115.92.5","10.115.92.6","10.115.92.7","10.115.92.8"]
      sw_remoto: ["10.115.94.2","10.115.94.10","10.115.94.18","10.115.94.26"]
      mux_remoto:["10.115.94.3","10.115.94.11","10.115.94.19","10.115.94.27"]
      aruba_remoto:["10.115.87.6","10.115.87.14","10.115.87.30","10.115.87.46"]
      acl_tags: ["v200_aa","v200_be","v200_bv","v200_cz"]   # optional (generated if missing)
    - ...

Common defaults are loaded automatically from group_vars/central_routers.yml (relative to repo root),
and are overridden by hostvars if hostvars define same keys.

CLI credentials (--username/--password) are used for ALL devices (router + switches).

Patch notes (2026-03-05):
- Hardening TELNET session preparation for IOS/C2960/C2921 that often drop the connection during
  terminal-width negotiation:
  * disable_auto_terminal_width=True
  * disable_auto_prompt_reset=True
  * global_delay_factor bumped, fast_cli disabled
  * retry-on-EOFError during ConnectHandler()
"""

import argparse
import ipaddress
import json
import re
import sys
import time
import importlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

_STABLE_DT_NAME = "cisco_ios_telnet_stablelogin"

# ----------------------------
# Models / utilities
# ----------------------------
@dataclass
class Result:
    ok: bool
    hostname: str
    where_failed: Optional[str] = None
    details: Optional[str] = None
    rollback_attempted: bool = False
    rollback_ok: Optional[bool] = None
    planned_commands: Optional[List[str]] = None

    # resumo operacional
    sites_total: int = 0
    sites_changed: int = 0
    sites_skipped: int = 0
    sites_failed: int = 0


def _now_tag() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s or "UNKNOWN")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="ignore")


def _write_json(path: Path, payload: Any) -> None:
    _write_text(path, json.dumps(payload, indent=2, ensure_ascii=False))


def _mklogbase(logs_dir: Path, label: str, ip: str) -> Path:
    tag = _now_tag()
    base = logs_dir / f"{_sanitize_filename(label)}_{_sanitize_filename(ip)}_{tag}"
    base.parent.mkdir(parents=True, exist_ok=True)
    return base


def _parse_hostname_from_prompt(prompt: str) -> str:
    # "R1#", "R1(config)#", "SW1>"
    m = re.match(r"^([A-Za-z0-9_.-]+)", (prompt or "").strip())
    return m.group(1) if m else "UNKNOWN"


# ----------------------------
# Netmiko helpers
# ----------------------------
def _register_ios_telnet_stable_device_type() -> str:
    sd = importlib.import_module("netmiko.ssh_dispatcher")

    # Já registrado?
    class_mapper = getattr(sd, "CLASS_MAPPER", None)
    if isinstance(class_mapper, dict) and _STABLE_DT_NAME in class_mapper:
        return _STABLE_DT_NAME

    base_cls = None
    if isinstance(class_mapper, dict):
        base_cls = class_mapper.get("cisco_ios_telnet")

    # Se não der pra pegar a classe base (Netmiko muito diferente), não tenta registrar.
    if base_cls is None:
        return "cisco_ios_telnet"

    class StableCiscoIosTelnet(base_cls):

        def telnet_login(  # type: ignore[override]
            self,
            pri_prompt_terminator=r"#",
            alt_prompt_terminator=r">",
            username_pattern=r"(?:username|login)\s*:",
            pwd_pattern=r"password\s*:",
            delay_factor=1,
            max_loops=60,
        ):
            # max_loops * (sleep) controla quanto tempo espera o banner/login aparecer
            # Ajuste fino: com links lentos, melhor várias esperas curtas do que um sleep gigante.
            user_re = re.compile(username_pattern, re.I)
            pass_re = re.compile(pwd_pattern, re.I)

            output = ""
            # 1) Espera aparecer Username/Login (varrendo banner)
            for _ in range(max_loops):
                try:
                    chunk = self.read_channel()
                except Exception:
                    chunk = ""
                if chunk:
                    output += chunk
                    if user_re.search(output):
                        break
                    # Se já apareceu Password direto (alguns devices pulam user), sai também
                    if pass_re.search(output):
                        break

                time.sleep(0.4 * delay_factor)

            if not (user_re.search(output) or pass_re.search(output)):
                raise NetmikoTimeoutException(
                    f"TELNET: não apareceu prompt de login em {self.host}. Último output: {output[-400:]}"
                )

            # 2) Se pediu usuário, envia usuário e espera password
            if user_re.search(output):
                self.write_channel(self.username + self.RETURN)
                output = ""

                for _ in range(max_loops):
                    chunk = self.read_channel()
                    if chunk:
                        output += chunk
                        if pass_re.search(output):
                            break
                    time.sleep(0.4 * delay_factor)

                if not pass_re.search(output):
                    raise NetmikoTimeoutException(
                        f"TELNET: não apareceu Password: após Username em {self.host}. Último output: {output[-400:]}"
                    )

            # 3) Envia senha e espera prompt
            self.write_channel(self.password + self.RETURN)

            output = ""
            prompt_re = re.compile(rf"({pri_prompt_terminator}|{alt_prompt_terminator})\s*$")

            for _ in range(max_loops):
                chunk = self.read_channel()
                if chunk:
                    output += chunk

                    # detecta erros comuns
                    if re.search(r"password\s+incorrect", output, re.I):
                        raise NetmikoAuthenticationException(f"Login failed: {self.host} (password incorrect)")
                    if re.search(r"password change dialog", output, re.I):
                        raise NetmikoAuthenticationException(
                            f"Login failed: {self.host} (entrou em password change dialog)"
                        )

                    if prompt_re.search(output.strip()):
                        # login OK
                        return output

                time.sleep(0.4 * delay_factor)

            raise NetmikoTimeoutException(
                f"TELNET: não obtive prompt após senha em {self.host}. Último output: {output[-400:]}"
            )

    # Registra no CLASS_MAPPER
    sd.CLASS_MAPPER[_STABLE_DT_NAME] = StableCiscoIosTelnet
    return _STABLE_DT_NAME

def _connect_ios_telnet(
    host: str,
    username: str,
    password: str,
    timeout: int = 30,
    session_log: Optional[Path] = None,
    retries: int = 3,
) -> ConnectHandler:
    """
    TELNET robusto sem session_preparation automático do cisco_ios_telnet.

    Estratégia:
    - usa generic_telnet
    - espera Username:/Password:
    - só considera conectado quando aparece prompt > ou #
    - só então envia 'terminal length 0'
    """

    base_device: Dict[str, Any] = {
        "device_type": "generic_telnet",
        "host": host,
        "username": username,
        "password": password,
        "timeout": max(timeout, 60),
        "banner_timeout": max(timeout, 60),
        "auth_timeout": max(timeout, 60),
        "conn_timeout": max(timeout, 60),
        "global_delay_factor": 2,
        "fast_cli": False,
    }

    if session_log:
        session_log.parent.mkdir(parents=True, exist_ok=True)
        base_device["session_log"] = str(session_log)

    last_exc: Optional[BaseException] = None

    for attempt in range(1, retries + 1):
        dev = dict(base_device)

        if attempt == 2:
            dev["global_delay_factor"] = 4
            dev["timeout"] = dev["banner_timeout"] = dev["auth_timeout"] = dev["conn_timeout"] = 90
        elif attempt >= 3:
            dev["global_delay_factor"] = 6
            dev["timeout"] = dev["banner_timeout"] = dev["auth_timeout"] = dev["conn_timeout"] = 120

        conn = None
        try:
            conn = ConnectHandler(**dev)

            # -------------------------
            # login manual
            # -------------------------
            output = ""
            got_prompt = False

            for _ in range(60):
                chunk = conn.read_channel()
                if chunk:
                    output += chunk

                    if re.search(r"Username:|login:", output, re.I):
                        conn.write_channel(username + "\n")
                        output = ""
                        time.sleep(1.0)
                        continue

                    if re.search(r"Password:", output, re.I):
                        conn.write_channel(password + "\n")
                        output = ""
                        time.sleep(1.0)
                        continue

                    if re.search(r"[>#]\s*$", output, re.M):
                        got_prompt = True
                        break

                    if re.search(r"Password incorrect", output, re.I):
                        raise NetmikoAuthenticationException(f"Login failed: {host}")

                    if re.search(r"Entering password change dialog|Old password:", output, re.I):
                        raise NetmikoAuthenticationException(
                            f"Login failed: {host} (entered password change dialog)"
                        )

                time.sleep(0.5)

            if not got_prompt:
                raise NetmikoTimeoutException(f"Prompt not detected after login on {host}")

            # -------------------------
            # estabiliza o prompt
            # -------------------------
            time.sleep(1.0)

            # se estiver em ">", sobe para enable se necessário
            prompt = conn.find_prompt()
            if prompt.strip().endswith(">"):
                conn.write_channel("enable\n")
                time.sleep(1.0)

                out2 = ""
                for _ in range(20):
                    chunk = conn.read_channel()
                    if chunk:
                        out2 += chunk
                        if re.search(r"Password:", out2, re.I):
                            conn.write_channel(password + "\n")
                            out2 = ""
                            time.sleep(1.0)
                            continue
                        if re.search(r"#\s*$", out2, re.M):
                            break
                    time.sleep(0.5)

            # -------------------------
            # só agora ajusta terminal
            # -------------------------
            try:
                conn.write_channel("terminal length 0\n")
                time.sleep(1.0)
                _ = conn.read_channel()
            except Exception:
                pass

            return conn

        except (EOFError, NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            last_exc = e
            try:
                if conn:
                    conn.disconnect()
            except Exception:
                pass
            time.sleep(1.0 + attempt)
            continue

        except Exception as e:
            last_exc = e
            try:
                if conn:
                    conn.disconnect()
            except Exception:
                pass
            break

    raise RuntimeError(f"TELNET connect failed to {host}: {last_exc}")




### código correto ###


def _safe_disconnect(conn: Optional[ConnectHandler]) -> None:
    try:
        if conn:
            conn.disconnect()
    except Exception:
        pass


def _send_exec(conn: ConnectHandler, cmd: str, expect: str = r"[#>]", delay: float = 0.0) -> str:
    out = conn.send_command(cmd, expect_string=expect, strip_prompt=False, strip_command=False)
    if delay:
        time.sleep(delay)
    return out


def _send_cfg(conn: ConnectHandler, cmds: List[str]) -> str:
    # send_config_set already enters config mode and exits
    return conn.send_config_set(cmds)


def _copy_run_to_flash(conn: ConnectHandler, flash_filename: str) -> str:
    cmd = f"copy running-config flash:{flash_filename}"
    out = conn.send_command_timing(cmd, strip_prompt=False, strip_command=False)
    if "Destination filename" in out or "destination filename" in out.lower():
        out += conn.send_command_timing("\n", strip_prompt=False, strip_command=False)
    if "[confirm]" in out.lower():
        out += conn.send_command_timing("\n", strip_prompt=False, strip_command=False)
    return out


def _configure_replace(conn: ConnectHandler, flash_filename: str) -> str:
    cmd = f"configure replace flash:{flash_filename} force"
    out = conn.send_command_timing(cmd, strip_prompt=False, strip_command=False)
    if "[confirm]" in out.lower():
        out += conn.send_command_timing("\n", strip_prompt=False, strip_command=False)
    return out


# ----------------------------
# Ping parsing
# ----------------------------

def _parse_ping(out: str) -> Tuple[bool, Optional[float]]:
    """Returns (ok, avg_ms)

    ok: success rate >= 40%
    avg_ms: parsed from "min/avg/max = a/b/c ms"
    """

    m_succ = re.search(r"Success +rate +is +(?P<pct>\d+) +percent", out, re.I)
    succ_ok = bool(m_succ and int(m_succ.group("pct")) >= 40)

    m_rtt = re.search(r"min/avg/max += +(?P<min>\d+)/(?P<avg>\d+)/(?P<max>\d+) +ms", out, re.I)
    avg = float(m_rtt.group("avg")) if m_rtt else None
    return succ_ok, avg


def _ping(conn: ConnectHandler, dst_ip: str, repeat: int = 5) -> Tuple[bool, Optional[float], str]:
    cmd = f"ping {dst_ip} repeat {repeat}"
    out = _send_exec(conn, cmd, expect=r"[#>]", delay=0.0)
    ok, avg = _parse_ping(out)
    return ok, avg, out


# ----------------------------
# v200 command builder (per block)
# ----------------------------

def _net_base_for_29(ip_str: str) -> str:
    net = ipaddress.ip_network(f"{ip_str}/29", strict=False)
    return str(net.network_address)


def _gen_acl_tag(block_idx: int, i: int) -> str:
    return f"v200_b{block_idx + 1}_{i + 1:02d}"


def _build_v200_block_commands(
    block: Dict[str, Any],
    route_map_name: str,
    next_hop_ip: str,
    apply_interfaces: List[str],
    set_pref_mode: str,
) -> List[str]:
    """Builds commands for one block.

    Regra correta para o central:
    - cada ACL/tag vira uma sequência própria do route-map
    - seq 10, 20, 30, 40...
    - cada sequência tem:
        match ip address <acl_tag>
        set ip next-hop verify-availability <next_hop_ip> 1 track <sla_id>
    """

    sw_remotos: List[str] = block["sw_remoto"]
    arubas: List[str] = block["aruba_remoto"]
    origin_ip: str = block["v200_source_ip"]

    if len(sw_remotos) != len(arubas):
        raise ValueError("sw_remoto and aruba_remoto must have same length in block")

    acl_tags: List[str] = block.get("acl_tags") or [
        _gen_acl_tag(block.get("_block_idx", 0), i) for i in range(len(sw_remotos))
    ]

    if len(acl_tags) != len(sw_remotos):
        raise ValueError("acl_tags must match sw_remoto length")

    cmds: List[str] = []

    # ACLs
    for i, swip in enumerate(sw_remotos):
        net_base = _net_base_for_29(swip)
        tag = acl_tags[i]
        cmds += [
            f"ip access-list extended {tag}",
            f" permit ip any {net_base} 0.0.0.7",
            "exit",
        ]

    # SLA + track (IDs from last octet of aruba IP)
    for i, aruba_ip in enumerate(arubas):
        sla_id = int(aruba_ip.strip().split(".")[-1])
        tag = acl_tags[i]
        cmds += [
            f"ip sla {sla_id}",
            f" icmp-echo {aruba_ip} source-ip {origin_ip}",
            f" tag {tag}",
            " frequency 5",
            "exit",
            f"ip sla schedule {sla_id} life forever start-time now",
            f"ip sla reaction-configuration {sla_id} react rtt threshold-type immediate threshold-value 500 100 action-type triggerOnly",
            f"track {sla_id} ip sla {sla_id} state",
            " delay down 2 up 10",
            "exit",
        ]

    # route-map correto: uma sequência por ACL/tag
    for i, aruba_ip in enumerate(arubas):
        sla_id = int(aruba_ip.strip().split(".")[-1])
        tag = acl_tags[i]
        seq = (i + 1) * 10

        cmds += [
            f"route-map {route_map_name} permit {seq}",
            f" match ip address {tag}",
            f" set ip next-hop verify-availability {next_hop_ip} 1 track {sla_id}",
            "exit",
        ]

    # apply policy
    for intf in apply_interfaces:
        cmds += [
            f"interface {intf}",
            f" ip policy route-map {route_map_name}",
            "exit",
        ]

    return cmds



# ----------------------------
# Sanity / validation helpers
# ----------------------------

def _sanity_router_structural(conn: ConnectHandler, route_map_name: str, sla_ids: List[int]) -> Dict[str, Any]:
    """Structural/state sanity on router."""

    res: Dict[str, Any] = {}
    try:
        res["route_map"] = _send_exec(conn, f"show route-map {route_map_name}")
    except Exception as e:
        res["route_map_error"] = str(e)

    try:
        res["ip_sla_summary"] = _send_exec(conn, "show ip sla summary")
    except Exception as e:
        res["ip_sla_summary_error"] = str(e)

    try:
        res["track_brief"] = _send_exec(conn, "show track brief")
    except Exception as e:
        res["track_brief_error"] = str(e)

    missing = []
    summary = res.get("ip_sla_summary", "")
    for sid in sla_ids:
        if re.search(rf"\b{sid}\b", summary) is None:
            missing.append(sid)
    res["missing_sla_ids_in_summary"] = missing
    return res


# ----------------------------
# Main flow: central_v200
# ----------------------------

def run_central_v200(
    router_host: str,
    username: str,
    password: str,
    hv: Dict[str, Any],
    gv: Dict[str, Any],
    logs_dir: Path,
    dry_run: bool,
) -> Result:
    base = _mklogbase(logs_dir, label=f"central_v200_{hv.get('inventory_hostname','R_CENTRAL')}", ip=router_host)
    sessionlog_router = base.with_suffix(".router.session.log")

    route_map_name = hv.get("route_map_name", gv.get("route_map_name", "v200_to_s2s"))
    next_hop_ip = hv.get("next_hop_ip", gv.get("next_hop_ip", "10.112.80.201"))
    apply_interfaces = hv.get("apply_interfaces", gv.get("apply_interfaces", ["GigabitEthernet0/0", "GigabitEthernet0/1"]))
    set_pref_mode = hv.get("set_pref_mode", gv.get("set_pref_mode", "all_1"))

    phase2_target_ip = hv.get("phase2_target_ip", gv.get("phase2_target_ip", "10.112.82.215"))

    pre_p1_th = int(hv.get("pre_phase1_rtt_ok_ms", gv.get("pre_phase1_rtt_ok_ms", 1200)))
    pre_p1_rep = int(hv.get("pre_phase1_repeat", gv.get("pre_phase1_repeat", 5)))
    pre_p2_th = int(hv.get("pre_phase2_rtt_ok_ms", gv.get("pre_phase2_rtt_ok_ms", 1200)))
    pre_p2_rep = int(hv.get("pre_phase2_repeat", gv.get("pre_phase2_repeat", 5)))

    post_p1_th = int(hv.get("post_phase1_rtt_ok_ms", gv.get("post_phase1_rtt_ok_ms", 1200)))
    post_p1_rep = int(hv.get("post_phase1_repeat", gv.get("post_phase1_repeat", 5)))
    post_p2_th = int(hv.get("post_phase2_rtt_ok_ms", gv.get("post_phase2_rtt_ok_ms", 1200)))
    post_p2_rep = int(hv.get("post_phase2_repeat", gv.get("post_phase2_repeat", 5)))

    blocks: List[Dict[str, Any]] = hv.get("blocks") or []
    if not blocks:
        return Result(ok=False, hostname="UNKNOWN", where_failed="hostvars_schema", details="Missing 'blocks' in hostvars")

    for i, b in enumerate(blocks):
        b["_block_idx"] = i

    where = "precheck"
    pre_report: Dict[str, Any] = {"blocks": []}

    def _fail_pre(msg: str) -> Result:
        _write_json(base.with_suffix(".precheck_report.json"), pre_report)
        return Result(ok=False, hostname="UNKNOWN", where_failed=where, details=msg)

    # ---- PRECHECKS (all blocks) ----
    for bi, b in enumerate(blocks):
        bname = b.get("name") or f"bloco{bi+1}"
        block_entry: Dict[str, Any] = {"name": bname, "phase1": [], "phase2": []}

        # Phase 1: sw_local -> each aruba_remoto
        sw_local_ip = b["sw_local"]
        s1log = base.with_suffix(f".{bname}.sw_local.session.log")
        conn_sw_local = None
        try:
            conn_sw_local = _connect_ios_telnet(sw_local_ip, username, password, timeout=30, session_log=s1log)
            for aruba_ip in b["aruba_remoto"]:
                ok, avg, raw = _ping(conn_sw_local, aruba_ip, repeat=pre_p1_rep)
                block_entry["phase1"].append({"from": sw_local_ip, "to": aruba_ip, "ok": ok, "avg_ms": avg, "raw": raw})
                if (not ok) or (avg is not None and avg >= pre_p1_th) or (avg is None):
                    _write_text(base.with_suffix(f".{bname}.pre_phase1_fail.txt"), raw)
                    pre_report["blocks"].append(block_entry)
                    return _fail_pre(f"Fase1 falhou: {sw_local_ip} -> {aruba_ip} avg={avg} th={pre_p1_th}")
        finally:
            _safe_disconnect(conn_sw_local)

        # Phase 2: each sw_remoto -> core
        for swr_ip in b["sw_remoto"]:
            s2log = base.with_suffix(f".{bname}.sw_remoto_{_sanitize_filename(swr_ip)}.session.log")
            conn_sw_r = None
            try:
                conn_sw_r = _connect_ios_telnet(swr_ip, username, password, timeout=30, session_log=s2log)
                ok, avg, raw = _ping(conn_sw_r, phase2_target_ip, repeat=pre_p2_rep)
                block_entry["phase2"].append({"from": swr_ip, "to": phase2_target_ip, "ok": ok, "avg_ms": avg, "raw": raw})
                if (not ok) or (avg is not None and avg >= pre_p2_th) or (avg is None):
                    _write_text(base.with_suffix(f".{bname}.pre_phase2_fail.txt"), raw)
                    pre_report["blocks"].append(block_entry)
                    return _fail_pre(f"Fase2 falhou: {swr_ip} -> {phase2_target_ip} avg={avg} th={pre_p2_th}")
            finally:
                _safe_disconnect(conn_sw_r)

        pre_report["blocks"].append(block_entry)

    _write_json(base.with_suffix(".precheck_report.json"), pre_report)

    # ---- Router connect and apply per block ----
    where = "connect_router"
    conn_router = None
    try:
        conn_router = _connect_ios_telnet(router_host, username, password, timeout=45, session_log=sessionlog_router)
        hostname = _parse_hostname_from_prompt(conn_router.find_prompt())

        planned_all: List[str] = []
        apply_report: Dict[str, Any] = {"router": router_host, "hostname": hostname, "blocks": []}

        for bi, b in enumerate(blocks):
            bname = b.get("name") or f"bloco{bi+1}"
            block_apply: Dict[str, Any] = {"name": bname}

            cmds = _build_v200_block_commands(
                block=b,
                route_map_name=route_map_name,
                next_hop_ip=next_hop_ip,
                apply_interfaces=apply_interfaces,
                set_pref_mode=set_pref_mode,
            )
            planned_all.extend(cmds)
            block_apply["planned_count"] = len(cmds)

            if dry_run:
                block_apply["applied"] = False
                apply_report["blocks"].append(block_apply)
                continue

            where = f"{bname}.snapshot"
            snap_name = f"pre_{hostname}_{bname}_{_now_tag()}.cfg"
            snap_out = _copy_run_to_flash(conn_router, snap_name)
            _write_text(base.with_suffix(f".{bname}.snapshot.txt"), snap_out)
            block_apply["snapshot"] = snap_name

            where = f"{bname}.apply_config"
            out_cfg = _send_cfg(conn_router, cmds)
            _write_text(base.with_suffix(f".{bname}.apply.txt"), out_cfg)
            block_apply["applied"] = True

            where = f"{bname}.sanity"
            sla_ids = [int(ip.split(".")[-1]) for ip in b["aruba_remoto"]]
            sanity = _sanity_router_structural(conn_router, route_map_name, sla_ids)
            _write_json(base.with_suffix(f".{bname}.sanity.json"), sanity)
            if sanity.get("missing_sla_ids_in_summary"):
                where = f"{bname}.rollback_missing_sla"
                rb_out = _configure_replace(conn_router, snap_name)
                _write_text(base.with_suffix(f".{bname}.rollback.txt"), rb_out)
                _write_json(base.with_suffix(".apply_report.json"), apply_report)
                return Result(
                    ok=False,
                    hostname=hostname,
                    where_failed=where,
                    details=f"Sanity falhou (SLA ausente): {sanity.get('missing_sla_ids_in_summary')}",
                    rollback_attempted=True,
                    rollback_ok=True,
                )

            where = f"{bname}.postcheck"
            post: Dict[str, Any] = {"post_phase1": [], "post_phase2": []}

            # Post 1: sw_local -> mux_remoto
            sw_local_ip = b["sw_local"]
            conn_sw_local = None
            try:
                conn_sw_local = _connect_ios_telnet(
                    sw_local_ip,
                    username,
                    password,
                    timeout=30,
                    session_log=base.with_suffix(f".{bname}.post.sw_local.session.log"),
                )
                for muxr in b["mux_remoto"]:
                    ok, avg, raw = _ping(conn_sw_local, muxr, repeat=post_p1_rep)
                    post["post_phase1"].append({"from": sw_local_ip, "to": muxr, "ok": ok, "avg_ms": avg, "raw": raw})
                    if (not ok) or (avg is not None and avg >= post_p1_th) or (avg is None):
                        _write_text(base.with_suffix(f".{bname}.post_phase1_fail.txt"), raw)
                        rb_out = _configure_replace(conn_router, snap_name)
                        _write_text(base.with_suffix(f".{bname}.rollback.txt"), rb_out)
                        _write_json(base.with_suffix(f".{bname}.postcheck.json"), post)
                        _write_json(base.with_suffix(".apply_report.json"), apply_report)
                        return Result(
                            ok=False,
                            hostname=hostname,
                            where_failed=where,
                            details=f"Pós1 falhou: {sw_local_ip} -> {muxr} avg={avg} th={post_p1_th}",
                            rollback_attempted=True,
                            rollback_ok=True,
                        )
            finally:
                _safe_disconnect(conn_sw_local)

            # Post 2: sw_remoto -> mux_local (1:1)
            if len(b["sw_remoto"]) != len(b["mux_local"]):
                rb_out = _configure_replace(conn_router, snap_name)
                _write_text(base.with_suffix(f".{bname}.rollback.txt"), rb_out)
                return Result(
                    ok=False,
                    hostname=hostname,
                    where_failed=where,
                    details="sw_remoto and mux_local length mismatch; rollback executed",
                    rollback_attempted=True,
                    rollback_ok=True,
                )

            for i, swr in enumerate(b["sw_remoto"]):
                muxt = b["mux_local"][i]
                conn_sw_r = None
                try:
                    conn_sw_r = _connect_ios_telnet(
                        swr,
                        username,
                        password,
                        timeout=30,
                        session_log=base.with_suffix(f".{bname}.post.sw_remoto_{_sanitize_filename(swr)}.session.log"),
                    )
                    ok, avg, raw = _ping(conn_sw_r, muxt, repeat=post_p2_rep)
                    post["post_phase2"].append({"from": swr, "to": muxt, "ok": ok, "avg_ms": avg, "raw": raw})
                    if (not ok) or (avg is not None and avg >= post_p2_th) or (avg is None):
                        _write_text(base.with_suffix(f".{bname}.post_phase2_fail.txt"), raw)
                        rb_out = _configure_replace(conn_router, snap_name)
                        _write_text(base.with_suffix(f".{bname}.rollback.txt"), rb_out)
                        _write_json(base.with_suffix(f".{bname}.postcheck.json"), post)
                        _write_json(base.with_suffix(".apply_report.json"), apply_report)
                        return Result(
                            ok=False,
                            hostname=hostname,
                            where_failed=where,
                            details=f"Pós2 falhou: {swr} -> {muxt} avg={avg} th={post_p2_th}",
                            rollback_attempted=True,
                            rollback_ok=True,
                        )
                finally:
                    _safe_disconnect(conn_sw_r)

            _write_json(base.with_suffix(f".{bname}.postcheck.json"), post)
            apply_report["blocks"].append(block_apply)

        _write_json(base.with_suffix(".apply_report.json"), apply_report)

        return Result(
            ok=True,
            hostname=hostname,
            planned_commands=planned_all if dry_run else None,
        )

    except Exception as e:
        _write_text(base.with_suffix(".exception.txt"), repr(e))
        return Result(ok=False, hostname="UNKNOWN", where_failed="connect_or_runtime", details=str(e))
    finally:
        _safe_disconnect(conn_router)


# ----------------------------
# Operatin in remote sites
# ----------------------------
def run_remote_sites(
    *,
    hv: Dict[str, Any],
    gv: Dict[str, Any],
    logs_dir: Path,
    dry_run: bool,
    username: str,
    password: str,
) -> Result:
    """
    Percorre todos os blocos definidos no host_vars do R_CENTRAL_X e,
    para cada circuito remoto (índice 1:1), executa:

    1. Conecta no roteador_remoto
    2. Verifica default N2 no OSPF 1
    3. Verifica policy route-map sbt aplicada em Gi0/0 ou Gi0/0.2
    4. Se elegível:
       - faz backup
       - SEMPRE reordena os 'set ip next-hop verify-availability' do route-map sbt permit 10
         colocando o Advertising Router atual em primeiro
       - renumera as prioridades (1, 2, 3, ...)
    5. Faz sanity estrutural/estado
    6. Faz testes funcionais:
       - sw_local -> mux_remoto (avg < 250 ms)
       - sw_remoto -> mux_local (avg < 250 ms)
    7. Se qualquer etapa falhar após mudança, rollback
    """

    def parse_verify_line(s: str) -> Optional[Dict[str, Any]]:
        m = re.search(
            r"set ip next-hop verify-availability\s+"
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"(\d+)\s+track\s+(\d+)",
            s
        )
        if not m:
            return None
        return {
            "next_hop": m.group(1),
            "priority": int(m.group(2)),
            "track": int(m.group(3)),
            "raw": s,
        }

    remote_route_map = gv.get("remote_route_map", "sbt")
    remote_route_map_seq = int(gv.get("remote_route_map_seq", 10))
    remote_policy_interfaces = gv.get(
        "remote_policy_interfaces",
        ["GigabitEthernet0/0", "GigabitEthernet0/0.2"]
    )
    remote_test_rtt_ms = int(gv.get("remote_test_rtt_ok_ms", 800))
    remote_test_repeat = int(gv.get("remote_test_repeat", 5))

    blocks: List[Dict[str, Any]] = hv.get("blocks") or []
    if not blocks:
        return Result(
            ok=False,
            hostname="UNKNOWN",
            where_failed="hostvars_schema",
            details="Missing 'blocks' in host_vars",
            sites_total=0,
            sites_changed=0,
            sites_skipped=0,
            sites_failed=0,
        )

    summary: Dict[str, Any] = {"blocks": []}
    hostname_last = "UNKNOWN"

    sites_total = 0
    sites_changed = 0
    sites_skipped = 0
    sites_failed = 0

    for b_idx, block in enumerate(blocks):
        block_name = block.get("name", f"block{b_idx+1}")

        required = [
            "sw_local",
            "mux_local",
            "sw_remoto",
            "mux_remoto",
            "aruba_remoto",
            "roteador_remoto",
        ]
        for key in required:
            if key not in block:
                return Result(
                    ok=False,
                    hostname=hostname_last,
                    where_failed="hostvars_schema",
                    details=f"Block {block_name}: missing key '{key}'",
                    sites_total=sites_total,
                    sites_changed=sites_changed,
                    sites_skipped=sites_skipped,
                    sites_failed=sites_failed,
                )

        count = len(block["roteador_remoto"])
        fields_1to1 = ["mux_local", "sw_remoto", "mux_remoto", "aruba_remoto", "roteador_remoto"]

        for field in fields_1to1:
            if len(block[field]) != count:
                return Result(
                    ok=False,
                    hostname=hostname_last,
                    where_failed="hostvars_schema",
                    details=f"Block {block_name}: field '{field}' length differs from roteador_remoto",
                    sites_total=sites_total,
                    sites_changed=sites_changed,
                    sites_skipped=sites_skipped,
                    sites_failed=sites_failed,
                )

        block_report = {"name": block_name, "sites": []}

        for i in range(count):
            sites_total += 1

            site = {
                "sw_local": block["sw_local"],
                "mux_local": block["mux_local"][i],
                "sw_remoto": block["sw_remoto"][i],
                "mux_remoto": block["mux_remoto"][i],
                "aruba_remoto": block["aruba_remoto"][i],
                "roteador_remoto": block["roteador_remoto"][i],
            }

            rr_ip = site["roteador_remoto"]
            base = _mklogbase(
                logs_dir,
                label=f"remote_{block_name}_{rr_ip}",
                ip=rr_ip,
            )

            site_report: Dict[str, Any] = {"site": site}
            conn_rr = None
            where = "connect_remote_router"

            try:
                # 1) conectar no roteador remoto
                conn_rr = _connect_ios_telnet(
                    rr_ip,
                    username,
                    password,
                    timeout=30,
                    session_log=base.with_suffix(".router.session.log"),
                )
                hostname_last = _parse_hostname_from_prompt(conn_rr.find_prompt())
                site_report["hostname"] = hostname_last

                # 2) verificar default N2
                where = "check_default_n2"
                out_n2 = _send_exec(conn_rr, "show ip ospf 1 database nssa-external 0.0.0.0")
                _write_text(base.with_suffix(".show_ospf_n2.txt"), out_n2)

                m_adv = re.search(r"Advertising Router:\s+(\d+\.\d+\.\d+\.\d+)", out_n2)
                if not m_adv:
                    site_report["status"] = "n2_missing"
                    site_report["error"] = "Advertising Router not found in NSSA default"
                    block_report["sites"].append(site_report)
                    _write_json(base.with_suffix(".result.json"), site_report)
                    sites_skipped += 1
                    continue

                advertising_router = m_adv.group(1)
                site_report["advertising_router"] = advertising_router

                if not (
                    advertising_router.startswith("10.115.87.")
                    or advertising_router.startswith("10.115.88.")
                ):
                    site_report["status"] = "n2_invalid"
                    site_report["error"] = f"Advertising Router {advertising_router} not in expected ranges"
                    block_report["sites"].append(site_report)
                    _write_json(base.with_suffix(".result.json"), site_report)
                    sites_skipped += 1
                    continue

                # 3) verificar policy aplicada
                where = "check_policy_interfaces"
                policy_found = False
                policy_hits = []

                for intf in remote_policy_interfaces:
                    out_intf = _send_exec(conn_rr, f"show run interface {intf}")
                    _write_text(base.with_suffix(f".{_sanitize_filename(intf)}.txt"), out_intf)
                    if f"ip policy route-map {remote_route_map}" in out_intf:
                        policy_found = True
                        policy_hits.append(intf)

                if not policy_found:
                    site_report["status"] = "policy_missing"
                    site_report["error"] = f"ip policy route-map {remote_route_map} not found on expected interfaces"
                    block_report["sites"].append(site_report)
                    _write_json(base.with_suffix(".result.json"), site_report)
                    sites_skipped += 1
                    continue

                site_report["policy_interfaces"] = policy_hits

                # 4) ler route-map atual
                where = "read_route_map"
                out_rm = _send_exec(conn_rr, f"show run | section ^route-map {remote_route_map}")
                _write_text(base.with_suffix(".route_map_before.txt"), out_rm)

                lines = out_rm.splitlines()
                in_target_seq = False
                set_lines = []

                for line in lines:
                    stripped = line.strip()

                    if re.match(rf"^route-map {re.escape(remote_route_map)} permit {remote_route_map_seq}$", stripped):
                        in_target_seq = True
                        continue

                    if in_target_seq:
                        if stripped.startswith("route-map "):
                            in_target_seq = False
                            continue

                        if stripped.startswith("set ip next-hop verify-availability"):
                            set_lines.append(stripped)

                if not set_lines:
                    site_report["status"] = "set_lines_missing"
                    site_report["error"] = "No 'set ip next-hop verify-availability' lines found"
                    block_report["sites"].append(site_report)
                    _write_json(base.with_suffix(".result.json"), site_report)
                    sites_skipped += 1
                    continue

                parsed_sets = []
                for s in set_lines:
                    parsed = parse_verify_line(s)
                    if not parsed:
                        raise RuntimeError(f"Could not parse verify-availability line: {s}")
                    parsed_sets.append(parsed)

                chosen = None
                remaining = []

                for item in parsed_sets:
                    if item["next_hop"] == advertising_router and chosen is None:
                        chosen = item
                    else:
                        remaining.append(item)

                if chosen is None:
                    site_report["status"] = "adv_not_in_route_map"
                    site_report["error"] = f"Advertising Router {advertising_router} not found among set lines"
                    block_report["sites"].append(site_report)
                    _write_json(base.with_suffix(".result.json"), site_report)
                    sites_skipped += 1
                    continue

                # ordem nova: advertising router primeiro
                new_order = [chosen] + remaining

                rebuilt_set_lines = [
                    f"set ip next-hop verify-availability {item['next_hop']} {idx} track {item['track']}"
                    for idx, item in enumerate(new_order, start=1)
                ]

                site_report["set_before"] = set_lines
                site_report["set_after"] = rebuilt_set_lines

                # 5) backup
                snap_name = f"pre_remote_{hostname_last}_{_now_tag()}.cfg"
                if not dry_run:
                    where = "backup_remote"
                    out_backup = _copy_run_to_flash(conn_rr, snap_name)
                    _write_text(base.with_suffix(".backup.txt"), out_backup)
                    site_report["backup"] = snap_name

                # 6) aplicar reorder obrigatório com renumeração de prioridade
                cfg_cmds: List[str] = []
                cfg_cmds.append(f"route-map {remote_route_map} permit {remote_route_map_seq}")

                for s in set_lines:
                    cfg_cmds.append(f" no {s}")

                for idx, item in enumerate(new_order, start=1):
                    cfg_cmds.append(
                        f" set ip next-hop verify-availability {item['next_hop']} {idx} track {item['track']}"
                    )

                cfg_cmds.append("exit")

                for intf in policy_hits:
                    cfg_cmds += [
                        f"interface {intf}",
                        f" ip policy route-map {remote_route_map}",
                        "exit",
                    ]

                site_report["planned_commands"] = cfg_cmds
                _write_text(base.with_suffix(".planned.cfg"), "\n".join(cfg_cmds) + "\n")

                if dry_run:
                    site_report["status"] = "dry_run_change_planned"
                    site_report["changed"] = True
                    block_report["sites"].append(site_report)
                    _write_json(base.with_suffix(".result.json"), site_report)
                    sites_changed += 1
                    continue

                where = "apply_remote_pbr"
                out_apply = _send_cfg(conn_rr, cfg_cmds)
                _write_text(base.with_suffix(".apply.txt"), out_apply)
                site_report["changed"] = True

                # 7) sanity
                where = "sanity_remote"
                out_rm_after = _send_exec(conn_rr, f"show run | section ^route-map {remote_route_map}")
                _write_text(base.with_suffix(".route_map_after.txt"), out_rm_after)

                out_n2_after = _send_exec(conn_rr, "show ip ospf 1 database nssa-external 0.0.0.0")
                _write_text(base.with_suffix(".show_ospf_n2_after.txt"), out_n2_after)

                m_first_set = re.search(
                    r"^\s*set ip next-hop verify-availability\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+track\s+(\d+)",
                    out_rm_after,
                    re.M,
                )
                if not m_first_set:
                    raise RuntimeError("Could not identify first set line after apply")

                first_next_hop = m_first_set.group(1)
                first_priority = int(m_first_set.group(2))

                if first_next_hop != advertising_router:
                    raise RuntimeError(
                        f"First next-hop after apply is {first_next_hop}, expected {advertising_router}"
                    )

                if first_priority != 1:
                    raise RuntimeError(
                        f"First next-hop priority after apply is {first_priority}, expected 1"
                    )

                for intf in policy_hits:
                    out_intf_after = _send_exec(conn_rr, f"show run interface {intf}")
                    _write_text(base.with_suffix(f".{_sanitize_filename(intf)}_after.txt"), out_intf_after)
                    if f"ip policy route-map {remote_route_map}" not in out_intf_after:
                        raise RuntimeError(f"Policy missing after apply on {intf}")

                # 8) testes funcionais
                where = "functional_tests"

                conn_sw_local = None
                try:
                    conn_sw_local = _connect_ios_telnet(
                        site["sw_local"],
                        username,
                        password,
                        timeout=30,
                        session_log=base.with_suffix(".sw_local.session.log"),
                    )
                    ok1, avg1, raw1 = _ping(conn_sw_local, site["mux_remoto"], repeat=remote_test_repeat)
                    _write_text(base.with_suffix(".test_sw_local_to_mux_remoto.txt"), raw1)
                    if (not ok1) or (avg1 is None) or (avg1 >= remote_test_rtt_ms):
                        raise RuntimeError(
                            f"sw_local -> mux_remoto failed: avg={avg1}, threshold={remote_test_rtt_ms}"
                        )
                finally:
                    _safe_disconnect(conn_sw_local)

                conn_sw_remoto = None
                try:
                    conn_sw_remoto = _connect_ios_telnet(
                        site["sw_remoto"],
                        username,
                        password,
                        timeout=30,
                        session_log=base.with_suffix(".sw_remoto.session.log"),
                    )
                    ok2, avg2, raw2 = _ping(conn_sw_remoto, site["mux_local"], repeat=remote_test_repeat)
                    _write_text(base.with_suffix(".test_sw_remoto_to_mux_local.txt"), raw2)
                    if (not ok2) or (avg2 is None) or (avg2 >= remote_test_rtt_ms):
                        raise RuntimeError(
                            f"sw_remoto -> mux_local failed: avg={avg2}, threshold={remote_test_rtt_ms}"
                        )
                finally:
                    _safe_disconnect(conn_sw_remoto)

                site_report["status"] = "ok"
                block_report["sites"].append(site_report)
                _write_json(base.with_suffix(".result.json"), site_report)
                sites_changed += 1

            except Exception as e:
                sites_failed += 1
                site_report["status"] = "failed"
                site_report["where_failed"] = where
                site_report["error"] = str(e)

                if not dry_run and "backup" in site_report:
                    try:
                        out_rb = _configure_replace(conn_rr, site_report["backup"])
                        _write_text(base.with_suffix(".rollback.txt"), out_rb)
                        site_report["rollback_attempted"] = True
                        site_report["rollback_ok"] = True
                    except Exception as rb_e:
                        site_report["rollback_attempted"] = True
                        site_report["rollback_ok"] = False
                        site_report["rollback_error"] = str(rb_e)

                block_report["sites"].append(site_report)
                _write_json(base.with_suffix(".result.json"), site_report)

                return Result(
                    ok=False,
                    hostname=hostname_last,
                    where_failed=where,
                    details=f"{rr_ip}: {e}",
                    rollback_attempted=site_report.get("rollback_attempted", False),
                    rollback_ok=site_report.get("rollback_ok"),
                    sites_total=sites_total,
                    sites_changed=sites_changed,
                    sites_skipped=sites_skipped,
                    sites_failed=sites_failed,
                )

            finally:
                _safe_disconnect(conn_rr)

        summary["blocks"].append(block_report)

    _write_json(logs_dir / f"remote_sites_summary_{_now_tag()}.json", summary)

    return Result(
        ok=True,
        hostname=hostname_last,
        sites_total=sites_total,
        sites_changed=sites_changed,
        sites_skipped=sites_skipped,
        sites_failed=sites_failed,
    )

# ----------------------------
# Loading vars
# ----------------------------

def _load_yaml_if_exists(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return {}
    return data


# ----------------------------
# CLI
# ----------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["central_v200", "remote_sites"])
    ap.add_argument("--host", required=True, help="Router management IP (ansible_host)")
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--hostvars", required=True, help="Path to host_vars YAML")
    ap.add_argument("--logs-dir", required=True, help="Logs directory")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    hv_path = Path(args.hostvars)
    hv = yaml.safe_load(hv_path.read_text(encoding="utf-8")) or {}
    if not isinstance(hv, dict):
        hv = {}
    hv["inventory_hostname"] = hv.get("inventory_hostname") or hv_path.stem

    # Auto-load group_vars/central_routers.yml
    scripts_dir = Path(__file__).resolve().parent
    repo_root = scripts_dir.parent
    gv_path = repo_root / "group_vars" / "central_routers.yml"
    gv = _load_yaml_if_exists(gv_path)

    logs_dir = Path(args.logs_dir)

    if args.mode == "central_v200":
        res = run_central_v200(
            router_host=args.host,
            username=args.username,
            password=args.password,
            hv=hv,
            gv=gv,
            logs_dir=logs_dir,
            dry_run=args.dry_run,
        )
    elif args.mode == "remote_sites":
        res = run_remote_sites(
            hv=hv,
            gv=gv,
            logs_dir=logs_dir,
            dry_run=args.dry_run,
            username=args.username,
            password=args.password,
        )
    else:
        res = Result(
            ok=False,
            hostname="UNKNOWN",
            where_failed="mode",
            details=f"Unsupported mode {args.mode}",
        )

    print(json.dumps(res.__dict__, indent=2, ensure_ascii=False))
    return 0 if res.ok else 2


if __name__ == "__main__":
    sys.exit(main())
