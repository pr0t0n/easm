"""Static, code-defined BAS (Breach & Attack Simulation) technique catalog.

Never a DB table: `risk_tier` and `availability` must not be admin-editable,
since bas_guardrail_policy's authorization gate depends on both being a fixed,
trusted property of the technique itself -- the same reason kali_catalog.py's
tool catalog and offensive_operator_core.py's phase contracts are code, not
rows a user could quietly loosen.

`availability` is the load-bearing field for whether a technique can be
dispatched at all:
  - "available"/"simulated" (the name is legacy -- it does NOT mean the
    dispatch is fake): routes through kali_runner + proxychains to the
    target BasAgent's real SOCKS5 tunnel. Whether the RESULT is real or
    fabricated depends entirely on which agent ran it (BasAgent.kind --
    "stub" for bas_agent_stub, which always fabricates its response
    content; "real" for a genuine agent, cryptographically proven via a
    CA-signed mTLS cert at enroll -- see bas_ca.py, bas_dispatcher.py). This
    catalog says nothing about that; `is_simulated_in_phase_1` below is a
    per-technique legacy hint, not a runtime truth.
  - "planned": no kali tool wired up yet.
  - "future_agent_required": proxychains/SOCKS5 CONNECT tunnels TCP only --
    it cannot carry UDP, broadcast/multicast, or anything requiring real L2
    presence on the customer's network segment (arp_poisoning, dhcp_spoofing:
    no tool wired up at all yet, stay disabled until a real agent exists).
  - Phase 3 exception, deliberate: llmnr_nbtns_poisoning/mdns_poisoning ARE
    dispatched for real (availability="simulated",
    execution_backend="kali_direct_no_tunnel_effect") even though the tunnel
    structurally can't help them -- Responder runs in real passive analyze
    mode (-A, never poisons) on kali_runner's own network, so the "no real
    signal" result is an observed fact demonstrating the limitation, not a
    guardrail assumption. See responder_analyze_attempt in bas_internal.yaml.
  - Host-based techniques (credential_dumping_mimikatz,
    dotfile_config_harvesting, kubeconfig_theft): same "future_agent_required"
    treatment as arp_poisoning/dhcp_spoofing, but for a different structural
    reason -- these need local code execution / filesystem access on an
    already-compromised host, not just a wrong network segment. There is no
    tool a SOCKS5 tunnel can carry for these at all (unlike Responder, which
    IS a real dispatchable tool that just fails visibly), so kali_tool_name
    stays None until a real agent is physically installed on that host.
"""
from __future__ import annotations

from typing import Any


def _technique(
    technique_key: str,
    *,
    category: str,
    mode: str,
    risk_tier: str,
    display_name: str,
    description: str,
    supported_os: list[str],
    mitre_refs: list[str],
    availability: str,
    execution_backend: str | None,
    kali_tool_name: str | None = None,
    kali_profile: str | None = None,
    requires_tcp: bool = False,
    requires_udp: bool = False,
    requires_l2: bool = False,
    requires_real_agent: bool = False,
    requires_privileged_agent: bool = False,
    is_simulated_in_phase_1: bool = False,
    # What shape of target string this technique's underlying tool actually
    # expects -- "host" (bare host/IP, no scheme/port), "host_port"
    # (host[:port], tool defaults the port itself if omitted), "url" (needs
    # a scheme), "domain" (bare domain, no scheme/port/path). A schedule (or
    # a chain, which shares ONE target_hint across every step) supplies a
    # single target_hint regardless of which techniques it drives -- see
    # bas_dispatcher._normalize_target, which reshapes that one string to
    # match each step's own declared format instead of passing it through
    # verbatim (confirmed live: nmap silently misresolved a "host:port"
    # string meant for a "host"-only step in the web_to_secrets_chain test).
    target_format: str = "host",
    # True only for techniques whose underlying CLI tool natively iterates a
    # CIDR range in a single invocation (nmap -sT -Pn, crackmapexec) -- lets
    # bas_dispatcher._normalize_target preserve a "/nn" mask instead of
    # collapsing target_hint to one bare host. Most techniques are
    # app/service/domain-specific (a webhook URL, one AD DC, one cloud
    # tenant) and would never make sense pointed at a range.
    accepts_range: bool = False,
    # Generic, technique-level remediation guidance shown in the BAS report
    # when this technique produces a real (non-simulated) finding.
    recommendation: str = "",
) -> dict[str, Any]:
    return {
        "technique_key": technique_key,
        "category": category,
        "mode": mode,
        "risk_tier": risk_tier,
        "display_name": display_name,
        "description": description,
        "supported_os": supported_os,
        "mitre_refs": mitre_refs,
        "kali_tool_name": kali_tool_name,
        "kali_profile": kali_profile,
        "availability": availability,
        "execution_backend": execution_backend,
        "requires_tcp": requires_tcp,
        "requires_udp": requires_udp,
        "requires_l2": requires_l2,
        "requires_real_agent": requires_real_agent,
        "requires_privileged_agent": requires_privileged_agent,
        "is_simulated_in_phase_1": is_simulated_in_phase_1,
        "target_format": target_format,
        "accepts_range": accepts_range,
        "recommendation": recommendation,
    }


BAS_TECHNIQUE_CATALOG: list[dict[str, Any]] = [
    # ── Works via SOCKS5/proxychains today (real network hop, stub content) ──
    _technique(
        "smb_enum_cme",
        category="smb", mode="intruder", risk_tier="safe",
        display_name="SMB Share Enumeration (CrackMapExec)",
        description="Enumerates SMB shares/sessions via crackmapexec, tunneled through the BAS agent.",
        supported_os=["windows", "linux"], mitre_refs=["T1135"],
        # kali_tool_name is a dispatch KEY into kali_executor.TOOL_TO_PROFILE,
        # namespaced with a "-bas" suffix -- NEVER the bare "crackmapexec" key,
        # which already maps to the external P01-P22 pipeline's untunneled
        # crackmapexec_smb profile. Reusing that key would silently dispatch
        # this BAS technique with no tunnel at all.
        kali_tool_name="crackmapexec-bas", kali_profile="crackmapexec_smb_bas_tunnel",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", accepts_range=True,
        recommendation="Restrinja acesso a compartilhamentos SMB anonimo/autenticado; desative SMBv1; segmente hosts com dados sensiveis do acesso geral da rede.",
    ),
    _technique(
        "smb_enum_enum4linux",
        category="smb", mode="bypass", risk_tier="safe",
        display_name="SMB/AD Enumeration (enum4linux-ng)",
        description="Null-session/authenticated SMB and AD enumeration, tunneled through the BAS agent.",
        supported_os=["windows"], mitre_refs=["T1087", "T1135"],
        kali_tool_name="enum4linux-ng-bas", kali_profile="enum4linux_ng_basic",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Desative null sessions RPC/SMB; restrinja enumeracao anonima de usuarios/RIDs; audite ACLs de compartilhamentos expostos.",
    ),
    _technique(
        "ad_bloodhound_collect",
        category="ad", mode="intruder", risk_tier="safe",
        display_name="AD Attack Path Collection (BloodHound ingestor)",
        description="Collects AD objects/ACLs via LDAP for attack-path graphing, tunneled through the BAS agent.",
        supported_os=["windows"], mitre_refs=["T1087.002", "T1482"],
        kali_tool_name="bloodhound-python-bas", kali_profile="bloodhound_python_collect",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Revise ACLs de Active Directory alcancaveis via LDAP anonimo/autenticado; monitore volumes anormais de consultas LDAP vindos de contas de baixo privilegio.",
    ),
    _technique(
        "ad_kerberoast",
        category="ad", mode="intruder", risk_tier="elevated",
        display_name="Kerberoasting (impacket GetUserSPNs)",
        description="Requests service-account TGS tickets over Kerberos/LDAP for offline cracking, tunneled through the BAS agent.",
        supported_os=["windows"], mitre_refs=["T1558.003"],
        kali_tool_name="getuserspns-bas", kali_profile="impacket_kerberoast",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Use senhas longas e aleatorias para contas de servico; habilite criptografia AES para tickets Kerberos; monitore requisicoes de TGS em massa (indicativo de kerberoasting).",
    ),
    _technique(
        "ntlm_relay_smb",
        category="ntlm", mode="intruder", risk_tier="high_risk",
        display_name="NTLM Relay to SMB (impacket ntlmrelayx)",
        description="Relays captured NTLM authentication to an SMB target over TCP, tunneled through the BAS agent.",
        supported_os=["windows"], mitre_refs=["T1557.001"],
        kali_tool_name="ntlmrelayx-bas", kali_profile="impacket_ntlmrelayx",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Habilite SMB signing em todos os hosts; desative NTLM quando possivel em favor de Kerberos; segmente a rede para reduzir superficie de relay.",
    ),

    # ── Requires a real agent on the customer's L2 segment -- never run as
    #    validated real traffic in Phase 1 (SOCKS5 CONNECT is TCP-only). ──
    _technique(
        "llmnr_nbtns_poisoning",
        category="ntlm", mode="poisoning", risk_tier="high_risk",
        display_name="LLMNR/NBT-NS Poisoning (Responder)",
        description=(
            "Listens for and answers LLMNR/NBT-NS broadcast queries to capture NetNTLM hashes. "
            "Phase 3 decision: dispatched for real (not guardrail-blocked) in passive analyze "
            "mode so the tunnel's structural inability to carry this technique shows up as an "
            "observed, real result (nothing captured -- Responder listens on kali_runner's own "
            "network, never the customer's) instead of an assumption. Real poisoning still "
            "requires a real agent physically on the customer's L2 segment."
        ),
        supported_os=["windows", "linux"], mitre_refs=["T1557.001"],
        kali_tool_name="responder-bas", kali_profile="responder_analyze_attempt",
        availability="simulated", execution_backend="kali_direct_no_tunnel_effect",
        requires_udp=True, requires_l2=True, requires_real_agent=True,
        requires_privileged_agent=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Desative LLMNR e NBT-NS via GPO onde nao forem necessarios; monitore respostas de poisoning na rede; use SMB signing para mitigar relay de hashes capturados.",
    ),
    _technique(
        "mdns_poisoning",
        category="ntlm", mode="poisoning", risk_tier="high_risk",
        display_name="mDNS Poisoning (Responder)",
        description=(
            "Answers mDNS broadcast queries to capture credentials from misconfigured clients. "
            "Same Phase 3 dispatched-analyze-mode decision as llmnr_nbtns_poisoning -- one "
            "Responder -A invocation covers LLMNR/NBT-NS/mDNS analysis together."
        ),
        supported_os=["windows", "linux"], mitre_refs=["T1557.001"],
        kali_tool_name="responder-bas", kali_profile="responder_analyze_attempt",
        availability="simulated", execution_backend="kali_direct_no_tunnel_effect",
        requires_udp=True, requires_l2=True, requires_real_agent=True,
        requires_privileged_agent=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Restrinja mDNS a segmentos de rede confiaveis; monitore respostas mDNS anomalas; eduque usuarios sobre prompts de credencial inesperados.",
    ),
    _technique(
        "arp_poisoning",
        category="ntlm", mode="poisoning", risk_tier="high_risk",
        display_name="ARP Poisoning / Spoofing",
        description="Poisons ARP tables on the local segment to intercept traffic between hosts.",
        supported_os=["linux"], mitre_refs=["T1557.002"],
        kali_tool_name=None, kali_profile=None,
        availability="future_agent_required", execution_backend=None,
        requires_l2=True, requires_real_agent=True, requires_privileged_agent=True,
        target_format="host", recommendation="Habilite DHCP snooping/dynamic ARP inspection nos switches; monitore tabelas ARP por anomalias; considere 802.1X para autenticacao de porta.",
    ),
    _technique(
        "dhcp_spoofing",
        category="ntlm", mode="poisoning", risk_tier="high_risk",
        display_name="DHCP Spoofing",
        description="Answers DHCP requests on the local segment to redirect client traffic.",
        supported_os=["linux"], mitre_refs=["T1557"],
        kali_tool_name=None, kali_profile=None,
        availability="future_agent_required", execution_backend=None,
        requires_udp=True, requires_l2=True, requires_real_agent=True,
        requires_privileged_agent=True,
        target_format="host", recommendation="Habilite DHCP snooping nos switches; restrinja quem pode responder a requisicoes DHCP na rede; monitore servidores DHCP nao autorizados.",
    ),

    # ── Phase 2: VMware/Firewall onboarded onto the existing tunnel (curl and
    #    nmap were already installed in kali_runner -- no Dockerfile change
    #    needed, just new profiles + TOOL_TO_PROFILE entries). ──
    _technique(
        "vmware_vcenter_default_creds",
        category="vmware", mode="bypass", risk_tier="elevated",
        display_name="vCenter/ESXi Default Credential Check",
        description="Tests the root/vmware default credential against vCenter's REST session API, tunneled through the BAS agent.",
        supported_os=[], mitre_refs=["T1078"],
        kali_tool_name="curl-vmware-bas", kali_profile="vmware_vcenter_default_creds_check",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Troque credenciais padrao de root/vmware imediatamente; force troca de senha no primeiro login; restrinja acesso a API REST do vCenter/ESXi por IP.",
    ),
    _technique(
        "firewall_segmentation_test",
        category="firewall", mode="intruder", risk_tier="safe",
        display_name="East-West Segmentation Test",
        description="TCP-connect reachability check on common ports, tunneled through the BAS agent -- confirms whether a supposedly-blocked internal segment is actually reachable.",
        supported_os=[], mitre_refs=["T1590.004"],
        kali_tool_name="nmap-firewall-bas", kali_profile="firewall_segmentation_probe",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", accepts_range=True,
        recommendation="Revise regras de firewall/ACLs entre segmentos; o alcance encontrado indica que a segmentacao presumida nao esta de fato aplicada na rede.",
    ),

    # ── Added on request: network/AD/cloud/web discovery + supply-chain
    #    secrets techniques, all onboarded onto the existing tunnel (no new
    #    architecture -- same proxychains-wrapped real-tool pattern). ──
    _technique(
        "network_share_discovery",
        category="smb", mode="intruder", risk_tier="safe",
        display_name="Network Share Discovery (smbmap)",
        description="Enumerates accessible SMB shares and permissions via smbmap, tunneled through the BAS agent.",
        supported_os=["windows"], mitre_refs=["T1135"],
        kali_tool_name="smbmap-bas", kali_profile="smbmap_share_discovery",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Restrinja permissoes de compartilhamentos SMB ao minimo necessario; remova acesso 'Everyone'/anonimo; audite compartilhamentos com dados sensiveis.",
    ),
    _technique(
        "ad_scouting_ldap",
        category="ad", mode="intruder", risk_tier="safe",
        display_name="Active Directory Scouting (LDAP)",
        description="Anonymous LDAP naming-context query for lightweight AD scouting, tunneled through the BAS agent.",
        supported_os=["windows"], mitre_refs=["T1087.002"],
        kali_tool_name="ldapsearch-bas", kali_profile="ad_ldap_scouting",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Desative bind anonimo LDAP no controlador de dominio; restrinja consultas LDAP nao autenticadas; monitore volumes de consulta anomalos.",
    ),
    _technique(
        "cloud_directory_scouting",
        category="cloud", mode="intruder", risk_tier="safe",
        display_name="Cloud Directory Discovery and Scouting",
        description="Queries Azure AD's userRealm discovery endpoint for a target domain to fingerprint cloud-identity tenancy, tunneled through the BAS agent.",
        supported_os=[], mitre_refs=["T1590.005", "T1526"],
        kali_tool_name="curl-clouddir-bas", kali_profile="cloud_directory_scouting_check",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="domain", recommendation="Revise o que a resposta de discovery do provedor de identidade expoe publicamente (tipo de federacao, tenant); considere respostas genericas para dominios nao gerenciados.",
    ),
    _technique(
        "port_service_scan",
        category="network", mode="intruder", risk_tier="safe",
        display_name="Port & Service Scanning",
        description="TCP-connect port + service-version scan across the top 100 ports, tunneled through the BAS agent.",
        supported_os=[], mitre_refs=["T1046"],
        kali_tool_name="nmap-portscan-bas", kali_profile="port_service_scan",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", accepts_range=True,
        recommendation="Feche portas/servicos desnecessariamente expostos; confirme que a segmentacao de rede presumida realmente bloqueia o alcance encontrado.",
    ),
    _technique(
        "chat_webhook_discovery",
        category="cloud", mode="intruder", risk_tier="safe",
        display_name="Teams/Slack (CHAT) Discovery",
        description="Probes a Teams/Slack incoming-webhook URL for reachability, tunneled through the BAS agent.",
        supported_os=[], mitre_refs=["T1213"],
        kali_tool_name="curl-chatwebhook-bas", kali_profile="chat_webhook_discovery_check",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="url", recommendation="Trate URLs de webhook como segredo; rotacione se vazadas; restrinja quem pode postar validando um token/assinatura na propria automacao que recebe o webhook.",
    ),
    _technique(
        "netlogon_zerologon_check",
        category="ad", mode="bypass", risk_tier="elevated",
        display_name="NetLogon Analysis for Hardcoded Authentication (Zerologon)",
        description="Tests for the Zerologon (CVE-2020-1472) hardcoded/null Netlogon authentication bypass via crackmapexec's zerologon module, tunneled through the BAS agent.",
        supported_os=["windows"], mitre_refs=["T1210"],
        kali_tool_name="zerologon-bas", kali_profile="netlogon_zerologon_check",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", recommendation="Aplique a correcao do CVE-2020-1472 (Zerologon); force 'FullSecureChannelProtection' no controlador de dominio; monitore falhas de autenticacao Netlogon.",
    ),
    _technique(
        "owasp_web_app_scan",
        category="web", mode="intruder", risk_tier="safe",
        display_name="OWASP Web Application Scan",
        description="OWASP-style web application misconfiguration/vulnerability scan against an operator-configured host (set the schedule's target_hint to the web app's URL/host), tunneled through the BAS agent.",
        supported_os=[], mitre_refs=["T1190"],
        kali_tool_name="nikto-owasp-bas", kali_profile="owasp_web_app_scan",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host_port", recommendation="Corrija os achados especificos listados no resultado real (ex: headers de seguranca ausentes, CORS permissivo); rode o scan completo (nuclei/zap) para cobertura OWASP Top 10 completa.",
    ),
    _technique(
        "safe_credential_checks",
        category="identity", mode="bypass", risk_tier="safe",
        display_name="Safe Credential Boundary Checks",
        description="Validates safe authentication boundary signals such as guest/null SMB exposure and protocol security posture without password spraying or brute force.",
        supported_os=["windows", "linux"], mitre_refs=["T1078", "T1110.001"],
        kali_tool_name="crackmapexec-bas", kali_profile="crackmapexec_smb_bas_tunnel",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", accepts_range=True,
        recommendation="Bloqueie acesso guest/null session; aplique lockout e MFA onde aplicavel; restrinja autenticação SMB/NTLM a origens autorizadas.",
    ),
    _technique(
        "lateral_movement_simulation_safe",
        category="lateral_movement", mode="intruder", risk_tier="safe",
        display_name="Safe Lateral Movement Reachability Simulation",
        description="Simulates lateral movement feasibility by validating reachability of administrative and common east-west TCP services through the agent tunnel without code execution.",
        supported_os=["windows", "linux"], mitre_refs=["T1021", "T1046"],
        kali_tool_name="nmap-firewall-bas", kali_profile="firewall_segmentation_probe",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host", accepts_range=True,
        recommendation="Reduza alcance east-west entre segmentos; bloqueie portas administrativas entre estações; exija jump hosts e políticas explícitas para RDP/WinRM/SSH/SMB.",
    ),
    _technique(
        "controlled_exploit_validation",
        category="exploit_validation", mode="intruder", risk_tier="elevated",
        display_name="Controlled Exploitability Validation",
        description="Runs a controlled, non-destructive web vulnerability validation through the agent tunnel and only promotes objective tool evidence as a proven BAS finding.",
        supported_os=[], mitre_refs=["T1190"],
        kali_tool_name="nikto-owasp-bas", kali_profile="owasp_web_app_scan",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="host_port",
        recommendation="Corrija a vulnerabilidade validada, preserve o comando de replay do BAS e rode o reteste controlado após mitigação.",
    ),
    _technique(
        "pipeline_secrets_harvesting",
        category="cicd", mode="intruder", risk_tier="safe",
        display_name="Secrets Harvesting via Pipeline Logs",
        description="Fetches an operator-provided CI/CD build-log URL and greps it for common exposed-secret patterns, tunneled through the BAS agent. Only reaches logs actually exposed at the given URL -- no CI platform credentials are used.",
        supported_os=[], mitre_refs=["T1552.001"],
        kali_tool_name="curl-pipelinelogs-bas", kali_profile="pipeline_secrets_harvest",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="url", recommendation="Nunca deixe segredos em texto claro em logs de build; use mascaramento nativo do CI/CD; rotacione qualquer segredo que ja tenha aparecido em log publico.",
    ),
    _technique(
        "source_code_secrets_scan",
        category="cicd", mode="intruder", risk_tier="safe",
        display_name="Hardcoded Secrets in Source Code Detection",
        description="Clones an operator-provided git repository URL and scans it with gitleaks for hardcoded passwords/API tokens/connection strings, tunneled through the BAS agent.",
        supported_os=[], mitre_refs=["T1552.001"],
        kali_tool_name="gitleaks-bas", kali_profile="source_code_secrets_scan",
        availability="simulated", execution_backend="kali_proxychains",
        requires_tcp=True, is_simulated_in_phase_1=True,
        target_format="url", recommendation="Rotacione imediatamente qualquer segredo encontrado no historico do git; adicione gitleaks/pre-commit hooks no pipeline; nunca versione arquivos .env/credenciais.",
    ),

    # ── Host-based -- require literal code execution / filesystem access ON
    #    the target endpoint. No SOCKS5 CONNECT tunnel can provide this: these
    #    don't "connect out" to a network service, they read local process
    #    memory or the local filesystem of a specific already-compromised
    #    host. Unlike Responder (a real tool whose failure the tunnel
    #    demonstrates), there is literally no command a network tunnel can
    #    carry for these -- so, like arp_poisoning/dhcp_spoofing, they stay
    #    hard-blocked with no kali_tool_name at all until a real agent is
    #    physically installed on the target host. ──
    _technique(
        "credential_dumping_mimikatz",
        category="windows", mode="intruder", risk_tier="high_risk",
        display_name="Credential Dumping (via Mimikatz)",
        description="Dumps credentials from LSASS process memory on a live Windows host. Requires local code execution on that host -- structurally impossible over a SOCKS5 CONNECT tunnel, which only carries outbound network connections, not local memory access.",
        supported_os=["windows"], mitre_refs=["T1003.001"],
        kali_tool_name=None, kali_profile=None,
        availability="future_agent_required", execution_backend=None,
        requires_real_agent=True, requires_privileged_agent=True,
        target_format="host", recommendation="Habilite Credential Guard/LSA Protection no Windows; restrinja privilegios administrativos locais; monitore acesso ao processo LSASS.",
    ),
    _technique(
        "dotfile_config_harvesting",
        category="linux", mode="intruder", risk_tier="high_risk",
        display_name="Dot-Files and Config Harvesting (.aws/credentials)",
        description="Silently scans a developer's machine for static access keys/tokens left in local config files (e.g. ~/.aws/credentials, Kubernetes tokens, ~/.gitconfig). Requires local filesystem read access on that host -- a network tunnel cannot read another host's local files.",
        supported_os=["linux"], mitre_refs=["T1552.001"],
        kali_tool_name=None, kali_profile=None,
        availability="future_agent_required", execution_backend=None,
        requires_real_agent=True, requires_privileged_agent=True,
        target_format="host", recommendation="Nunca grave credenciais em texto claro em arquivos de configuracao locais; use um gerenciador de segredos (Vault, AWS Secrets Manager); restrinja permissoes de leitura desses arquivos.",
    ),
    _technique(
        "kubeconfig_theft",
        category="linux", mode="intruder", risk_tier="high_risk",
        display_name="Kubeconfig File Theft",
        description="Attempts to extract ~/.kube/config from a DevOps engineer's machine to gain direct remote access to the company's Kubernetes clusters. Requires local filesystem read access on that host -- same structural limitation as dotfile_config_harvesting.",
        supported_os=["linux"], mitre_refs=["T1552.001"],
        kali_tool_name=None, kali_profile=None,
        availability="future_agent_required", execution_backend=None,
        requires_real_agent=True, requires_privileged_agent=True,
        target_format="host", recommendation="Use autenticacao de curta duracao para kubeconfig (OIDC/exec plugin) em vez de tokens estaticos de longa duracao; restrinja permissoes de leitura em ~/.kube/config.",
    ),
]

_CATALOG_BY_KEY: dict[str, dict[str, Any]] = {row["technique_key"]: row for row in BAS_TECHNIQUE_CATALOG}


def list_techniques() -> list[dict[str, Any]]:
    return list(BAS_TECHNIQUE_CATALOG)


def get_technique(technique_key: str) -> dict[str, Any] | None:
    return _CATALOG_BY_KEY.get(str(technique_key or ""))


RISK_TIER_ORDER: dict[str, int] = {"safe": 0, "elevated": 1, "high_risk": 2}
