import os
import sys
import urllib.parse
from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools import tool

# 1. Initialize the local model via Ollama
network_llm = LLM(model="ollama/llama3.1", base_url="http://localhost:11434")


# ==========================================
# CUSTOM AGENT TOOLS
# ==========================================

@tool("Payload Decoder Tool")
def decode_payload_tool(payload: str) -> str:
    """
    Use this tool when a network payload contains URL-encoded characters (like %20, %27, %3D).
    Pass the raw payload string to this tool to get the decoded, readable plaintext back.
    """
    decoded = urllib.parse.unquote(payload)
    return f"Decoded Payload: {decoded}"

@tool("IP History Checker Tool")
def check_ip_history_tool(ip_address: str) -> str:
    """
    Use this tool to check how many times an IP address has connected to the network in the last 5 minutes.
    Pass the source IP address (e.g., '192.168.1.5') to this tool.
    """
    # For the Viva, we simulate a database lookup. 
    # Later, you can connect this to the SQLite database you used in your LockLens project!
    suspicious_ips = ["93.184.216.34", "192.168.65.7"]
    
    if ip_address in suspicious_ips:
        return f"CRITICAL: IP {ip_address} has attempted 4,502 connections in the last 3 minutes (Possible Brute-Force/DoS)."
    else:
        return f"NORMAL: IP {ip_address} has only 2 connections in the last 5 minutes."


@tool("Global Threat Feed Checker Tool")
def threat_feed_checker_tool(ip_address: str) -> str:
    """
    Use this tool to check if an IP address exists in global OSINT threat intelligence feeds (Mock VirusTotal/AbuseIPDB).
    Pass the target IP address as a string.
    """
    # Simulated local database for zero-trust viva demonstration
    known_malicious = {
        "192.168.65.7": "HIGH THREAT: IP flagged by 14 security vendors. Known node for automated SQLi scanning.",
        "93.184.216.34": "CRITICAL: Known Command & Control (C2) server associated with data exfiltration.",
        "139.84.16.34": "CRITICAL: Cobalt Strike beacon infrastructure."
    }
    return known_malicious.get(ip_address, f"IP {ip_address} not found in global threat feeds. Reputation: Neutral.")

@tool("CVE Database Lookup Tool")
def cve_lookup_tool(attack_vector: str) -> str:
    """
    Use this tool to look up known Common Vulnerabilities and Exposures (CVEs) related to a specific attack technique.
    Pass the attack type (e.g., 'SQL Injection', 'Cross-Site Scripting') to get the CVE context.
    """
    if "sql" in attack_vector.lower() or "sqli" in attack_vector.lower():
        return "CVE-2024-2143: Critical SQL Injection vulnerability actively exploited in the wild to bypass authentication panels."
    return "No specific recent CVEs found for this generic attack type."

@tool("Firewall Rule Generator Tool")
def firewall_rule_generator_tool(ip_address: str) -> str:
    """
    Use this tool to instantly generate a Linux UFW firewall command to block a critical threat IP.
    Pass the malicious IP address to be blocked.
    """
    return f"Execute this command as root to mitigate the threat: sudo ufw deny from {ip_address} to any comment 'AegisNet Auto-Block'"
# ==========================================



# 2. Define the Agents
network_analyst = Agent(
    role='Senior Network Security Analyst',
    goal='Analyze raw Deep Packet Inspection (DPI) logs, decode obfuscated payloads, and assess IP threat levels.',
    backstory='You are a bare-metal network engineer. You analyze raw TCP/IP payloads and actively use forensic tools to investigate anomalies.',
    verbose=True,
    allow_delegation=False,
    llm=network_llm,
    tools=[decode_payload_tool, check_ip_history_tool] # <--- TOOLS ADDED HERE
)

osint_investigator = Agent(
    role='Threat Intelligence Investigator',
    goal='Correlate flagged IPs and attack vectors with known global threat campaigns and CVEs.',
    backstory='You are a Cyber Threat Intel (CTI) researcher. You use local threat databases and CVE lookups to contextualize network anomalies.',
    verbose=True,
    allow_delegation=False,
    llm=network_llm,
    tools=[threat_feed_checker_tool, cve_lookup_tool] # <--- NEW TOOLS ADDED
)

reporting_lead = Agent(
    role='SOC Incident Commander',
    goal='Synthesize network findings and generate actionable mitigation commands.',
    backstory='You translate highly technical network breaches into actionable defense playbooks, actively generating firewall rules to protect the system.',
    verbose=True,
    allow_delegation=False,
    llm=network_llm,
    tools=[firewall_rule_generator_tool] # <--- NEW TOOL ADDED
)

# 3. Define the Investigation Pipeline
def run_investigation(packet_log):
    print(f"\n[AegisNet] AI SOC analyzing new intercepted payload...\n")
    
    analyze_task = Task(
        description=f"Analyze this raw DPI packet interception:\n\n{packet_log}\n\n"
                    f"STEP 1: Extract the Source IP and use your tool to check its network history.\n"
                    f"STEP 2: Check the L7_PAYLOAD. If it looks URL encoded, use your decoder tool to translate it.\n"
                    f"STEP 3: Provide a final technical diagnosis of the attack vector.",
        expected_output="A technical diagnosis of the packet, including IP history context and decoded payload analysis.",
        agent=network_analyst
    )
    
    osint_task = Task(
        description="Take the findings from the network analyst.\n"
                    "STEP 1: Use your threat feed tool to check the reputation of the attacker's IP address.\n"
                    "STEP 2: Use your CVE lookup tool to find the exact CVE number associated with the attack technique (e.g., SQL Injection).\n"
                    "STEP 3: Provide a summary of the global threat context.",
        expected_output="Threat intelligence context including IP reputation and CVE correlations.",
        agent=osint_investigator
    )
    
    report_task = Task(
        description="Synthesize the analysis and OSINT data into a concise SOC incident report.\n"
                    "Crucially, use your Firewall Rule Generator tool to create the exact command needed to block the attacker's IP, and include this generated command in your final report.",
        expected_output="A finalized Executive SOC Report containing the generated firewall mitigation command.",
        agent=reporting_lead
    )
    
    soc_crew = Crew(
        agents=[network_analyst, osint_investigator, reporting_lead],
        tasks=[analyze_task, osint_task, report_task],
        process=Process.sequential,
        verbose=True
    )
    
    result = soc_crew.kickoff()
    
    print("\n==================================================")
    print("[AegisNet] FINAL AI SOC REPORT:")
    print("==================================================")
    print(result)
    print("==================================================\n")

# 4. Execute the Pipeline
if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Accept the live packet from the C++ sniffer
        live_packet = sys.argv[1]
        run_investigation(live_packet)
    else:
        print("Waiting for packet data...")