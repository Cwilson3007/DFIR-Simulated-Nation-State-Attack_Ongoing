# Investigating a Nation-State Supply Chain Attack with Multi-Layered Evasion Techniques

## Scenario
> A multinational corporation has suffered a stealthy, year-long supply chain compromise 
> orchestrated by a nation-state threat actor. The attack has infiltrated thousands of 
> endpoints across multiple regions, leveraging advanced evasion techniques to remain undetected.

# Adversary Tactics:
$ Living-off-the-Land (LotL) - Uses legitimate system tools to evade detection
$ Encrypted C2 Communications - Hides traffic via DNS tunneling, domain fronting
$ Anti-Forensic Measures - Timestomping, log wiping, process injection
$ Ransomware Distraction - Encrypts systems to divert attention from data exfiltration

## Objective
# You are tasked with leading the forensic investigation:
$ Identify the initial attack vector       # Determine how the attacker compromised the supply chain
$ Map the full scope of the breach         # Track lateral movement and persistence techniques
$ Attribute the attack                     # Analyze TTPs to identify the threat actor
$ Provide actionable remediation            # Develop defense strategies to prevent future incidents

## Tools & Techniques
# The investigation will involve:
$ Memory forensics   - Using Volatility for RAM analysis
$ Malware analysis   - Reversing engineered samples via REMnux
$ Network forensics  - Inspecting PCAPs with Wireshark and Zeek
$ Anti-forensics detection - Identifying evasion techniques and log tampering

> This project simulates a real-world forensic case study using a controlled lab 
> environment. The findings will be documented and analyzed for a structured report.
