master_thesis
Repo to post and store the code/scripts ive been working on while developing my thesis.

My thesis is currently developing and comparing existing LLM-based tooling to help automate penetration testing in the energy sector.

There is a wide gap between Cyber- and Cyber-physical systems in terms of how secure they are and consequences. While, a DDoS attack or Ransomware attack which compromises the availabilty [CIA-triad] aspects of security, its consequences are more severe in an OT-enviornment compares to Cyber.

When talking about Cyber, i refer to typical IT-architecture in businsses and normally just software. If a ransomware-attack happened on such a Cyber-system, then a few services are down. However, if in the energy sector there happened a Ransomware-attack, then produciton would stop and it would affect the safety and lives of people.

As such, these types of CPSs [Cyber Physical Systems] are considered Critical Infrastructure (CI). Typically, a CPS is a system-of-systems. There are multiple systems which are interconnected, where each system-of-systems consists of thousands of Layer 7 (outer sensors, cameras etc) and 5 devices (Edge computing) [Ref: WorldIoTLayers] which contributes to an enormous attack surface compared to normal IT-systems. As such, penetration testing is time-consuming and expensive because the complexity-levels are so high.

There is also the physical aspect of these systems, in addition to the software. Hence the name: Cyber-Physical systems.

Therefore, the point of the thesis is to provde an automated way of finding vulnerabilities, misconfigurations, etc. in these CI's to find the more known threats in a more time- and resource efficient way. As such, this can help penetration testers in the energy sector to focus on finding Zero Day Threats, which are typically more unique and very difficult to find.
