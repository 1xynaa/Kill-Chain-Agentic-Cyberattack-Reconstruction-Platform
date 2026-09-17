from backend.app.agent import Agent
from backend.app.skills import SkillSummary


def skill(name: str, text: str) -> SkillSummary:
    return SkillSummary(name=name, path=name, description=text, overview=text, when_to_use=text)


def test_pcap_skill_selection_prefers_packet_analysis():
    catalog = [
        skill("performing-network-traffic-analysis-with-tshark", "PCAP packet capture tshark DNS IOC analysis"),
        skill("conducting-man-in-the-middle-attack-simulation", "attack simulation interception"),
    ]
    selected = Agent._select_skills(catalog, "attack_scenario.pcap pcap capture file")
    assert selected[0].name == "performing-network-traffic-analysis-with-tshark"
