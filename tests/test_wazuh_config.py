from __future__ import annotations

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WAZUH = ROOT / "infra" / "wazuh"


def read_elements(path: Path) -> ET.Element:
    return ET.fromstring(f"<config>{path.read_text(encoding='utf-8')}</config>")


class WazuhConfigTests(unittest.TestCase):
    def test_all_wazuh_xml_and_agent_configs_parse(self) -> None:
        paths = sorted(WAZUH.rglob("*.xml")) + sorted(WAZUH.rglob("ossec.conf"))
        self.assertGreater(len(paths), 0)
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                read_elements(path)

    def test_modular_rule_ids_are_unique(self) -> None:
        seen: dict[str, Path] = {}
        for path in sorted((WAZUH / "rules").rglob("*.xml")):
            for rule in read_elements(path).iter("rule"):
                rule_id = rule.attrib["id"]
                self.assertNotIn(rule_id, seen, f"Duplicate rule {rule_id}: {path}")
                seen[rule_id] = path

    def test_suricata_text_decoder_extracts_ipv4_endpoints(self) -> None:
        decoder = read_elements(
            WAZUH / "decoders" / "pfsense_suricata_wanlab_decoder.xml"
        ).find("decoder")
        self.assertIsNotNone(decoder)
        assert decoder is not None
        pattern = decoder.findtext("regex")
        prematch = decoder.findtext("prematch")
        order = decoder.findtext("order")
        assert pattern is not None and prematch is not None and order is not None
        fields = order.split(",")
        cases = [
            (
                "[1:1000202:1] WAN LAB - SSH test "
                "[Classification: Misc activity] [Priority: 2] "
                "{TCP} 10.10.10.20:45000 -> 192.168.56.30:22",
                ("1000202", "WAN LAB - SSH test", "2", "TCP",
                 "10.10.10.20", "45000", "192.168.56.30", "22"),
            ),
            (
                "[1:1000201:1] WAN LAB - ICMP test [Priority: 3] "
                "{ICMP} 10.10.10.20 -> 192.168.56.30",
                ("1000201", "WAN LAB - ICMP test", "3", "ICMP",
                 "10.10.10.20", None, "192.168.56.30", None),
            ),
        ]
        for message, expected in cases:
            with self.subTest(message=message):
                full_log = f"Oct 27 14:00:00 pfsense suricata[123]: {message}"
                self.assertIsNotNone(re.search(prematch, full_log))
                match = re.search(pattern, full_log)
                self.assertIsNotNone(match)
                assert match is not None
                self.assertEqual(len(fields), len(match.groups()))
                self.assertEqual(dict(zip(fields, match.groups())),
                                 dict(zip(fields, expected)))

    def test_suricata_prematch_rejects_unrelated_signature(self) -> None:
        decoder = read_elements(
            WAZUH / "decoders" / "pfsense_suricata_wanlab_decoder.xml"
        )
        prematch = decoder.findtext("decoder/prematch")
        assert prematch is not None
        self.assertIsNone(re.search(prematch, "[1:1000206:1] WAN LAB - other"))

    def test_manager_fragments_have_expected_transport_and_threshold(self) -> None:
        remote = read_elements(WAZUH / "manager-syslog.xml")
        self.assertEqual(remote.findtext("remote/port"), "514")
        self.assertEqual(remote.findtext("remote/protocol"), "udp")
        self.assertEqual(remote.findtext("remote/allowed-ips"),
                         "CHANGE_ME_PFSENSE_SOURCE_IP")
        integration = read_elements(WAZUH / "shuffle-integration.xml")
        self.assertEqual(integration.findtext("integration/name"), "shuffle")
        self.assertEqual(integration.findtext("integration/alert_format"), "json")
        self.assertEqual(integration.findtext("integration/level"), "5")


if __name__ == "__main__":
    unittest.main()
