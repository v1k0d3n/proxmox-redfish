"""EthernetInterface must report the MAC address of the NIC.

A provisioning client matches a machine to its network configuration by MAC address and reads it from
EthernetInterfaces. Proxmox keeps the address in the `net<N>` option, but none of it reached the response, so the
client had to be told the address out of band.
"""

import unittest
from unittest.mock import MagicMock

from proxmox_redfish.api.redfish_endpoints import get_ethernet_interface_detail, parse_net_mac

MAC = "BC:24:11:61:8D:5C"


class ParseNetMacTest(unittest.TestCase):
    def test_address_is_the_value_of_the_model_key(self):
        self.assertEqual(parse_net_mac(f"e1000e={MAC},bridge=vmbr0"), MAC)

    def test_every_model_is_read_the_same_way(self):
        for model in ("virtio", "e1000", "rtl8139", "vmxnet3"):
            self.assertEqual(parse_net_mac(f"{model}={MAC},bridge=vmbr0,firewall=1"), MAC)

    def test_macaddr_spelling_is_read(self):
        self.assertEqual(parse_net_mac(f"model=virtio,macaddr={MAC},bridge=vmbr0"), MAC)

    def test_address_is_reported_upper_case(self):
        self.assertEqual(parse_net_mac(f"virtio={MAC.lower()},bridge=vmbr0"), MAC)

    def test_position_in_the_option_does_not_matter(self):
        self.assertEqual(parse_net_mac(f"bridge=vmbr0,tag=20,virtio={MAC}"), MAC)

    def test_option_without_an_address_yields_none(self):
        self.assertIsNone(parse_net_mac("virtio,bridge=vmbr0"))
        self.assertIsNone(parse_net_mac(""))

    def test_other_values_are_not_mistaken_for_an_address(self):
        self.assertIsNone(parse_net_mac("model=virtio,bridge=vmbr0,tag=20,rate=12:34"))


class EthernetInterfaceResourceTest(unittest.TestCase):
    def _interface(self, config, interface_id="net0"):
        proxmox = MagicMock()
        # The daemon resolves which node a guest is on before addressing it.
        proxmox.cluster.resources.get.return_value = [{"vmid": 106, "node": "n1", "type": "qemu"}]
        proxmox.nodes.return_value.qemu.return_value.config.get.return_value = config
        return get_ethernet_interface_detail(proxmox, 106, interface_id)

    def test_mac_address_is_reported(self):
        response = self._interface({"net0": f"e1000e={MAC},bridge=vmbr0"})
        self.assertEqual(response["MACAddress"], MAC)
        self.assertEqual(response["PermanentMACAddress"], MAC)

    def test_each_interface_reports_its_own_address(self):
        config = {"net0": f"e1000e={MAC},bridge=vmbr0", "net1": "virtio=BC:24:11:00:00:02,bridge=vmbr10"}
        self.assertEqual(self._interface(config, "net1")["MACAddress"], "BC:24:11:00:00:02")

    def test_unknown_address_is_omitted_not_nulled(self):
        response = self._interface({"net0": "virtio,bridge=vmbr0"})
        self.assertNotIn("MACAddress", response)
        self.assertNotIn("PermanentMACAddress", response)

    def test_missing_interface_is_still_not_found(self):
        _, status = self._interface({"net0": f"e1000e={MAC},bridge=vmbr0"}, "net1")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
