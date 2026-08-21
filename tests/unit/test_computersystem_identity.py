"""ComputerSystem must carry the standard identification properties.

Redfish defines UUID on ComputerSystem as matching the SMBIOS UUID byte for
byte. Proxmox records exactly that in its `smbios1` option, but none of it
reached the response, so a client had no way to tie a system back to an
inventory record.
"""

import base64
import unittest
from unittest.mock import MagicMock

from proxmox_redfish.api.redfish_endpoints import get_vm_status, parse_smbios1

UUID = "12345678-1234-5678-1234-567812345678"


class ParseSmbiosTest(unittest.TestCase):
    def test_uuid_maps_to_the_standard_property(self):
        self.assertEqual(parse_smbios1(f"uuid={UUID}"), {"UUID": UUID})

    def test_full_set_maps_to_redfish_names(self):
        raw = f"uuid={UUID},manufacturer=Acme,product=Widget,serial=SN1,sku=SKU9"
        self.assertEqual(
            parse_smbios1(raw),
            {"UUID": UUID, "Manufacturer": "Acme", "Model": "Widget", "SerialNumber": "SN1", "SKU": "SKU9"},
        )

    def test_absent_fields_are_omitted_not_nulled(self):
        """A property Proxmox knows nothing about should not appear at all."""
        result = parse_smbios1(f"uuid={UUID}")
        for absent in ("Manufacturer", "Model", "SerialNumber", "SKU"):
            self.assertNotIn(absent, result)

    def test_empty_option_yields_nothing(self):
        self.assertEqual(parse_smbios1(""), {})

    def test_version_and_family_are_not_surfaced(self):
        """Neither has a standard ComputerSystem property."""
        result = parse_smbios1(f"uuid={UUID},version=1.0,family=Servers")
        self.assertEqual(set(result), {"UUID"})

    def test_base64_values_are_decoded_only_when_flagged(self):
        encoded = base64.b64encode(b"Acme Corp").decode()
        self.assertEqual(parse_smbios1(f"manufacturer={encoded},base64=1")["Manufacturer"], "Acme Corp")

    def test_plain_values_are_not_decoded(self):
        """ "SN1234" is valid base64. Decoding it opportunistically corrupts it."""
        self.assertEqual(parse_smbios1("serial=SN1234")["SerialNumber"], "SN1234")

    def test_uuid_is_never_decoded_even_when_flagged(self):
        result = parse_smbios1(f"uuid={UUID},manufacturer={base64.b64encode(b'X').decode()},base64=1")
        self.assertEqual(result["UUID"], UUID)

    def test_the_base64_flag_is_not_reported_as_a_property(self):
        self.assertNotIn("base64", parse_smbios1(f"uuid={UUID},base64=0"))


class ComputerSystemResourceTest(unittest.TestCase):
    def _system(self, smbios1):
        proxmox = MagicMock()
        # The daemon resolves which node a guest is on before addressing it.
        proxmox.cluster.resources.get.return_value = [{"vmid": 1, "node": "n1", "type": "qemu"}]
        qemu = proxmox.nodes.return_value.qemu.return_value
        qemu.status.current.get.return_value = {"status": "stopped"}
        qemu.config.get.return_value = {"name": "vm", "memory": 2048, "smbios1": smbios1}
        return get_vm_status(proxmox, 1)

    def test_uuid_appears_on_the_resource(self):
        self.assertEqual(self._system(f"uuid={UUID}")["UUID"], UUID)

    def test_identification_properties_appear(self):
        system = self._system(f"uuid={UUID},manufacturer=Acme,product=Widget,serial=SN1,sku=SKU9")
        self.assertEqual(system["Manufacturer"], "Acme")
        self.assertEqual(system["Model"], "Widget")
        self.assertEqual(system["SerialNumber"], "SN1")
        self.assertEqual(system["SKU"], "SKU9")

    def test_a_system_without_smbios_still_renders(self):
        system = self._system("")
        self.assertEqual(system["Id"], "1")
        self.assertNotIn("UUID", system)

    def test_existing_properties_are_untouched(self):
        system = self._system(f"uuid={UUID}")
        for expected in ("@odata.id", "Id", "Name", "PowerState", "Boot", "Actions", "MemorySummary", "Status"):
            self.assertIn(expected, system)


class RemovedEndpointTest(unittest.TestCase):
    def test_the_non_standard_smbios_endpoint_is_gone(self):
        """/Systems/{id}/Bios/SMBIOS is not a Redfish URI and no route served it."""
        from proxmox_redfish.api import redfish_endpoints

        self.assertFalse(hasattr(redfish_endpoints, "get_smbios_type1"))

    def test_bios_no_longer_links_to_a_missing_resource(self):
        from proxmox_redfish.api.redfish_endpoints import get_bios

        proxmox = MagicMock()
        proxmox.nodes.return_value.qemu.return_value.config.get.return_value = {"bios": "ovmf", "boot": "order=scsi0"}
        self.assertNotIn("SMBIOS", str(get_bios(proxmox, 1)))


if __name__ == "__main__":
    unittest.main()


class MemoryIsReportedWhereItIsReadTest(unittest.TestCase):
    """Memory is a link to a collection of modules, not a place for totals.

    The daemon has no collection of modules to offer, so it offers none
    rather than offering a link that does not answer, and reports the total
    it does know from MemorySummary, which is where a client reads one.
    """

    def _system(self, extra_config=""):
        return ComputerSystemResourceTest._system(self, extra_config)

    def test_the_total_is_in_the_summary(self):
        system = self._system()
        self.assertIn("MemorySummary", system)
        self.assertIn("TotalSystemMemoryGiB", system["MemorySummary"])

    def test_no_memory_link_is_offered(self):
        """Nothing serves /Systems/{id}/Memory, so nothing points at it."""
        self.assertNotIn("Memory", self._system())

    def test_every_link_it_does_offer_is_served(self):
        """The other collections all answer, and are named as links."""
        system = self._system()
        for served in ("Bios", "Processors", "Storage", "EthernetInterfaces"):
            self.assertIn("@odata.id", system[served])
