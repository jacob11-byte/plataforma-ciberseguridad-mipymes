import struct
import unittest
from pathlib import Path

from agent.windows_tray import APPLICATION_ICON_RESOURCE_ID, FALLBACK_ICON_RESOURCE_ID


ROOT = Path(__file__).resolve().parents[1]
ICON = ROOT / "agent" / "assets" / "cybercheck.ico"


class AgentBrandingTest(unittest.TestCase):
    def test_icon_contains_windows_tray_and_executable_sizes(self):
        data = ICON.read_bytes()
        reserved, image_type, count = struct.unpack_from("<HHH", data)
        self.assertEqual((reserved, image_type), (0, 1))
        self.assertGreaterEqual(count, 6)
        sizes = set()
        for index in range(count):
            width, height = struct.unpack_from("<BB", data, 6 + index * 16)
            sizes.add((width or 256, height or 256))
        self.assertTrue({(16, 16), (20, 20), (24, 24), (32, 32), (48, 48), (256, 256)} <= sizes)

    def test_build_embeds_the_brand_icon_and_tray_loads_it(self):
        build = (ROOT / "agent" / "build_standalone.ps1").read_text(encoding="utf-8")
        self.assertGreaterEqual(build.count("--icon $iconPath"), 2)
        self.assertEqual(APPLICATION_ICON_RESOURCE_ID, 1)
        self.assertEqual(FALLBACK_ICON_RESOURCE_ID, 32518)


if __name__ == "__main__":
    unittest.main()
