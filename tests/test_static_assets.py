import unittest

from fastapi.testclient import TestClient

from app import main


class StaticAssetsTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)

    def test_brand_assets_are_served_with_their_type(self):
        logo = self.client.get("/static/brand/cybercheck-logo.jpg")
        self.assertEqual(logo.status_code, 200)
        self.assertEqual(logo.headers["content-type"], "image/jpeg")
        shield = self.client.get("/static/brand/shield.svg")
        self.assertEqual(shield.headers["content-type"], "image/svg+xml")
        favicon = self.client.get("/favicon.ico")
        self.assertEqual(favicon.content, shield.content)

    def test_brand_route_only_serves_images_from_its_folder(self):
        for name in ("..%5Cmain.py", "..", "styles.css", "missing.png"):
            self.assertEqual(self.client.get(f"/static/brand/{name}").status_code, 404, name)

    def test_panel_files_are_revalidated_after_deploys(self):
        for path in ("/login", "/reset", "/static/styles.css", "/static/app.js", "/static/device.js",
                     "/static/modules/theme.js", "/static/modules/icons.js"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertEqual(response.headers.get("cache-control"), "no-cache", path)

    def test_every_page_loads_the_theme_before_the_stylesheet(self):
        for page in ("index.html", "device.html", "login.html", "reset.html"):
            html = (main.WEB_DIR / page).read_text(encoding="utf-8")
            self.assertLess(html.index("/static/modules/theme.js"), html.index("/static/styles.css"), page)


if __name__ == "__main__":
    unittest.main()
