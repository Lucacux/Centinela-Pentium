import unittest
from types import SimpleNamespace

from ip_geolocation import CountryResolver, country_from_cloudflare


class FakeReader:
    def __init__(self, database_type=""):
        self.calls = []
        self.database_type = database_type

    def country(self, ip):
        self.calls.append(ip)
        country = SimpleNamespace(
            iso_code="AR",
            names={"es": "Argentina", "en": "Argentina"},
            name="Argentina",
        )
        return SimpleNamespace(country=country, registered_country=country)

    def metadata(self):
        return SimpleNamespace(database_type=self.database_type)


class CountryExtractionTests(unittest.TestCase):
    def test_prefers_cloudflare_country_name_and_code(self):
        result = country_from_cloudflare(
            {"Country": "Argentina", "country_code": "ar"}
        )
        self.assertEqual(result.label, "Argentina (AR)")
        self.assertEqual(result.source, "Cloudflare")

    def test_supports_nested_cloudflare_geo_country_code(self):
        result = country_from_cloudflare({"geo": {"country": "UY"}})
        self.assertEqual(result.label, "UY")


class CountryResolverTests(unittest.TestCase):
    def test_private_and_loopback_addresses_are_not_geolocated(self):
        reader = FakeReader()
        resolver = CountryResolver(reader=reader)
        self.assertIsNone(resolver.resolve("192.168.1.20"))
        self.assertIsNone(resolver.resolve("127.0.0.1"))
        self.assertEqual(reader.calls, [])

    def test_local_database_result_is_cached(self):
        reader = FakeReader()
        resolver = CountryResolver(reader=reader, locale="es")
        first = resolver.resolve("8.8.8.8")
        second = resolver.resolve("8.8.8.8")
        self.assertEqual(first.label, "Argentina (AR)")
        self.assertEqual(first.source, "GeoLite2 local")
        self.assertIs(first, second)
        self.assertEqual(reader.calls, ["8.8.8.8"])

    def test_cloudflare_result_avoids_database_lookup(self):
        reader = FakeReader()
        resolver = CountryResolver(reader=reader)
        result = resolver.resolve(
            "8.8.8.8", {"country": "United States", "country_code": "US"}
        )
        self.assertEqual(result.label, "United States (US)")
        self.assertEqual(reader.calls, [])

    def test_dbip_database_is_attributed(self):
        resolver = CountryResolver(reader=FakeReader("DBIP-Country-Lite"))
        result = resolver.resolve("8.8.8.8")
        self.assertEqual(result.source, "DB-IP Lite local")

    def test_invalid_address_is_ignored(self):
        resolver = CountryResolver(reader=FakeReader())
        self.assertIsNone(resolver.resolve("not-an-ip"))

    def test_missing_database_fails_open(self):
        resolver = CountryResolver(
            database_path="/definitely/missing/GeoLite2-Country.mmdb"
        )
        self.assertIsNone(resolver.resolve("8.8.8.8"))
        self.assertIn("No existe", resolver.error)


if __name__ == "__main__":
    unittest.main()
