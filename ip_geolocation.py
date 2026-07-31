"""Privacy-preserving country estimation for public security-event IPs.

Cloudflare fields are preferred when present.  Otherwise lookups use a local
MaxMind GeoLite2/GeoIP2 Country database; no client IP is sent to a third-party
geolocation API.
"""

from dataclasses import dataclass
import ipaddress
from pathlib import Path


DEFAULT_DATABASE_PATHS = (
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
)


@dataclass(frozen=True)
class CountryEstimate:
    name: str = ""
    code: str = ""
    source: str = ""

    @property
    def label(self):
        if self.name and self.code and self.name.casefold() != self.code.casefold():
            return f"{self.name} ({self.code})"
        return self.name or self.code


def _clean_country_code(value):
    text = str(value or "").strip().upper()
    return text if len(text) == 2 and text.isalpha() else ""


def country_from_cloudflare(item):
    """Extract country data when a Cloudflare response includes it.

    The Access Requests REST schema currently does not guarantee this field,
    but Logpush and some Access payloads expose either ``Country``, a country
    code, or a nested ``geo.country`` value.
    """
    item = item or {}
    geo = item.get("geo") if isinstance(item.get("geo"), dict) else {}

    raw_country = (
        item.get("country_name")
        or item.get("Country")
        or item.get("country")
        or geo.get("country_name")
        or geo.get("country")
    )
    raw_code = (
        item.get("country_code")
        or item.get("country_iso_code")
        or geo.get("country_code")
        or geo.get("country_iso_code")
    )

    if isinstance(raw_country, dict):
        raw_code = raw_code or raw_country.get("code") or raw_country.get("iso_code")
        raw_country = raw_country.get("name")

    country = str(raw_country or "").strip()
    code = _clean_country_code(raw_code)
    if not code:
        code = _clean_country_code(country)
        if code:
            country = ""
    if not country and not code:
        return None
    return CountryEstimate(name=country, code=code, source="Cloudflare")


class CountryResolver:
    """Resolve public IPs locally, with a small bounded in-memory cache."""

    def __init__(
        self,
        database_path="",
        locale="es",
        cache_size=2048,
        reader=None,
    ):
        self.locale = (locale or "es").strip()
        self.cache_size = max(1, int(cache_size))
        self.database_path = self._find_database(database_path)
        self._reader = reader
        self._reader_attempted = reader is not None
        self._cache = {}
        self.error = ""

    @staticmethod
    def _find_database(configured_path):
        if configured_path:
            return str(Path(configured_path).expanduser())
        for candidate in DEFAULT_DATABASE_PATHS:
            if Path(candidate).is_file():
                return candidate
        return ""

    def _get_reader(self):
        if self._reader_attempted:
            return self._reader
        self._reader_attempted = True
        if not self.database_path:
            self.error = "No se encontró una base GeoLite2-Country.mmdb local"
            return None
        if not Path(self.database_path).is_file():
            self.error = f"No existe la base GeoIP configurada: {self.database_path}"
            return None
        try:
            from geoip2.database import Reader

            self._reader = Reader(self.database_path)
        except (ImportError, OSError, ValueError) as error:
            self.error = f"No se pudo abrir GeoIP: {error}"
        return self._reader

    def resolve(self, ip, cloudflare_item=None):
        direct = country_from_cloudflare(cloudflare_item)
        if direct:
            return direct

        try:
            address = ipaddress.ip_address(str(ip or "").strip())
        except ValueError:
            return None
        if not address.is_global:
            return None

        key = str(address)
        if key in self._cache:
            return self._cache[key]

        result = self._lookup(key)
        if len(self._cache) >= self.cache_size:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = result
        return result

    def _lookup(self, ip):
        reader = self._get_reader()
        if reader is None:
            return None
        try:
            response = reader.country(ip)
            record = response.country
            if not getattr(record, "iso_code", None):
                record = response.registered_country
            names = getattr(record, "names", {}) or {}
            name = (
                names.get(self.locale)
                or names.get("es")
                or names.get("en")
                or getattr(record, "name", "")
                or ""
            )
            code = _clean_country_code(getattr(record, "iso_code", ""))
            if not name and not code:
                return None
            return CountryEstimate(
                name=str(name).strip(),
                code=code,
                source="GeoLite2 local",
            )
        except Exception as error:
            # AddressNotFoundError and an invalid/old database must not stop the
            # security watcher.  Keep the diagnostic for DEBUG_MODE instead.
            self.error = f"Lookup GeoIP falló para {ip}: {error}"
            return None

    def close(self):
        if self._reader is not None and hasattr(self._reader, "close"):
            self._reader.close()
