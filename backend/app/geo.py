"""Source address classification and optional, strictly local geolocation enrichment.

Nothing here contacts another system. A source address is first classified by
its range; only globally routable addresses may receive a location, and only
from a database file the operator placed on the laboratory host. Without such a
file every public source stays "location unknown". Locations are approximate:
they describe where an address block is registered, not who used it or where.
"""
import bisect
import csv
import logging
import os
from array import array
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from sqlalchemy import select
from .config import settings
from .models import SourceGeo, now

log = logging.getLogger("honeyforge.geo")

COUNTRIES = {
    "AE": ("ОАЭ", 24.0, 54.0), "AF": ("Афганистан", 33.9, 67.7), "AL": ("Албания", 41.2, 20.2),
    "AM": ("Армения", 40.1, 45.0), "AO": ("Ангола", -11.2, 17.9), "AR": ("Аргентина", -38.4, -63.6),
    "AT": ("Австрия", 47.5, 14.6), "AU": ("Австралия", -25.3, 133.8), "AZ": ("Азербайджан", 40.1, 47.6),
    "BA": ("Босния и Герцеговина", 43.9, 17.7), "BD": ("Бангладеш", 23.7, 90.4), "BE": ("Бельгия", 50.5, 4.5),
    "BG": ("Болгария", 42.7, 25.5), "BH": ("Бахрейн", 26.0, 50.6), "BO": ("Боливия", -16.3, -63.6),
    "BR": ("Бразилия", -14.2, -51.9), "BY": ("Беларусь", 53.7, 28.0), "CA": ("Канада", 56.1, -106.3),
    "CD": ("ДР Конго", -4.0, 21.8), "CH": ("Швейцария", 46.8, 8.2), "CI": ("Кот-д’Ивуар", 7.5, -5.5),
    "CL": ("Чили", -35.7, -71.5), "CM": ("Камерун", 7.4, 12.4), "CN": ("Китай", 35.9, 104.2),
    "CO": ("Колумбия", 4.6, -74.3), "CR": ("Коста-Рика", 9.7, -83.8), "CU": ("Куба", 21.5, -77.8),
    "CY": ("Кипр", 35.1, 33.4), "CZ": ("Чехия", 49.8, 15.5), "DE": ("Германия", 51.2, 10.5),
    "DK": ("Дания", 56.3, 9.5), "DO": ("Доминиканская Республика", 18.7, -70.2), "DZ": ("Алжир", 28.0, 1.7),
    "EC": ("Эквадор", -1.8, -78.2), "EE": ("Эстония", 58.6, 25.0), "EG": ("Египет", 26.8, 30.8),
    "ES": ("Испания", 40.5, -3.7), "ET": ("Эфиопия", 9.1, 40.5), "FI": ("Финляндия", 61.9, 25.7),
    "FR": ("Франция", 46.2, 2.2), "GB": ("Великобритания", 55.4, -3.4), "GE": ("Грузия", 42.3, 43.4),
    "GH": ("Гана", 7.9, -1.0), "GR": ("Греция", 39.1, 21.8), "GT": ("Гватемала", 15.8, -90.2),
    "HK": ("Гонконг", 22.3, 114.2), "HR": ("Хорватия", 45.1, 15.2), "HU": ("Венгрия", 47.2, 19.5),
    "ID": ("Индонезия", -0.8, 113.9), "IE": ("Ирландия", 53.4, -8.2), "IL": ("Израиль", 31.0, 34.9),
    "IN": ("Индия", 20.6, 79.0), "IQ": ("Ирак", 33.2, 43.7), "IR": ("Иран", 32.4, 53.7),
    "IS": ("Исландия", 64.9, -19.0), "IT": ("Италия", 41.9, 12.6), "JO": ("Иордания", 30.6, 36.2),
    "JP": ("Япония", 36.2, 138.3), "KE": ("Кения", -0.02, 37.9), "KG": ("Киргизия", 41.2, 74.8),
    "KH": ("Камбоджа", 12.6, 105.0), "KR": ("Республика Корея", 35.9, 127.8), "KW": ("Кувейт", 29.3, 47.5),
    "KZ": ("Казахстан", 48.0, 66.9), "LA": ("Лаос", 19.9, 102.5), "LB": ("Ливан", 33.9, 35.9),
    "LK": ("Шри-Ланка", 7.9, 80.8), "LT": ("Литва", 55.2, 23.9), "LU": ("Люксембург", 49.8, 6.1),
    "LV": ("Латвия", 56.9, 24.6), "LY": ("Ливия", 26.3, 17.2), "MA": ("Марокко", 31.8, -7.1),
    "MD": ("Молдавия", 47.4, 28.4), "ME": ("Черногория", 42.7, 19.4), "MK": ("Северная Македония", 41.6, 21.7),
    "MM": ("Мьянма", 21.9, 96.0), "MN": ("Монголия", 46.9, 103.8), "MX": ("Мексика", 23.6, -102.6),
    "MY": ("Малайзия", 4.2, 102.0), "NG": ("Нигерия", 9.1, 8.7), "NL": ("Нидерланды", 52.1, 5.3),
    "NO": ("Норвегия", 60.5, 8.5), "NP": ("Непал", 28.4, 84.1), "NZ": ("Новая Зеландия", -40.9, 174.9),
    "OM": ("Оман", 21.5, 55.9), "PA": ("Панама", 8.5, -80.8), "PE": ("Перу", -9.2, -75.0),
    "PH": ("Филиппины", 12.9, 121.8), "PK": ("Пакистан", 30.4, 69.3), "PL": ("Польша", 51.9, 19.1),
    "PT": ("Португалия", 39.4, -8.2), "PY": ("Парагвай", -23.4, -58.4), "QA": ("Катар", 25.4, 51.2),
    "RO": ("Румыния", 45.9, 25.0), "RS": ("Сербия", 44.0, 21.0), "RU": ("Россия", 61.5, 105.3),
    "SA": ("Саудовская Аравия", 23.9, 45.1), "SE": ("Швеция", 60.1, 18.6), "SG": ("Сингапур", 1.35, 103.8),
    "SI": ("Словения", 46.2, 15.0), "SK": ("Словакия", 48.7, 19.7), "SN": ("Сенегал", 14.5, -14.5),
    "SY": ("Сирия", 34.8, 39.0), "TH": ("Таиланд", 15.9, 101.0), "TJ": ("Таджикистан", 38.9, 71.3),
    "TM": ("Туркмения", 38.97, 59.6), "TN": ("Тунис", 33.9, 9.5), "TR": ("Турция", 39.0, 35.2),
    "TW": ("Тайвань", 23.7, 121.0), "TZ": ("Танзания", -6.4, 34.9), "UA": ("Украина", 48.4, 31.2),
    "UG": ("Уганда", 1.4, 32.3), "US": ("США", 39.8, -98.6), "UY": ("Уругвай", -32.5, -55.8),
    "UZ": ("Узбекистан", 41.4, 64.6), "VE": ("Венесуэла", 6.4, -66.6), "VN": ("Вьетнам", 14.1, 108.3),
    "YE": ("Йемен", 15.6, 48.5), "ZA": ("ЮАР", -30.6, 22.9), "ZM": ("Замбия", -13.1, 27.8),
    "ZW": ("Зимбабве", -19.0, 29.2),
}


SPECIAL = tuple(ip_network(block) for block in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "100.64.0.0/10", "192.0.0.0/24", "2001:db8::/32"))


def classify(value: str) -> str:
    """Routing scope of a source address: public, private, loopback or reserved."""
    address = ip_address(value)
    address = getattr(address, "ipv4_mapped", None) or address
    if address.is_loopback:
        return "loopback"
    if address.is_multicast or address.is_unspecified or address.is_reserved or address.is_link_local:
        return "reserved"
    if any(address in network for network in SPECIAL if network.version == address.version):
        return "reserved"
    if address.is_global:
        return "public"
    return "private" if address.is_private else "reserved"


class CsvDatabase:
    """Range database in the common "start,end,country[,…,city,latitude,longitude]" CSV layout.

    Three columns give a country; eight columns (start, end, continent, country, region,
    city, latitude, longitude) also give a city and coordinates. Rows are kept in compact
    arrays and searched by bisection, so a country-level file costs a few megabytes.
    """
    def __init__(self, path: str, limit: int):
        self.path, self.modified = path, datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
        self.starts = {4: array("Q"), 6: []}
        self.ends = {4: array("Q"), 6: []}
        self.records = {4: [], 6: []}
        cities, rows = {}, 0
        with open(path, newline="", encoding="utf-8") as stream:
            for row in csv.reader(stream):
                if len(row) < 3 or rows >= limit:
                    continue
                try:
                    first, last = ip_address(row[0]), ip_address(row[1])
                except ValueError:
                    continue
                detailed = len(row) >= 8
                code = (row[3] if detailed else row[2]).strip().upper()
                if len(code) != 2 or first.version != last.version:
                    continue
                record = (code, None, None, None)
                if detailed:
                    try:
                        record = (code, row[5].strip()[:120] or None, float(row[6]), float(row[7]))
                    except ValueError:
                        pass
                family = first.version
                self.starts[family].append(int(first))
                self.ends[family].append(int(last))
                self.records[family].append(cities.setdefault(record, record))
                rows += 1
        self.rows = rows
        for family in (4, 6):
            starts = self.starts[family]
            if any(starts[index] > starts[index + 1] for index in range(len(starts) - 1)):
                order = sorted(range(len(starts)), key=starts.__getitem__)
                self.starts[family] = self.pack(family, (starts[index] for index in order))
                self.ends[family] = self.pack(family, (self.ends[family][index] for index in order))
                self.records[family] = [self.records[family][index] for index in order]

    @staticmethod
    def pack(family, values):
        return array("Q", values) if family == 4 else list(values)

    def lookup(self, value: str):
        address = ip_address(value)
        number, family = int(address), address.version
        index = bisect.bisect_right(self.starts[family], number) - 1
        if index < 0 or number > self.ends[family][index]:
            return None
        return self.records[family][index]


_database = {"key": None, "value": None, "error": None}


def database():
    """The configured local database, loaded once; None when geolocation is not configured or unusable."""
    cfg = settings()
    key = (cfg.geoip_provider, cfg.geoip_database)
    if _database["key"] != key:
        _database.update(key=key, value=None, error=None)
        if cfg.geoip_provider == "csv":
            try:
                _database["value"] = CsvDatabase(cfg.geoip_database, cfg.geoip_max_rows)
                if not _database["value"].rows:
                    _database.update(value=None, error="empty")
            except OSError:
                _database["error"] = "unreadable"
            except (ValueError, csv.Error, UnicodeDecodeError):
                _database["error"] = "malformed"
            if _database["error"]:
                log.warning("База геолокации недоступна (%s); источники останутся без местоположения", _database["error"])
    return _database["value"]


def provider_status() -> dict:
    cfg = settings()
    loaded = database()
    return {"name": cfg.geoip_provider if cfg.geoip_provider == "csv" else "none",
            "ready": loaded is not None, "error": _database["error"],
            "records": loaded.rows if loaded else 0,
            "database_updated_at": loaded.modified if loaded else None,
            "attribution": cfg.geoip_attribution[:120] if loaded else "",
            "attribution_url": cfg.geoip_attribution_url[:200] if loaded and cfg.geoip_attribution_url.startswith("https://") else "",
            "external_requests": False}


def locate(address: str) -> dict:
    """Enrichment record for one address. Unknown stays unknown; nothing is guessed."""
    scope = classify(address)
    result = {"scope": scope, "country_code": None, "country_name": None, "city": None,
              "latitude": None, "longitude": None, "asn": None, "provider": "none"}
    loaded = database() if scope == "public" else None
    if not loaded:
        return result
    result["provider"] = "csv"
    record = loaded.lookup(address)
    if not record:
        return result
    code, city, latitude, longitude = record
    known = COUNTRIES.get(code)
    if latitude is None and known:
        latitude, longitude = known[1], known[2]
    result.update(country_code=code, country_name=known[0] if known else code, city=city,
                  latitude=latitude, longitude=longitude)
    return result


async def enrich(db, addresses) -> dict:
    """Cached enrichment for the given addresses; raw telemetry is never modified."""
    addresses = list(dict.fromkeys(addresses))
    if not addresses:
        return {}
    cfg = settings()
    current = "csv" if database() else "none"
    cached = {row.ip_address: row for row in (await db.scalars(select(SourceGeo).where(SourceGeo.ip_address.in_(addresses)))).all()}
    moment = now()
    for address in addresses:
        row = cached.get(address)
        expired = row and row.expires_at and row.expires_at.replace(tzinfo=row.expires_at.tzinfo or timezone.utc) < moment
        if row and row.provider == current and not expired:
            continue
        data = locate(address)
        if not row:
            row = SourceGeo(ip_address=address)
            db.add(row)
            cached[address] = row
        for key, value in data.items():
            setattr(row, key, value)
        row.enriched_at = moment
        row.expires_at = moment + timedelta(days=cfg.geoip_ttl_days) if data["scope"] == "public" else None
    await db.flush()
    return cached
