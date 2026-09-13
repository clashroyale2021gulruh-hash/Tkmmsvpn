"""
fetcher.py — Модуль автоматического сбора, загрузки и первичной обработки
конфигураций бесплатных прокси/VPN (VLESS, VMess, Trojan, Shadowsocks и др.)
из публичных источников на GitHub.

Модуль 1 в конвейере проверки и мониторинга прокси-узлов.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import re
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# Попытка импорта httpx; при отсутствии предоставляется автономный fallback
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    import urllib.request

# ---------------------------------------------------------------------------
# Настройка логирования
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("VPNFetcher")

# ---------------------------------------------------------------------------
# Список публичных источников GitHub по умолчанию
# Проверены и активны: Россия (обход DPI / Reality), Global VLESS, VMess, Trojan, SS
# ---------------------------------------------------------------------------
DEFAULT_SOURCES: List[str] = [
    # --- Россия / СНГ (Анти-блокировки, VLESS Reality, белые списки DPI) ---
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",

    # --- Крупные агрегаторы подписок (VLESS / VMess / Trojan / Shadowsocks) ---
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/ws_tls/proxies/wstls",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/v2ray-links/v2ray-free/master/v2ray",
]

# Поддерживаемые протоколы
SUPPORTED_SCHEMES: Set[str] = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
}

# Регулярное выражение для поиска URI ссылок в тексте
URI_REGEX = re.compile(
    r"(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic)://[^\s\r\n\t]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Структуры данных (Data Models)
# ---------------------------------------------------------------------------
@dataclass
class ProxyNode:
    """
    Структурированное представление прокси-узла,
    готовое для сохранения и передачи в Модуль 2 (пинг-тестер).
    """
    id: str
    protocol: str
    server: str
    port: int
    remark: str
    uri: str
    source_url: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь для сериализации в JSON."""
        return asdict(self)

    @property
    def host_port_key(self) -> Tuple[str, int]:
        """Ключ дедупликации по хосту и порту."""
        return (self.server.lower(), self.port)

    @property
    def protocol_host_port_key(self) -> Tuple[str, str, int]:
        """Ключ дедупликации по протоколу, хосту и порту."""
        return (self.protocol.lower(), self.server.lower(), self.port)


# ---------------------------------------------------------------------------
# Вспомогательные функции парсинга и декодирования
# ---------------------------------------------------------------------------
def fix_base64_padding(s: str) -> str:
    """Добавляет недостающие символы заполнения '=' к Base64 строке."""
    clean = re.sub(r"[^A-Za-z0-9+/=_-]", "", s)
    missing = (-len(clean)) % 4
    if missing:
        clean += "=" * missing
    return clean


def try_decode_base64(raw_text: str) -> Optional[str]:
    """
    Проверяет, является ли строка Base64-кодированной подпиской,
    и декодирует её в UTF-8 текст. Поддерживает URL-safe и стандартный Base64.
    """
    stripped = raw_text.strip()
    if not stripped:
        return None

    # Если уже явно содержит URI протоколы, декодирование всей строки не требуется
    if any(f"{proto}://" in stripped for proto in SUPPORTED_SCHEMES):
        return stripped

    padded = fix_base64_padding(stripped)
    # Замена символов URL-safe на стандартный Base64 при необходимости
    normalized = padded.replace("-", "+").replace("_", "/")

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded_bytes = decoder(normalized)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace")
            # Проверяем, появились ли после декодирования известные протоколы
            if any(f"{proto}://" in decoded_text for proto in SUPPORTED_SCHEMES):
                return decoded_text
        except Exception:
            continue

    return None


def parse_vmess_uri(uri: str, source_url: str) -> Optional[ProxyNode]:
    """
    Парсер vmess:// ссылок (содержит Base64-JSON структуру).
    Формат: vmess://eyJhZGQiOiAi...In0=
    """
    raw_payload = uri[8:].strip()
    padded = fix_base64_padding(raw_payload)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            json_bytes = decoder(padded)
            data = json.loads(json_bytes.decode("utf-8", errors="ignore"))
            if not isinstance(data, dict):
                continue

            server = str(data.get("add") or data.get("host") or "").strip()
            port_val = data.get("port")
            if not server or port_val is None:
                continue

            port = int(port_val)
            remark = str(data.get("ps") or "").strip()
            node_id = f"vmess-{server}-{port}"

            extra = {
                "uuid": data.get("id"),
                "aid": data.get("aid", 0),
                "net": data.get("net"),
                "type": data.get("type"),
                "tls": data.get("tls"),
                "path": data.get("path"),
            }

            return ProxyNode(
                id=node_id,
                protocol="vmess",
                server=server,
                port=port,
                remark=remark,
                uri=uri,
                source_url=source_url,
                extra={k: v for k, v in extra.items() if v is not None},
            )
        except Exception:
            continue

    return None


def parse_shadowsocks_uri(uri: str, source_url: str) -> Optional[ProxyNode]:
    """
    Парсер ss:// ссылок.
    Поддерживает:
      1. ss://BASE64(method:password@host:port)#tag
      2. ss://BASE64(method:password)@host:port#tag
      3. ss://method:password@host:port#tag
    """
    content = uri[5:]
    remark = ""

    # Извлечение #remark/tag
    if "#" in content:
        content, raw_remark = content.split("#", 1)
        remark = urllib.parse.unquote(raw_remark).strip()

    server = ""
    port = 0
    extra: Dict[str, Any] = {}

    # Случай A: есть явный разделитель '@'
    if "@" in content:
        userinfo_part, host_part = content.split("@", 1)
        # Отсекаем query-параметры (?plugin=...)
        if "?" in host_part:
            host_part, _ = host_part.split("?", 1)
        if "/" in host_part:
            host_part = host_part.split("/", 1)[0]

        # Разбор host:port (с поддержкой IPv6 [::1]:port)
        if host_part.startswith("[") and "]:" in host_part:
            server_part, port_str = host_part[1:].split("]:", 1)
            server = server_part
        elif ":" in host_part:
            server_part, port_str = host_part.rsplit(":", 1)
            server = server_part
        else:
            return None

        try:
            port = int(port_str)
        except ValueError:
            return None

    # Случай B: вся часть закодирована в Base64 (SIP002 legacy)
    else:
        padded = fix_base64_padding(content.split("?", 1)[0].split("/", 1)[0])
        try:
            decoded = base64.urlsafe_b64decode(padded.replace("-", "+").replace("_", "/")).decode(
                "utf-8", errors="ignore"
            )
            if "@" in decoded:
                _, host_part = decoded.split("@", 1)
                if ":" in host_part:
                    server_part, port_str = host_part.rsplit(":", 1)
                    server = server_part
                    port = int(port_str)
        except Exception:
            return None

    if not server or port <= 0:
        return None

    node_id = f"ss-{server}-{port}"
    return ProxyNode(
        id=node_id,
        protocol="ss",
        server=server,
        port=port,
        remark=remark,
        uri=uri,
        source_url=source_url,
        extra=extra,
    )


def parse_standard_url_uri(uri: str, source_url: str) -> Optional[ProxyNode]:
    """
    Парсер URI со стандартным синтаксисом:
    vless://, trojan://, hysteria://, hysteria2://, hy2://, tuic://
    Формат: protocol://uuid_or_pwd@server:port?query_params#remark
    """
    try:
        parsed = urllib.parse.urlparse(uri)
        protocol = parsed.scheme.lower()
        server = parsed.hostname
        port = parsed.port

        if not server or not port:
            # Ручная попытка разбора netloc при сбоях urlparse
            netloc = parsed.netloc
            if "@" in netloc:
                netloc = netloc.split("@", 1)[1]
            if ":" in netloc:
                server, port_str = netloc.rsplit(":", 1)
                port = int(port_str)

        if not server or not port:
            return None

        remark = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ""
        query_params = dict(urllib.parse.parse_qsl(parsed.query))

        node_id = f"{protocol}-{server}-{port}"
        return ProxyNode(
            id=node_id,
            protocol=protocol,
            server=server,
            port=port,
            remark=remark,
            uri=uri,
            source_url=source_url,
            extra=query_params,
        )
    except Exception as exc:
        logger.debug("Ошибка разбора стандартного URI %s: %s", uri, exc)
        return None


def parse_single_uri(uri: str, source_url: str) -> Optional[ProxyNode]:
    """
    Диспетчер парсинга прокси-ссылки в зависимости от протокола.
    """
    uri = uri.strip()
    if not uri or "://" not in uri:
        return None

    scheme = uri.split("://", 1)[0].lower()

    if scheme == "vmess":
        return parse_vmess_uri(uri, source_url)
    elif scheme == "ss":
        return parse_shadowsocks_uri(uri, source_url)
    elif scheme in SUPPORTED_SCHEMES:
        return parse_standard_url_uri(uri, source_url)

    return None


# ---------------------------------------------------------------------------
# Класс асинхронного сборщика (ConfigFetcher)
# ---------------------------------------------------------------------------
class ConfigFetcher:
    """
    Асинхронный модуль загрузки, декодирования и дедупликации VPN конфигураций.
    """

    def __init__(
        self,
        sources: Optional[List[str]] = None,
        timeout: float = 10.0,
        max_concurrency: int = 5,
        dedup_mode: str = "protocol_host_port",  # "protocol_host_port" или "host_port"
    ) -> None:
        """
        :param sources: Список URL-адресов подписок или сырых файлов GitHub.
        :param timeout: Тайм-аут каждого HTTP-запроса в секундах.
        :param max_concurrency: Максимальное число одновременных сетевых запросов.
        :param dedup_mode: Режим дедупликации ('protocol_host_port' или 'host_port').
        """
        self.sources: List[str] = sources if sources is not None else DEFAULT_SOURCES
        self.timeout: float = timeout
        self.max_concurrency: int = max_concurrency
        self.dedup_mode: str = dedup_mode
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def _download_source_httpx(self, client: httpx.AsyncClient, url: str) -> Optional[str]:
        """Загрузка контента источника через httpx с обработкой сетевых исключений."""
        async with self._semaphore:
            try:
                logger.debug("Загрузка источника: %s", url)
                response = await client.get(
                    url,
                    timeout=self.timeout,
                    follow_redirects=True,
                    headers={
                        "User-Agent": "v2rayN/6.23 Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "Accept": "text/plain, */*",
                    },
                )
                if response.status_code == 200:
                    logger.info("✓ Успешно скачан [%d байт]: %s", len(response.content), url)
                    return response.text
                else:
                    logger.warning("✗ Ошибка ответа HTTP %d для: %s", response.status_code, url)
                    return None
            except httpx.TimeoutException:
                logger.warning("⏱ Превышен тайм-аут (%.1fs) для: %s", self.timeout, url)
            except httpx.HTTPError as exc:
                logger.warning("✗ Сетевая ошибка при запросе %s: %s", url, exc)
            except Exception as exc:
                logger.error("✗ Непредвиденная ошибка при запросе %s: %s", url, exc)
            return None

    async def _download_source_fallback(self, url: str) -> Optional[str]:
        """
        Автономный fallback-загрузчик на случай отсутствия установленного httpx.
        Использует urllib в отдельном потоке (asyncio.to_thread).
        """
        async with self._semaphore:
            def _blocking_fetch() -> Optional[str]:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "v2rayN/6.23 Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "Accept": "text/plain, */*",
                    },
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        return resp.read().decode("utf-8", errors="replace")
                return None

            try:
                logger.debug("Загрузка (fallback urllib): %s", url)
                content = await asyncio.to_thread(_blocking_fetch)
                if content:
                    logger.info("✓ Успешно скачан [%d байт]: %s", len(content), url)
                return content
            except Exception as exc:
                logger.warning("✗ Ошибка загрузки источника %s: %s", url, exc)
                return None

    def extract_uris_from_content(self, raw_content: str) -> List[str]:
        """
        Извлекает сырые URI строк из текста, автоматически распознавая Base64 подписки.
        """
        uris: List[str] = []

        # 1. Попытка декодировать весь файл как единый Base64 блок
        decoded_text = try_decode_base64(raw_content)
        content_to_process = decoded_text if decoded_text else raw_content

        # 2. Построчный проход с проверкой Base64 для каждой отдельной строки
        for line in content_to_process.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Если строка содержит URI протокол
            if any(f"{scheme}://" in line for scheme in SUPPORTED_SCHEMES):
                # Находим все совпадения по регулярному выражению
                matches = URI_REGEX.findall(line)
                if matches:
                    uris.extend(matches)
                else:
                    uris.append(line)
            else:
                # Пробуем декодировать отдельную строку как Base64
                sub_decoded = try_decode_base64(line)
                if sub_decoded:
                    matches = URI_REGEX.findall(sub_decoded)
                    uris.extend(matches)

        return uris

    def parse_and_deduplicate(
        self, raw_data_map: Dict[str, str]
    ) -> Tuple[List[ProxyNode], Dict[str, int]]:
        """
        Парсит извлеченные URI и очищает их от дубликатов.
        :param raw_data_map: Словарь {url_источника: содержимое_ответа}
        :return: (Список уникальных ProxyNode, Статистика)
        """
        seen_keys: Set[Any] = set()
        unique_nodes: List[ProxyNode] = []

        total_lines_inspected = 0
        total_uris_found = 0
        protocol_counter: Dict[str, int] = {}

        for source_url, content in raw_data_map.items():
            uris = self.extract_uris_from_content(content)
            total_lines_inspected += len(content.splitlines())
            total_uris_found += len(uris)

            for uri in uris:
                node = parse_single_uri(uri, source_url)
                if not node:
                    continue

                # Выбор ключа дедупликации
                if self.dedup_mode == "host_port":
                    dedup_key = node.host_port_key
                else:
                    dedup_key = node.protocol_host_port_key

                if dedup_key in seen_keys:
                    continue

                seen_keys.add(dedup_key)
                unique_nodes.append(node)
                protocol_counter[node.protocol] = protocol_counter.get(node.protocol, 0) + 1

        stats = {
            "total_lines_inspected": total_lines_inspected,
            "total_uris_found": total_uris_found,
            "total_unique_nodes": len(unique_nodes),
            **protocol_counter,
        }
        return unique_nodes, stats

    async def fetch_all(self) -> Tuple[List[ProxyNode], Dict[str, Any]]:
        """
        Основной асинхронный цикл сбора:
        1. Параллельная асинхронная загрузка всех источников с тайм-аутом
        2. Декодирование Base64 и парсинг URI
        3. Дедупликация
        4. Формирование структурированного отчета
        """
        logger.info("Запуск сбора конфигураций из %d источников...", len(self.sources))
        start_time = datetime.now(timezone.utc)
        raw_data_map: Dict[str, str] = {}

        if HAS_HTTPX:
            async with httpx.AsyncClient(verify=False) as client:
                tasks = [self._download_source_httpx(client, url) for url in self.sources]
                results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            logger.info("Модуль httpx не найден, используется встроенный fallback (urllib).")
            tasks = [self._download_source_fallback(url) for url in self.sources]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        successful_downloads = 0
        for url, res in zip(self.sources, results):
            if isinstance(res, str) and res:
                raw_data_map[url] = res
                successful_downloads += 1
            elif isinstance(res, Exception):
                logger.error("Исключение при обработке источника %s: %s", url, res)

        logger.info(
            "Загрузка завершена. Успешно: %d/%d источников.",
            successful_downloads,
            len(self.sources),
        )

        nodes, stats = self.parse_and_deduplicate(raw_data_map)
        elapsed_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()

        summary: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed_seconds, 2),
            "sources_total": len(self.sources),
            "sources_successful": successful_downloads,
            "stats": stats,
        }

        logger.info("=" * 60)
        logger.info("ИТОГОВЫЙ ОТЧЕТ СБОРА:")
        logger.info("  Источников опрошено:   %d (успешно: %d)", len(self.sources), successful_downloads)
        logger.info("  Строк проанализировано: %d", stats["total_lines_inspected"])
        logger.info("  Извлечено URI ссылок:  %d", stats["total_uris_found"])
        logger.info("  Уникальных узлов:      %d", stats["total_unique_nodes"])
        for proto, count in sorted(stats.items()):
            if proto not in ("total_lines_inspected", "total_uris_found", "total_unique_nodes"):
                logger.info("    • %-12s: %d", proto.upper(), count)
        logger.info("  Время выполнения:      %.2f сек", elapsed_seconds)
        logger.info("=" * 60)

        return nodes, summary

    def save_to_json(
        self,
        nodes: List[ProxyNode],
        summary: Dict[str, Any],
        output_path: str = "configs_raw.json",
    ) -> Path:
        """
        Сохраняет отфильтрованные конфигурации в локальный JSON-файл.
        Формат оптимизирован для удобного чтения и передачи в Модуль 2 (пинг-тестер).
        """
        target = Path(output_path)
        payload = {
            "metadata": summary,
            "total_count": len(nodes),
            "configs": [node.to_dict() for node in nodes],
        }

        with open(target, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        logger.info("Конфигурации сохранены в файл: %s (%d узлов)", target.resolve(), len(nodes))
        return target


# ---------------------------------------------------------------------------
# Удобная функция-обертка для вызова из других модулей (например, Модуля 2)
# ---------------------------------------------------------------------------
async def fetch_configs(
    sources: Optional[List[str]] = None,
    output_file: Optional[str] = "configs_raw.json",
    timeout: float = 10.0,
    dedup_mode: str = "protocol_host_port",
) -> List[Dict[str, Any]]:
    """
    Высокоуровневая функция для вызова из Модуля 2 (пинг-тестера) или других скриптов.
    Возвращает список словарей узлов.
    """
    fetcher = ConfigFetcher(
        sources=sources,
        timeout=timeout,
        dedup_mode=dedup_mode,
    )
    nodes, summary = await fetcher.fetch_all()
    if output_file:
        fetcher.save_to_json(nodes, summary, output_path=output_file)
    return [node.to_dict() for node in nodes]


# ---------------------------------------------------------------------------
# Точка входа CLI
# ---------------------------------------------------------------------------
def main() -> None:
    """CLI интерфейс для автономного запуска модуля fetcher.py."""
    parser = argparse.ArgumentParser(
        description="Модуль 1: Автономный асинхронный сборщик и парсер VPN/прокси подписок (GitHub)."
    )
    parser.add_argument(
        "-o", "--output",
        default="configs_raw.json",
        help="Путь к выходному JSON-файлу (по умолчанию: configs_raw.json)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=10.0,
        help="Тайм-аут HTTP-запроса к источнику в секундах (по умолчанию: 10.0)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=5,
        help="Максимальное количество параллельных соединений (по умолчанию: 5)",
    )
    parser.add_argument(
        "--dedup",
        choices=["protocol_host_port", "host_port"],
        default="protocol_host_port",
        help="Критерий дедупликации узлов (по умолчанию: protocol_host_port)",
    )
    parser.add_argument(
        "--sources-file",
        type=str,
        default=None,
        help="Текстовый файл со списком дополнительных URL источников (по одному на строку)",
    )

    args = parser.parse_args()

    sources = list(DEFAULT_SOURCES)
    if args.sources_file:
        src_path = Path(args.sources_file)
        if src_path.exists():
            with open(src_path, "r", encoding="utf-8") as f:
                custom_sources = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                sources.extend(custom_sources)
                logger.info("Загружено %d источников из файла %s", len(custom_sources), args.sources_file)

    fetcher = ConfigFetcher(
        sources=sources,
        timeout=args.timeout,
        max_concurrency=args.concurrency,
        dedup_mode=args.dedup,
    )

    try:
        nodes, summary = asyncio.run(fetcher.fetch_all())
        fetcher.save_to_json(nodes, summary, output_path=args.output)
    except KeyboardInterrupt:
        logger.warning("Процесс прерван пользователем.")
        sys.exit(130)


if __name__ == "__main__":
    main()
