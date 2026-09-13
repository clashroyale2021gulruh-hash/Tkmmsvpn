"""
config_generator.py — Модуль 3: Генератор рабочей конфигурации ядра (Sing-box / Xray).

Выбирает наиболее производительный (минимальный пинг) и валидный узел
из файла configs_tested.json (результат Модуля 2) и собирает полнофункциональный
конфигурационный файл config.json для локального запуска VPN-клиента.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import shutil
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Настройка логирования
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ConfigGenerator")


# ---------------------------------------------------------------------------
# Модель распарсенного узла для генерации Outbound
# ---------------------------------------------------------------------------
@dataclass
class ParsedProxy:
    """Унифицированная структура параметров прокси-сервера."""
    protocol: str
    server: str
    port: int
    uuid_or_password: str
    ping_ms: int
    remark: str = ""
    flow: Optional[str] = None
    security: Optional[str] = None
    sni: Optional[str] = None
    fingerprint: Optional[str] = None
    public_key: Optional[str] = None  # Reality pbk
    short_id: Optional[str] = None    # Reality sid
    transport_type: Optional[str] = None  # tcp, ws, grpc, xhttp
    transport_path: Optional[str] = None
    transport_host: Optional[str] = None
    method: Optional[str] = None  # для Shadowsocks
    raw_uri: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Парсинг прокси-URI в универсальную структуру ParsedProxy
# ---------------------------------------------------------------------------
def _fix_base64_padding(s: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9+/=_-]", "", s)
    missing = (-len(clean)) % 4
    if missing:
        clean += "=" * missing
    return clean


def parse_vless_uri(uri: str, ping_ms: int) -> Optional[ParsedProxy]:
    """Разбор VLESS ссылки (включая Reality, TLS, Vision, WS, gRPC)."""
    try:
        parsed = urllib.parse.urlparse(uri)
        user_uuid = parsed.username or ""
        server = parsed.hostname or ""
        port = parsed.port or 0

        if not user_uuid or not server or port <= 0:
            # Ручной разбор при спецсимволах
            netloc = parsed.netloc
            if "@" in netloc:
                user_uuid, hp = netloc.split("@", 1)
                if ":" in hp:
                    server, port_s = hp.rsplit(":", 1)
                    port = int(port_s)

        if not user_uuid or not server or port <= 0:
            return None

        query = dict(urllib.parse.parse_qsl(parsed.query))
        remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""

        security = query.get("security", "").lower()
        public_key = query.get("pbk") or query.get("publicKey")
        short_id = query.get("sid") or query.get("shortId")

        # Если задан pbk, но security не указан — это Reality
        if public_key and not security:
            security = "reality"

        return ParsedProxy(
            protocol="vless",
            server=server,
            port=port,
            uuid_or_password=user_uuid,
            ping_ms=ping_ms,
            remark=remark,
            flow=query.get("flow"),
            security=security,
            sni=query.get("sni") or query.get("host") or server,
            fingerprint=query.get("fp", "chrome"),
            public_key=public_key,
            short_id=short_id,
            transport_type=query.get("type", "tcp").lower(),
            transport_path=query.get("path", "/"),
            transport_host=query.get("host"),
            raw_uri=uri,
            extra=query,
        )
    except Exception as exc:
        logger.debug("Ошибка разбора VLESS: %s", exc)
        return None


def parse_vmess_uri(uri: str, ping_ms: int) -> Optional[ParsedProxy]:
    """Разбор VMess ссылки (Base64 JSON)."""
    try:
        raw_b64 = uri[8:].strip()
        padded = _fix_base64_padding(raw_b64)
        json_bytes = base64.b64decode(padded.replace("-", "+").replace("_", "/"))
        data = json.loads(json_bytes.decode("utf-8", errors="ignore"))

        server = str(data.get("add") or data.get("host") or "").strip()
        port = int(data.get("port", 0))
        uuid_val = str(data.get("id") or "").strip()
        if not server or port <= 0 or not uuid_val:
            return None

        remark = str(data.get("ps") or "").strip()
        net = str(data.get("net") or "tcp").lower()
        tls_mode = str(data.get("tls") or "").lower()

        return ParsedProxy(
            protocol="vmess",
            server=server,
            port=port,
            uuid_or_password=uuid_val,
            ping_ms=ping_ms,
            remark=remark,
            security="tls" if tls_mode == "tls" else "none",
            sni=str(data.get("sni") or data.get("host") or server),
            fingerprint=data.get("fp", "chrome"),
            transport_type=net,
            transport_path=data.get("path", "/"),
            transport_host=data.get("host"),
            raw_uri=uri,
            extra=data,
        )
    except Exception as exc:
        logger.debug("Ошибка разбора VMess: %s", exc)
        return None


def parse_trojan_uri(uri: str, ping_ms: int) -> Optional[ParsedProxy]:
    """Разбор Trojan ссылки."""
    try:
        parsed = urllib.parse.urlparse(uri)
        password = parsed.username or ""
        server = parsed.hostname or ""
        port = parsed.port or 0
        if not password or not server or port <= 0:
            return None

        query = dict(urllib.parse.parse_qsl(parsed.query))
        remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""

        return ParsedProxy(
            protocol="trojan",
            server=server,
            port=port,
            uuid_or_password=password,
            ping_ms=ping_ms,
            remark=remark,
            security="tls",
            sni=query.get("sni") or server,
            fingerprint=query.get("fp", "chrome"),
            transport_type=query.get("type", "tcp").lower(),
            transport_path=query.get("path", "/"),
            transport_host=query.get("host"),
            raw_uri=uri,
            extra=query,
        )
    except Exception as exc:
        logger.debug("Ошибка разбора Trojan: %s", exc)
        return None


def parse_shadowsocks_uri(uri: str, ping_ms: int) -> Optional[ParsedProxy]:
    """Разбор Shadowsocks (ss://) ссылки."""
    try:
        content = uri[5:]
        remark = ""
        if "#" in content:
            content, raw_rem = content.split("#", 1)
            remark = urllib.parse.unquote(raw_rem).strip()

        server = ""
        port = 0
        method = ""
        password = ""

        if "@" in content:
            userinfo, host_part = content.split("@", 1)
            # Отсекаем query
            if "?" in host_part:
                host_part = host_part.split("?", 1)[0]
            if "/" in host_part:
                host_part = host_part.split("/", 1)[0]

            if ":" in host_part:
                server, port_str = host_part.rsplit(":", 1)
                port = int(port_str)

            # userinfo может быть base64
            padded = _fix_base64_padding(userinfo)
            try:
                decoded = base64.b64decode(padded.replace("-", "+").replace("_", "/")).decode("utf-8")
                if ":" in decoded:
                    method, password = decoded.split(":", 1)
            except Exception:
                if ":" in userinfo:
                    method, password = userinfo.split(":", 1)

        if server and port > 0 and method and password:
            return ParsedProxy(
                protocol="shadowsocks",
                server=server,
                port=port,
                uuid_or_password=password,
                method=method,
                ping_ms=ping_ms,
                remark=remark,
                raw_uri=uri,
            )
    except Exception as exc:
        logger.debug("Ошибка разбора SS: %s", exc)
    return None


def parse_proxy_item(item: Dict[str, Any]) -> Optional[ParsedProxy]:
    """Диспетчер разбора элемента из configs_tested.json."""
    uri = (item.get("config") or "").strip()
    ping_ms = int(item.get("ping", 9999))

    if not uri or "://" not in uri:
        return None

    proto = uri.split("://", 1)[0].lower()
    if proto == "vless":
        return parse_vless_uri(uri, ping_ms)
    elif proto == "vmess":
        return parse_vmess_uri(uri, ping_ms)
    elif proto == "trojan":
        return parse_trojan_uri(uri, ping_ms)
    elif proto == "ss":
        return parse_shadowsocks_uri(uri, ping_ms)

    return None


# ---------------------------------------------------------------------------
# Генерация Outbound секции Sing-box
# ---------------------------------------------------------------------------
def build_singbox_outbound(proxy: ParsedProxy, tag: str = "proxy-out") -> Dict[str, Any]:
    """
    Генерирует объект outbound для ядра Sing-box на основе распарсенного узла.
    Особое внимание уделяется протоколу VLESS + XTLS-Reality.
    """
    if proxy.protocol == "vless":
        outbound: Dict[str, Any] = {
            "type": "vless",
            "tag": tag,
            "server": proxy.server,
            "server_port": proxy.port,
            "uuid": proxy.uuid_or_password,
        }

        if proxy.flow:
            outbound["flow"] = proxy.flow

        # TLS / Reality конфигурация
        if proxy.security in ("reality", "tls"):
            tls_conf: Dict[str, Any] = {
                "enabled": True,
                "server_name": proxy.sni or proxy.server,
                "utls": {
                    "enabled": True,
                    "fingerprint": proxy.fingerprint or "chrome",
                },
            }

            if proxy.security == "reality" and proxy.public_key:
                reality_conf: Dict[str, Any] = {
                    "enabled": True,
                    "public_key": proxy.public_key,
                }
                if proxy.short_id:
                    reality_conf["short_id"] = proxy.short_id
                tls_conf["reality"] = reality_conf

            outbound["tls"] = tls_conf

        # Транспортный уровень (WebSocket / gRPC)
        if proxy.transport_type == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": proxy.transport_path or "/",
                "headers": {"Host": proxy.transport_host or proxy.sni or proxy.server},
            }
        elif proxy.transport_type == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": proxy.transport_path or "",
            }

        return outbound

    elif proxy.protocol == "vmess":
        vmess_outbound: Dict[str, Any] = {
            "type": "vmess",
            "tag": tag,
            "server": proxy.server,
            "server_port": proxy.port,
            "uuid": proxy.uuid_or_password,
            "security": "auto",
            "alter_id": int(proxy.extra.get("aid", 0)),
        }
        if proxy.security == "tls":
            vmess_outbound["tls"] = {
                "enabled": True,
                "server_name": proxy.sni or proxy.server,
                "insecure": False,
            }
        if proxy.transport_type == "ws":
            vmess_outbound["transport"] = {
                "type": "ws",
                "path": proxy.transport_path or "/",
                "headers": {"Host": proxy.transport_host or proxy.server},
            }
        return vmess_outbound

    elif proxy.protocol == "trojan":
        trojan_outbound: Dict[str, Any] = {
            "type": "trojan",
            "tag": tag,
            "server": proxy.server,
            "server_port": proxy.port,
            "password": proxy.uuid_or_password,
            "tls": {
                "enabled": True,
                "server_name": proxy.sni or proxy.server,
            },
        }
        return trojan_outbound

    elif proxy.protocol == "shadowsocks":
        return {
            "type": "shadowsocks",
            "tag": tag,
            "server": proxy.server,
            "server_port": proxy.port,
            "method": proxy.method or "aes-256-gcm",
            "password": proxy.uuid_or_password,
        }

    raise ValueError(f"Неподдерживаемый протокол: {proxy.protocol}")


# ---------------------------------------------------------------------------
# Полный шаблон конфигурации Sing-box
# ---------------------------------------------------------------------------
def generate_singbox_full_config(
    proxy: ParsedProxy,
    mixed_port: int = 2080,
    enable_tun: bool = False,
) -> Dict[str, Any]:
    """
    Формирует полный готовый к запуску файл конфигурации Sing-box:
    - Локальный Mixed (SOCKS5 + HTTP) прокси-порт для подключения приложений
    - Локальный DNS резолвер с защитой от утечек
    - Основной прокси Outbound на базе выбранного лучшего узла
    - Прямые (direct) маршруты для локальной сети и блокировка рекламы
    """
    proxy_outbound = build_singbox_outbound(proxy, tag="proxy-best")

    inbounds: List[Dict[str, Any]] = [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": mixed_port,
            "sniff": True,
            "sniff_override_destination": True,
        }
    ]

    if enable_tun:
        inbounds.append({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "singbox-tun",
            "inet4_address": "172.19.0.1/30",
            "auto_route": True,
            "strict_route": True,
            "stack": "system",
            "sniff": True,
        })

    config: Dict[str, Any] = {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "tls://1.1.1.1",
                    "address_resolver": "dns-local",
                    "detour": "proxy-best",
                },
                {
                    "tag": "dns-local",
                    "address": "local",
                    "detour": "direct",
                },
            ],
            "rules": [
                {
                    "outbound": "any",
                    "server": "dns-local",
                }
            ],
            "strategy": "prefer_ipv4",
        },
        "inbounds": inbounds,
        "outbounds": [
            proxy_outbound,
            {
                "type": "direct",
                "tag": "direct",
            },
            {
                "type": "block",
                "tag": "block",
            },
            {
                "type": "dns",
                "tag": "dns-out",
            },
        ],
        "route": {
            "rules": [
                {
                    "protocol": "dns",
                    "outbound": "dns-out",
                },
                {
                    "geoip": ["private"],
                    "outbound": "direct",
                },
                {
                    "outbound": "proxy-best",
                },
            ],
            "auto_detect_interface": True,
        },
    }

    return config


# ---------------------------------------------------------------------------
# Логика резервного копирования и восстановления
# ---------------------------------------------------------------------------
def backup_existing_config(config_path: Path, backup_path: Path) -> bool:
    """Создает резервную копию текущей рабочей конфигурации."""
    try:
        if config_path.exists() and config_path.stat().st_size > 0:
            shutil.copy2(config_path, backup_path)
            logger.info("Создана резервная копия конфигурации: %s", backup_path.resolve())
            return True
    except Exception as exc:
        logger.warning("Не удалось создать бэкап: %s", exc)
    return False


def restore_backup_config(backup_path: Path, config_path: Path) -> bool:
    """Восстанавливает конфигурацию из резервной копии при сбое."""
    try:
        if backup_path.exists() and backup_path.stat().st_size > 0:
            shutil.copy2(backup_path, config_path)
            logger.info("Успешно восстановлена конфигурация из бэкапа: %s -> %s", backup_path, config_path)
            return True
    except Exception as exc:
        logger.error("Ошибка при восстановлении бэкапа: %s", exc)
    return False


# ---------------------------------------------------------------------------
# Класс управления генератором (ConfigGeneratorService)
# ---------------------------------------------------------------------------
class ConfigGeneratorService:
    """Сервисный класс для выбора лучшего узла и формирования config.json."""

    def __init__(
        self,
        tested_file: str = "configs_tested.json",
        output_file: str = "singbox_config.json",
        backup_file: str = "singbox_config.backup.json",
        mixed_port: int = 2080,
    ) -> None:
        self.tested_path = Path(tested_file)
        self.output_path = Path(output_file)
        self.backup_path = Path(backup_file)
        self.mixed_port = mixed_port

    def wait_for_tested_file(self, timeout_sec: float = 30.0, poll_interval: float = 2.0) -> bool:
        """Ожидает появления файла configs_tested.json (если Модуль 2 еще выполняется)."""
        start = time.time()
        logger.info("Ожидание появления файла '%s' (до %.1fs)...", self.tested_path, timeout_sec)
        while time.time() - start < timeout_sec:
            if self.tested_path.exists() and self.tested_path.stat().st_size > 0:
                return True
            time.sleep(poll_interval)
        return False

    def load_candidates(self) -> List[Dict[str, Any]]:
        """Загружает список протестированных узлов, фильтрует только 'active'."""
        if not self.tested_path.exists():
            raise FileNotFoundError(f"Файл {self.tested_path} отсутствует!")

        with open(self.tested_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError(f"Неверный формат данных в {self.tested_path}: ожидался список")

        # Отбираем только активные узлы с валидным пингом
        active_nodes = [
            item for item in data
            if isinstance(item, dict)
            and item.get("status") == "active"
            and item.get("ping", -1) > 0
        ]

        # Дополнительно сортируем по пингу на случай, если порядок нарушен
        active_nodes.sort(key=lambda x: x.get("ping", 99999))
        return active_nodes

    def select_best_proxy(self, candidates: List[Dict[str, Any]]) -> Tuple[Optional[ParsedProxy], int]:
        """
        Ищет первый доступный узел с минимальным пингом,
        который успешно парсится в поддерживаемый формат Sing-box.
        При ошибке парсинга узла переходит к следующему по скорости.
        """
        for index, item in enumerate(candidates):
            parsed = parse_proxy_item(item)
            if parsed is not None:
                return parsed, index
            else:
                logger.debug("Пропуск узла #%d: не удалось распознать формат", index + 1)

        return None, -1

    def run(self, wait_if_missing: bool = False, max_wait_sec: float = 20.0) -> Optional[ParsedProxy]:
        """
        Главная функция генерации:
        1. Проверка наличия configs_tested.json (с опциональным ожиданием)
        2. Загрузка и отбор лучшего узла с минимальным пингом
        3. Обработка сценариев отказа (восстановление из бэкапа)
        4. Создание бэкапа текущего config.json
        5. Запись нового config.json
        """
        logger.info("Запуск Модуля 3 (Генератор конфигурации Sing-box)...")

        # 1. Проверка существования файла
        if not self.tested_path.exists() or self.tested_path.stat().st_size == 0:
            if wait_if_missing:
                found = self.wait_for_tested_file(timeout_sec=max_wait_sec)
                if not found:
                    self._handle_failure("Таймаут ожидания файла configs_tested.json")
                    return None
            else:
                self._handle_failure(f"Файл {self.tested_path} не найден!")
                return None

        # 2. Загрузка кандидатов
        try:
            candidates = self.load_candidates()
        except Exception as exc:
            self._handle_failure(f"Ошибка чтения кандидатов: {exc}")
            return None

        if not candidates:
            self._handle_failure("Список рабочих серверов в configs_tested.json пуст!")
            return None

        logger.info("Загружено %d активных серверов из '%s'", len(candidates), self.tested_path)

        # 3. Выбор лучшего сервера
        best_proxy, rank = self.select_best_proxy(candidates)
        if best_proxy is None:
            self._handle_failure("Не удалось спарсить ни один из активных серверов!")
            return None

        logger.info("=" * 60)
        logger.info("ВЫБРАН ЛУЧШИЙ СЕРВЕР (#%d в рейтинге пинга):", rank + 1)
        logger.info("  Протокол:   %s", best_proxy.protocol.upper())
        logger.info("  Адрес:      %s:%d", best_proxy.server, best_proxy.port)
        logger.info("  Пинг:       %d ms", best_proxy.ping_ms)
        if best_proxy.security:
            logger.info("  Защита:     %s (SNI: %s)", best_proxy.security, best_proxy.sni)
        if best_proxy.public_key:
            logger.info("  Reality PK: %s...", best_proxy.public_key[:12])
        if best_proxy.remark:
            logger.info("  Имя узла:   %s", best_proxy.remark)
        logger.info("=" * 60)

        # 4. Бэкап существующей конфигурации
        if self.output_path.exists():
            backup_existing_config(self.output_path, self.backup_path)

        # 5. Шаблонизация и сохранение config.json
        full_config = generate_singbox_full_config(
            proxy=best_proxy,
            mixed_port=self.mixed_port,
        )

        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(full_config, f, ensure_ascii=False, indent=2)

        logger.info(
            "✓ Итоговый файл конфигурации сохранен: '%s' (Mixed Proxy: 127.0.0.1:%d)",
            self.output_path.resolve(),
            self.mixed_port,
        )
        return best_proxy

    def _handle_failure(self, reason: str) -> None:
        """Обработка ошибок: оповещение и автоматическое восстановление бэкапа."""
        logger.error("⚠ СБОЙ МОДУЛЯ 3: %s", reason)
        if self.backup_path.exists():
            logger.info("Попытка активировать резервную конфигурацию '%s'...", self.backup_path)
            restored = restore_backup_config(self.backup_path, self.output_path)
            if restored:
                logger.warning("Ядро сохранит работоспособность на предыдущей резервной конфигурации.")
                return

        logger.critical(
            "Резервная копия не найдена! Убедитесь, что Модуль 1 (fetcher) и Модуль 2 (ping_tester) завершились успешно."
        )


# ---------------------------------------------------------------------------
# Удобная высокоуровневая функция для внешнего вызова (Pipeline)
# ---------------------------------------------------------------------------
def generate_config(
    input_file: str = "configs_tested.json",
    output_file: str = "singbox_config.json",
    backup_file: str = "singbox_config.backup.json",
    mixed_port: int = 2080,
    wait_if_missing: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Функция для прямого вызова из Python пайплайнов или скриптов автоматизации.
    Возвращает сгенерированный словарь конфигурации Sing-box.
    """
    service = ConfigGeneratorService(
        tested_file=input_file,
        output_file=output_file,
        backup_file=backup_file,
        mixed_port=mixed_port,
    )
    proxy = service.run(wait_if_missing=wait_if_missing)
    if proxy and service.output_path.exists():
        with open(service.output_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


# ---------------------------------------------------------------------------
# CLI Точка входа
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Модуль 3: Генератор рабочей конфигурации ядра (Sing-box)."
    )
    parser.add_argument(
        "-i", "--input",
        default="configs_tested.json",
        help="Входной файл с протестированными серверами (по умолчанию: configs_tested.json)",
    )
    parser.add_argument(
        "-o", "--output",
        default="singbox_config.json",
        help="Выходной файл конфигурации ядра (по умолчанию: singbox_config.json)",
    )
    parser.add_argument(
        "-b", "--backup",
        default="singbox_config.backup.json",
        help="Путь для резервной копии (по умолчанию: singbox_config.backup.json)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=2080,
        help="Локальный Mixed SOCKS5/HTTP порт (по умолчанию: 2080)",
    )
    parser.add_argument(
        "-w", "--wait",
        action="store_true",
        help="Ожидать появление файла configs_tested.json, если он еще формируется Модулем 2",
    )
    parser.add_argument(
        "--wait-timeout",
        type=float,
        default=30.0,
        help="Максимальное время ожидания файла в секундах (по умолчанию: 30.0)",
    )

    args = parser.parse_args()

    service = ConfigGeneratorService(
        tested_file=args.input,
        output_file=args.output,
        backup_file=args.backup,
        mixed_port=args.port,
    )

    result = service.run(wait_if_missing=args.wait, max_wait_sec=args.wait_timeout)
    if result is None:
        sys.exit(1)


if __name__ == "__main__":
    main()
