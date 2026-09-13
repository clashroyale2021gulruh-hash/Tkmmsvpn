"""
ping_tester.py — Модуль 2: Асинхронный высокопроизводительный тестер доступности
и задержки (ping) для VPN/прокси узлов.

Считывает конфигурации из configs_raw.json (результат Модуля 1), параллельно
проверяет сетевую доступность каждого сервера и порта, измеряет время отклика
в миллисекундах, отсеивает нерабочие узлы и сортирует живые конфигурации
по возрастанию пинга. Результат сохраняется в configs_tested.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Настройка логирования
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("PingTester")


# ---------------------------------------------------------------------------
# Вспомогательный парсер URI (если входной файл содержит только URI строки)
# ---------------------------------------------------------------------------
def extract_host_port_from_uri(uri: str) -> Optional[Tuple[str, int]]:
    """
    Извлекает хост и порт из прокси-URI (vless, vmess, ss, trojan, hy2 и др.).
    """
    uri = uri.strip()
    if not uri or "://" not in uri:
        return None

    scheme, rest = uri.split("://", 1)
    scheme = scheme.lower()

    # VMess часто содержит Base64-JSON
    if scheme == "vmess":
        try:
            import base64
            clean_b64 = re.sub(r"[^A-Za-z0-9+/=_-]", "", rest)
            missing = (-len(clean_b64)) % 4
            if missing:
                clean_b64 += "=" * missing
            decoded = base64.b64decode(clean_b64.replace("-", "+").replace("_", "/"))
            data = json.loads(decoded.decode("utf-8", errors="ignore"))
            server = str(data.get("add") or data.get("host") or "").strip()
            port = int(data.get("port", 0))
            if server and port > 0:
                return (server, port)
        except Exception:
            return None

    # Shadowsocks SIP002 Base64
    if scheme == "ss" and "@" not in rest and "#" in rest:
        try:
            import base64
            b64_part = rest.split("#", 1)[0].split("?", 1)[0]
            clean_b64 = re.sub(r"[^A-Za-z0-9+/=_-]", "", b64_part)
            missing = (-len(clean_b64)) % 4
            if missing:
                clean_b64 += "=" * missing
            decoded = base64.urlsafe_b64decode(clean_b64).decode("utf-8", errors="ignore")
            if "@" in decoded:
                host_port = decoded.split("@", 1)[1]
                if ":" in host_port:
                    s, p = host_port.rsplit(":", 1)
                    return (s.strip(), int(p))
        except Exception:
            pass

    # Стандартные URI: vless://, trojan://, ss://, hysteria2://
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.hostname and parsed.port:
            return (parsed.hostname, parsed.port)

        # Ручной разбор netloc при специфических символах в URI
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = netloc.split("@", 1)[1]
        if ":" in netloc:
            s, p = netloc.rsplit(":", 1)
            return (s.strip(), int(p))
    except Exception:
        pass

    return None


@dataclass
class TestedNodeResult:
    """Результат проверки отдельного узла."""
    config: str
    server: str
    port: int
    is_alive: bool
    ping_ms: Optional[int]
    error_reason: Optional[str] = None

    def to_output_dict(self) -> Dict[str, Any]:
        """Формат вывода согласно требованиям ТЗ."""
        return {
            "config": self.config,
            "ping": self.ping_ms if self.ping_ms is not None else -1,
            "status": "active" if self.is_alive else "dead",
        }


# ---------------------------------------------------------------------------
# Основной класс асинхронного тестера
# ---------------------------------------------------------------------------
class AsyncPingTester:
    """
    Асинхронный тестер сетевой доступности серверов и измерения RTT (round-trip latency).
    """

    def __init__(
        self,
        timeout: float = 3.5,
        max_concurrency: int = 150,
        dns_cache: bool = True,
    ) -> None:
        """
        :param timeout: Максимальный таймаут ожидания соединения в секундах (по умолчанию 3.5 сек).
        :param max_concurrency: Количество одновременно проверяемых узлов.
        :param dns_cache: Использовать локальное кэширование DNS для ускорения тестов.
        """
        self.timeout: float = timeout
        self.max_concurrency: int = max_concurrency
        self.semaphore: asyncio.Semaphore = asyncio.Semaphore(max_concurrency)
        self._dns_cache: Dict[str, str] = {} if dns_cache else {}

    async def _test_tcp_connection(self, host: str, port: int) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Проверяет установление TCP-соединения (SYN -> SYN-ACK) с сервером на указанный порт
        и измеряет точное время отклика в миллисекундах.
        """
        start_time = time.perf_counter()
        writer: Optional[asyncio.StreamWriter] = None

        try:
            # Асинхронное открытие TCP сокета с жестким таймаутом
            connect_coro = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)

            # Вычисление времени подключения в миллисекундах
            elapsed_ms = round((time.perf_counter() - start_time) * 1000)
            return True, elapsed_ms, None

        except asyncio.TimeoutError:
            return False, None, f"Timeout (>{self.timeout:.1f}s)"
        except ConnectionRefusedError:
            return False, None, "Connection refused (port closed)"
        except (OSError, socket_error) as exc:
            # Сюда входят No route to host, Network unreachable, DNS resolution fail
            err_str = str(exc)
            if "Name or service not known" in err_str or "gaierror" in type(exc).__name__:
                return False, None, "DNS resolution failed"
            return False, None, f"Socket error: {exc}"
        except Exception as exc:
            return False, None, f"Error: {exc}"
        finally:
            if writer is not None:
                try:
                    writer.close()
                    # Закрываем поток без блокирования
                    await writer.wait_closed()
                except Exception:
                    pass

    async def test_single_node(self, raw_item: Union[Dict[str, Any], str]) -> TestedNodeResult:
        """
        Тестирует один узел с ограничением параллелизма через Semaphore.
        """
        config_str = ""
        server = ""
        port = 0

        # Разбор входного элемента
        if isinstance(raw_item, dict):
            config_str = raw_item.get("uri") or raw_item.get("config") or ""
            server = str(raw_item.get("server", "")).strip()
            port = int(raw_item.get("port", 0))

            # Если сервер и порт не были явно указаны в словаре
            if (not server or port <= 0) and config_str:
                extracted = extract_host_port_from_uri(config_str)
                if extracted:
                    server, port = extracted
        elif isinstance(raw_item, str):
            config_str = raw_item.strip()
            extracted = extract_host_port_from_uri(config_str)
            if extracted:
                server, port = extracted

        # Если не удалось извлечь сервер или порт
        if not server or port <= 0:
            logger.debug("Пропуск некорректного узла: %s", config_str[:60])
            return TestedNodeResult(
                config=config_str,
                server=server,
                port=port,
                is_alive=False,
                ping_ms=None,
                error_reason="Invalid host/port",
            )

        async with self.semaphore:
            is_alive, ping_ms, error_reason = await self._test_tcp_connection(server, port)

        if is_alive:
            logger.debug("✓ %s:%d — OK (%d ms)", server, port, ping_ms or 0)
        else:
            logger.debug("✗ %s:%d — DEAD: %s", server, port, error_reason)

        return TestedNodeResult(
            config=config_str,
            server=server,
            port=port,
            is_alive=is_alive,
            ping_ms=ping_ms,
            error_reason=error_reason,
        )

    async def test_all(
        self, items: List[Union[Dict[str, Any], str]], limit: Optional[int] = None
    ) -> List[TestedNodeResult]:
        """
        Параллельный запуск тестирования всех переданных узлов.
        """
        targets = items[:limit] if limit else items
        total_count = len(targets)
        logger.info(
            "Запуск тестирования %d узлов (concurrency=%d, timeout=%.1fs)...",
            total_count,
            self.max_concurrency,
            self.timeout,
        )

        start_time = time.perf_counter()

        # Создание задач для каждого узла
        tasks = [asyncio.create_task(self.test_single_node(item)) for item in targets]

        results: List[TestedNodeResult] = []
        alive_count = 0
        dead_count = 0
        error_stats: Dict[str, int] = {}

        # Обработка по мере готовности для вывода прогресса
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)

            if result.is_alive:
                alive_count += 1
            else:
                dead_count += 1
                reason = result.error_reason or "Unknown"
                # Группируем причины ошибок для красивого отчета
                reason_category = reason.split(":")[0]
                error_stats[reason_category] = error_stats.get(reason_category, 0) + 1

            current_done = alive_count + dead_count
            if current_done % 200 == 0 or current_done == total_count:
                logger.info(
                    "Прогресс: %d/%d (%.1f%%) | Рабочих: %d | Мертвых: %d",
                    current_done,
                    total_count,
                    (current_done / total_count) * 100,
                    alive_count,
                    dead_count,
                )

        elapsed = time.perf_counter() - start_time
        logger.info("=" * 60)
        logger.info("ИТОГИ ТЕСТИРОВАНИЯ (Модуль 2):")
        logger.info("  Всего проверено:   %d узлов", total_count)
        logger.info("  Рабочих (active):  %d (%.1f%%)", alive_count, (alive_count / max(1, total_count)) * 100)
        logger.info("  Недоступных (dead): %d", dead_count)
        if error_stats:
            logger.info("  Причины сбоев:")
            for err, cnt in sorted(error_stats.items(), key=lambda x: -x[1])[:5]:
                logger.info("    • %-28s: %d", err, cnt)
        logger.info("  Время проверки:    %.2f сек (%.1f узлов/сек)", elapsed, total_count / max(0.01, elapsed))
        logger.info("=" * 60)

        return results


# ---------------------------------------------------------------------------
# Чтение входного файла configs_raw.json
# ---------------------------------------------------------------------------
def load_raw_configs(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Загружает сырые конфигурации из файла configs_raw.json,
    поддерживая как форматы с ключом 'configs', так и прямые списки.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Файл {file_path} не найден. Сначала запустите fetcher.py!")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        if "configs" in data and isinstance(data["configs"], list):
            return data["configs"]
        elif "nodes" in data and isinstance(data["nodes"], list):
            return data["nodes"]
        return [data]
    elif isinstance(data, list):
        return data

    return []


# ---------------------------------------------------------------------------
# Сохранение отфильтрованных и отсортированных результатов в configs_tested.json
# ---------------------------------------------------------------------------
def save_tested_configs(
    results: List[TestedNodeResult],
    output_path: Union[str, Path] = "configs_tested.json",
    keep_dead: bool = False,
) -> Path:
    """
    Фильтрует, сортирует по пингу и сохраняет результат в JSON
    строго в соответствии со спецификацией ТЗ:
    [
      {
        "config": "vless://...",
        "ping": 45,
        "status": "active"
      },
      ...
    ]
    """
    path = Path(output_path)

    if keep_dead:
        nodes_to_save = results
    else:
        # Только живые узлы
        nodes_to_save = [r for r in results if r.is_alive and r.ping_ms is not None]

    # Сортировка по возрастанию пинга (от быстрых к медленным)
    sorted_nodes = sorted(
        nodes_to_save,
        key=lambda x: (not x.is_alive, x.ping_ms if x.ping_ms is not None else 999999),
    )

    formatted_output = [node.to_output_dict() for node in sorted_nodes]

    with open(path, "w", encoding="utf-8") as f:
        json.dump(formatted_output, f, ensure_ascii=False, indent=2)

    logger.info(
        "Результаты сохранены в '%s': %d активных узлов (быстрейший: %d ms, медленнейший: %d ms)",
        path.resolve(),
        len(formatted_output),
        formatted_output[0]["ping"] if formatted_output else 0,
        formatted_output[-1]["ping"] if formatted_output else 0,
    )
    return path


# ---------------------------------------------------------------------------
# Высокоуровневая функция для внешнего вызова (Pipeline integration)
# ---------------------------------------------------------------------------
async def run_ping_test(
    input_file: str = "configs_raw.json",
    output_file: str = "configs_tested.json",
    timeout: float = 3.5,
    concurrency: int = 150,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Запускает полный цикл тестирования и возвращает структурированный список активных узлов.
    """
    raw_nodes = load_raw_configs(input_file)
    tester = AsyncPingTester(timeout=timeout, max_concurrency=concurrency)
    results = await tester.test_all(raw_nodes, limit=limit)
    save_tested_configs(results, output_path=output_file)

    alive_nodes = [r for r in results if r.is_alive]
    alive_nodes.sort(key=lambda x: x.ping_ms or 999999)
    return [r.to_output_dict() for r in alive_nodes]


# ---------------------------------------------------------------------------
# CLI Точка входа
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Модуль 2: Асинхронный пинг-тестер и валидатор прокси узлов."
    )
    parser.add_argument(
        "-i", "--input",
        default="configs_raw.json",
        help="Путь к файлу с сырыми конфигурациями (по умолчанию: configs_raw.json)",
    )
    parser.add_argument(
        "-o", "--output",
        default="configs_tested.json",
        help="Путь к выходному файлу с результатами (по умолчанию: configs_tested.json)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=3.5,
        help="Таймаут соединения в секундах (по умолчанию: 3.5)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=150,
        help="Количество параллельных TCP соединений (по умолчанию: 150)",
    )
    parser.add_argument(
        "-l", "--limit",
        type=int,
        default=None,
        help="Максимальное количество конфигураций для тестирования (для быстрой проверки)",
    )
    parser.add_argument(
        "--keep-dead",
        action="store_true",
        help="Сохранять также нерабочие (dead) узлы в выходной файл",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Включить подробный вывод отладки (логирование каждого узла)",
    )

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        raw_configs = load_raw_configs(args.input)
        tester = AsyncPingTester(timeout=args.timeout, max_concurrency=args.concurrency)
        results = asyncio.run(tester.test_all(raw_configs, limit=args.limit))
        save_tested_configs(results, output_path=args.output, keep_dead=args.keep_dead)
    except KeyboardInterrupt:
        logger.warning("Тестирование прервано пользователем.")
        sys.exit(130)
    except Exception as exc:
        logger.error("Критическая ошибка: %s", exc)
        sys.exit(1)


# Для обратной совместимости с socket error
import socket
socket_error = socket.error

if __name__ == "__main__":
    main()
