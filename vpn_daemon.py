"""
vpn_daemon.py — Модуль 4: Фоновый сервис-сторож (Watchdog Daemon) для VPN.

Обеспечивает непрерывную и отказоустойчивую работу VPN:
1. Запускает и контролирует процесс ядра (Sing-box / Xray) в качестве дочернего процесса.
2. Watchdog: периодически проверяет фактическую доступность интернета через активный
   прокси-канал (например, запрос на http://www.gstatic.com/generate_204 или 1.1.1.1).
3. Автоматический Failover: при обрыве соединения или превышении лимита задержки
   выбирает следующий лучший сервер из configs_tested.json, перегенерирует config.json
   (Модуль 3) и перезапускает ядро без участия пользователя.
4. При исчерпании списка живых узлов автоматически перезапускает сбор (Модуль 1 + Модуль 2).
5. Ведет подробный журнал всех событий в файле vpn_daemon.log и в консоли.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Настройка логирования (в консоль и в файл vpn_daemon.log)
# ---------------------------------------------------------------------------
LOG_FILE = "vpn_daemon.log"

logger = logging.getLogger("VPNDaemon")
logger.setLevel(logging.INFO)
logger.propagate = False

# Очистка существующих обработчиков во избежание дублирования
if logger.hasHandlers():
    logger.handlers.clear()

# Форматтер
log_formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Вывод в консоль
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# Запись в файл vpn_daemon.log
file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)


# ---------------------------------------------------------------------------
# Конфигурация параметров демона
# ---------------------------------------------------------------------------
@dataclass
class DaemonConfig:
    check_interval: float = 6.0          # Интервал между проверками связи (сек)
    check_timeout: float = 3.5           # Таймаут проверочного HTTP-запроса (сек)
    fail_threshold: int = 3              # Количество неудачных проверок подряд до переключения
    max_latency_ms: float = 2500.0       # Максимально допустимый порог задержки (мс)
    proxy_host: str = "127.0.0.1"        # Хост локального прокси
    proxy_port: int = 2080               # Порт локального Mixed/HTTP прокси
    test_url: str = "http://www.gstatic.com/generate_204"  # Эндпоинт проверки интернета
    fallback_test_url: str = "http://cp.cloudflare.com/generate_204"
    core_executable: str = "sing-box"     # Имя исполняемого файла ядра
    config_file: str = "singbox_config.json"     # Путь к конфигу ядра
    tested_file: str = "configs_tested.json"  # Файл с проверенными узлами (Модуль 2)
    mock_core: bool = False              # Тестовый режим без реального бинарника sing-box


# ---------------------------------------------------------------------------
# Класс управления процессом ядра VPN (CoreProcessController)
# ---------------------------------------------------------------------------
class CoreProcessController:
    """Управляет жизненным циклом процесса sing-box (запуск, мониторинг, перезапуск, остановка)."""

    def __init__(self, executable: str = "sing-box", config_path: str = "singbox_config.json", mock_mode: bool = False) -> None:
        self.executable = executable
        self.config_path = config_path
        self.mock_mode = mock_mode
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        """Запуск ядра VPN."""
        if self.mock_mode:
            logger.info("ℹ Режим симуляции ядра (mock_core=True): бинарник %s не запускается.", self.executable)
            return True

        if not Path(self.config_path).exists():
            logger.error("Не найден файл конфигурации '%s' для запуска ядра!", self.config_path)
            return False

        # Проверяем наличие исполняемого файла sing-box в системе
        bin_path = shutil_which(self.executable)
        if not bin_path:
            logger.warning(
                "Исполняемый файл '%s' не найден в PATH. Демон работает в режиме контроля конфигурации.",
                self.executable,
            )
            return False

        cmd = [self.executable, "run", "-c", self.config_path]
        try:
            logger.info("Запуск процесса ядра: %s", " ".join(cmd))
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            logger.info("Ядро %s успешно запущено с PID=%d", self.executable, self.process.pid)
            return True
        except Exception as exc:
            logger.error("Ошибка при запуске ядра %s: %s", self.executable, exc)
            self.process = None
            return False

    def stop(self) -> None:
        """Мягкая остановка ядра."""
        if self.process is None:
            return

        pid = self.process.pid
        logger.info("Остановка процесса ядра (PID=%d)...", pid)
        try:
            self.process.terminate()
            try:
                self.process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                logger.warning("Процесс PID=%d не ответил на SIGTERM, принудительное завершение (SIGKILL)...", pid)
                self.process.kill()
                self.process.wait()
            logger.info("Процесс ядра остановлен.")
        except Exception as exc:
            logger.error("Ошибка при остановке процесса ядра PID=%d: %s", pid, exc)
        finally:
            self.process = None

    def restart(self) -> bool:
        """Перезапуск ядра с новым файлом конфигурации."""
        logger.info("Перезапуск ядра с обновленной конфигурацией...")
        self.stop()
        time.sleep(0.5)
        return self.start()

    def is_running(self) -> bool:
        """Проверка, жив ли процесс."""
        if self.mock_mode:
            return True
        if self.process is None:
            return False
        return self.process.poll() is None


def shutil_which(cmd: str) -> Optional[str]:
    """Аналог shutil.which."""
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(path_dir) / cmd
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


# ---------------------------------------------------------------------------
# Класс Сторожевого таймера (Watchdog Network Checker)
# ---------------------------------------------------------------------------
class NetworkWatchdog:
    """Проверяет фактическую связность и измеряет задержку через локальный прокси."""

    def __init__(self, proxy_host: str, proxy_port: int, timeout: float = 3.5) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.timeout = timeout
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

        # Настраиваем urllib opener для работы через локальный HTTP/Mixed прокси
        proxy_support = urllib.request.ProxyHandler({
            "http": self.proxy_url,
            "https": self.proxy_url,
        })
        self.opener = urllib.request.build_opener(proxy_support)

    def check_connectivity(self, target_url: str) -> Tuple[bool, float, Optional[str]]:
        """
        Выполняет запрос через прокси и измеряет время отклика (пинг).
        Возвращает: (успех, задержка_мс, текст_ошибки)
        """
        start = time.perf_counter()
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Connection": "close",
            },
        )

        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                status_code = resp.status
                # 204 No Content или 200 OK свидетельствуют об успешном выходе в интернет
                if status_code in (200, 204):
                    elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
                    return True, elapsed_ms, None
                else:
                    return False, 0.0, f"Неожиданный HTTP код: {status_code}"
        except urllib.error.HTTPError as exc:
            return False, 0.0, f"HTTP Error {exc.code}"
        except urllib.error.URLError as exc:
            reason_str = str(exc.reason)
            if "timed out" in reason_str.lower():
                return False, 0.0, f"Timeout (>{self.timeout:.1f}s)"
            elif "Connection refused" in reason_str:
                return False, 0.0, "Локальный прокси-порт недоступен (ядро упало)"
            return False, 0.0, f"Сетевая ошибка: {exc.reason}"
        except Exception as exc:
            return False, 0.0, f"Ошибка соединения: {exc}"


# ---------------------------------------------------------------------------
# Основной Демон управления VPN (VPNDaemon)
# ---------------------------------------------------------------------------
class VPNDaemon:
    """
    Координирует работу всех 4 модулей системы:
    - Модуль 1 (fetcher): загрузка свежих ссылок при истощении базы
    - Модуль 2 (ping_tester): параллельный тест серверов
    - Модуль 3 (config_generator): сборка config.json под выбранный узел
    - Модуль 4 (watchdog): непрерывный мониторинг и горячий failover
    """

    def __init__(self, config: DaemonConfig) -> None:
        self.config = config
        self.watchdog = NetworkWatchdog(
            proxy_host=config.proxy_host,
            proxy_port=config.proxy_port,
            timeout=config.check_timeout,
        )
        self.core = CoreProcessController(
            executable=config.core_executable,
            config_path=config.config_file,
            mock_mode=config.mock_core,
        )
        self.active_server_index: int = 0
        self.consecutive_failures: int = 0
        self._is_running: bool = False

    def load_tested_servers(self) -> List[Dict[str, Any]]:
        """Загрузка списка протестированных серверов из configs_tested.json."""
        path = Path(self.config.tested_file)
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [x for x in data if x.get("status") == "active" and x.get("ping", -1) > 0]
        except Exception as exc:
            logger.error("Ошибка при чтении %s: %s", self.config.tested_file, exc)
            return []

    def switch_to_next_server(self, reason: str) -> bool:
        """
        Реакция на сбой: переключение на следующий сервер в списке,
        перегенерация config.json (Модуль 3) и перезапуск ядра.
        """
        logger.warning("=" * 65)
        logger.warning("🚨 СБОЙ СОЕДИНЕНИЯ: %s", reason)
        logger.warning("Инициирован процесс переключения на резервный сервер...")

        servers = self.load_tested_servers()

        # Если локальный список исчерпан, запускаем авто-обновление пула (Модули 1 и 2)
        if not servers or self.active_server_index >= len(servers) - 1:
            logger.info("Список серверов исчерпан или устарел. Запуск авто-обновления пула...")
            refreshed = self.trigger_full_pipeline_refresh()
            if refreshed:
                servers = self.load_tested_servers()
                self.active_server_index = 0
            else:
                logger.error("Не удалось обновить пул серверов.")

        if not servers:
            logger.critical("Нет доступных серверов для переключения!")
            logger.warning("=" * 65)
            return False

        # Выбираем следующий сервер
        self.active_server_index = (self.active_server_index + 1) % len(servers)
        candidate = servers[self.active_server_index]

        logger.info(
            "Выбран сервер #%d/%d (Пинг: %d ms, URI: %s...)",
            self.active_server_index + 1,
            len(servers),
            candidate.get("ping", 0),
            candidate.get("config", "")[:50],
        )

        # Вызов Модуля 3 для генерации нового config.json
        try:
            from config_generator import ConfigGeneratorService
            gen_service = ConfigGeneratorService(
                tested_file=self.config.tested_file,
                output_file=self.config.config_file,
                mixed_port=self.config.proxy_port,
            )
            # Принудительно ставим выбранный сервер во главу
            reordered_candidates = [candidate] + [s for i, s in enumerate(servers) if i != self.active_server_index]
            best_proxy, _ = gen_service.select_best_proxy(reordered_candidates)
            if best_proxy:
                from config_generator import generate_singbox_full_config
                cfg = generate_singbox_full_config(best_proxy, mixed_port=self.config.proxy_port)
                with open(self.config.config_file, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, ensure_ascii=False, indent=2)
                logger.info("✓ Конфигурация ядра '%s' обновлена под новый узел.", self.config.config_file)
            else:
                logger.error("Не удалось сгенерировать конфигурацию для узла.")
                return False
        except Exception as exc:
            logger.error("Ошибка при вызове Модуля 3: %s", exc)
            return False

        # Перезапуск процесса ядра
        self.core.restart()
        self.consecutive_failures = 0
        logger.warning("✓ Переключение завершено. Ядро перезапущено.")
        logger.warning("=" * 65)
        return True

    def trigger_full_pipeline_refresh(self) -> bool:
        """Запуск цикла Модуль 1 (Fetcher) -> Модуль 2 (Tester)."""
        logger.info("Запуск конвейера обновления: Модуль 1 (fetcher.py)...")
        try:
            # Вызов Модуля 1
            cmd_fetch = [sys.executable, "fetcher.py", "-o", "configs_raw.json", "-t", "8.0", "-c", "5"]
            sub_res = subprocess.run(cmd_fetch, capture_output=True, text=True, timeout=60)
            if sub_res.returncode != 0:
                logger.warning("Сбой fetcher.py: %s", sub_res.stderr)
                return False

            # Вызов Модуля 2
            logger.info("Запуск конвейера обновления: Модуль 2 (ping_tester.py)...")
            cmd_ping = [sys.executable, "ping_tester.py", "-i", "configs_raw.json", "-o", self.config.tested_file, "-t", "3.0", "-c", "100"]
            sub_ping = subprocess.run(cmd_ping, capture_output=True, text=True, timeout=60)
            if sub_ping.returncode != 0:
                logger.warning("Сбой ping_tester.py: %s", sub_ping.stderr)
                return False

            return True
        except Exception as exc:
            logger.error("Ошибка при авто-обновлении пула узлов: %s", exc)
            return False

    def setup_signals(self) -> None:
        """Обработка системных сигналов SIGTERM и SIGINT для корректного завершения."""
        import threading
        if threading.current_thread() is not threading.main_thread():
            return

        def _signal_handler(signum: int, frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info("Получен сигнал %s. Корректное завершение демона...", sig_name)
            self.stop()
            sys.exit(0)

        try:
            signal.signal(signal.SIGINT, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)
        except (ValueError, OSError) as exc:
            logger.debug("Не удалось зарегистрировать обработчик сигналов: %s", exc)

    def start(self, max_iterations: Optional[int] = None) -> None:
        """Главный цикл работы демона-сторожа."""
        self._is_running = True
        self.setup_signals()

        logger.info("============================================================")
        logger.info("🚀 ЗАПУСК МОДУЛЯ 4 (VPN Watchdog Daemon)")
        logger.info("  Интервал проверки:  %.1f сек", self.config.check_interval)
        logger.info("  Таймаут запроса:    %.1f сек", self.config.check_timeout)
        logger.info("  Лимит сбоев:        %d подряд", self.config.fail_threshold)
        logger.info("  Локальный прокси:   %s:%d", self.config.proxy_host, self.config.proxy_port)
        logger.info("  Контрольный URL:    %s", self.config.test_url)
        logger.info("  Файл журнала:       %s", Path(LOG_FILE).resolve())
        logger.info("============================================================")

        # 1. Проверяем наличие config.json, если нет — генерируем Модулем 3
        if not Path(self.config.config_file).exists():
            logger.info("Конфигурация ядра '%s' отсутствует, запуск генератора...", self.config.config_file)
            from config_generator import ConfigGeneratorService
            gen = ConfigGeneratorService(
                tested_file=self.config.tested_file,
                output_file=self.config.config_file,
                mixed_port=self.config.proxy_port,
            )
            gen.run(wait_if_missing=True)

        # 2. Запуск ядра
        self.core.start()

        # Даем ядру время на подъем сокетов
        time.sleep(1.0)

        iteration_count = 0
        # 3. Основной цикл мониторинга
        while self._is_running:
            try:
                iteration_count += 1
                # Проверяем доступность тестового эндпоинта
                success, latency_ms, error_msg = self.watchdog.check_connectivity(self.config.test_url)

                # Если основной URL вернул ошибку, делаем быструю контрольную проверку через запасной URL
                if not success:
                    success, latency_ms, error_msg = self.watchdog.check_connectivity(self.config.fallback_test_url)

                if success:
                    if latency_ms > self.config.max_latency_ms:
                        logger.warning("⚠ Высокий пинг: %.1f ms (порог: %.1f ms)", latency_ms, self.config.max_latency_ms)
                        self.consecutive_failures += 1
                    else:
                        logger.info("✓ Соединение стабильно | Пинг: %.1f ms | Сервер #%d", latency_ms, self.active_server_index + 1)
                        self.consecutive_failures = 0
                else:
                    self.consecutive_failures += 1
                    logger.warning(
                        "✗ Сбой проверки связи (%d/%d): %s",
                        self.consecutive_failures,
                        self.config.fail_threshold,
                        error_msg,
                    )

                # Достигнут порог сбоев -> инициируем переключение
                if self.consecutive_failures >= self.config.fail_threshold:
                    self.switch_to_next_server(reason=f"{self.config.fail_threshold} сбоев подряд ({error_msg})")
                    time.sleep(1.5)

                if max_iterations is not None and iteration_count >= max_iterations:
                    logger.info("Достигнут лимит итераций (%d). Завершение цикла мониторинга...", max_iterations)
                    break

            except Exception as exc:
                logger.error("Непредвиденное исключение в цикле Watchdog: %s", exc)

            time.sleep(self.config.check_interval)

    def stop(self) -> None:
        """Остановка демона и дочерних процессов."""
        self._is_running = False
        self.core.stop()
        logger.info("VPN Watchdog Daemon остановлен.")


# ---------------------------------------------------------------------------
# CLI интерфейс
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Модуль 4: Фоновый сервис-сторож (Watchdog Daemon) для VPN."
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=6.0,
        help="Интервал проверки сети в секундах (по умолчанию: 6.0)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=3.5,
        help="Таймаут контрольного запроса в секундах (по умолчанию: 3.5)",
    )
    parser.add_argument(
        "-f", "--threshold",
        type=int,
        default=3,
        help="Количество сбоев подряд до смены сервера (по умолчанию: 3)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=2080,
        help="Порт локального Mixed прокси (по умолчанию: 2080)",
    )
    parser.add_argument(
        "--core",
        default="sing-box",
        help="Имя исполняемого файла ядра (по умолчанию: sing-box)",
    )
    parser.add_argument(
        "--mock-core",
        action="store_true",
        help="Режим тестирования без запуска бинарного файла ядра sing-box",
    )
    parser.add_argument(
        "--test-run",
        type=int,
        default=None,
        help="Количество итераций проверки перед автоматическим завершением (для тестов)",
    )

    args = parser.parse_args()

    daemon_config = DaemonConfig(
        check_interval=args.interval,
        check_timeout=args.timeout,
        fail_threshold=args.threshold,
        proxy_port=args.port,
        core_executable=args.core,
        mock_core=args.mock_core,
    )

    daemon = VPNDaemon(daemon_config)

    # Если задан тестовый прогон на N итераций
    if args.test_run:
        logger.info("Запуск демона в режиме самопроверки на %d итераций...", args.test_run)
        daemon.start(max_iterations=args.test_run)
        daemon.stop()
        logger.info("Самопроверка успешно завершена.")
        return

    try:
        daemon.start()
    except KeyboardInterrupt:
        logger.info("Прерывание с клавиатуры.")
        daemon.stop()


if __name__ == "__main__":
    main()
