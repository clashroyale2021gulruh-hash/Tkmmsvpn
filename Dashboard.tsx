import React, { useState, useEffect, useRef, useMemo } from "react";
import {
  Shield,
  ShieldCheck,
  Activity,
  Zap,
  RefreshCw,
  Copy,
  Check,
  Terminal,
  Server,
  Globe,
  ArrowUpDown,
  Search,
  Wifi,
  AlertCircle,
  Pause,
  Play,
  Trash2,
  ChevronRight,
  ExternalLink,
} from "lucide-react";

// ============================================================================
// Типы данных
// ============================================================================
export interface ServerNode {
  id: string;
  config: string;
  server: string;
  port: number;
  protocol: "vless" | "vmess" | "trojan" | "ss";
  country: string;
  flag: string;
  city: string;
  security: string;
  ping: number;
  status: "active" | "testing" | "dead";
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: "INFO" | "WARNING" | "ERROR" | "DEBUG";
  message: string;
}

// ============================================================================
// Мок-данные (на основе реальных серверов из нашей системы)
// ============================================================================
const INITIAL_SERVERS: ServerNode[] = [
  {
    id: "node-1",
    config: "vless://e8358eb5-7210-4cf8-982f-68af141b7694@56.69.159.191:53271?security=reality&flow=xtls-rprx-vision&pbk=1P58ZYmo81kP...&sni=www.tesla.com#Malaysia",
    server: "56.69.159.191",
    port: 53271,
    protocol: "vless",
    country: "Malaysia",
    city: "Kuala Lumpur",
    flag: "🇲🇾",
    security: "Reality (Vision)",
    ping: 42,
    status: "active",
  },
  {
    id: "node-2",
    config: "vless://e2b8b217-cffb-4d66-9b8b-eca6e4334032@13.231.19.51:11690?security=reality&flow=xtls-rprx-vision&pbk=Bv3z0_uFRab...&sni=www.tesla.com#Japan",
    server: "13.231.19.51",
    port: 11690,
    protocol: "vless",
    country: "Japan",
    city: "Shibuya, Tokyo",
    flag: "🇯🇵",
    security: "Reality (Vision)",
    ping: 48,
    status: "active",
  },
  {
    id: "node-3",
    config: "vless://f053b140-9673-4ac5-bc8b-587bfd2c8fd8@54.255.121.205:43840?security=reality&flow=xtls-rprx-vision&pbk=tDzxVcXg6zz...&sni=www.sony.com#Singapore",
    server: "54.255.121.205",
    port: 43840,
    protocol: "vless",
    country: "Singapore",
    city: "Downtown Core",
    flag: "🇸🇬",
    security: "Reality (Vision)",
    ping: 74,
    status: "active",
  },
  {
    id: "node-4",
    config: "vless://167ed405-7de9-4bff-b1ea-6e3d49c76b0b@172.238.232.239:32833?security=reality&flow=xtls-rprx-vision&pbk=PaTDdYBrlh1...&sni=www.intel.com#Italy",
    server: "172.238.232.239",
    port: 32833,
    protocol: "vless",
    country: "Italy",
    city: "Milan",
    flag: "🇮🇹",
    security: "Reality (Vision)",
    ping: 110,
    status: "active",
  },
  {
    id: "node-5",
    config: "vmess://eyJ2IjoiMiIsInBzIjoiR2VybWFueSIsImFkZCI6IjE4OC4yNTMuMjUuMTcyIiwicG9ydCI6IjQ0MyJ9",
    server: "188.253.25.172",
    port: 443,
    protocol: "vmess",
    country: "Germany",
    city: "Frankfurt am Main",
    flag: "🇩🇪",
    security: "TLS (WS)",
    ping: 135,
    status: "active",
  },
  {
    id: "node-6",
    config: "vless://10de5732-5d62-43bd-80a2-ec678100824a@151.242.169.119:443?security=reality&sni=yidio.com#Norway",
    server: "151.242.169.119",
    port: 443,
    protocol: "vless",
    country: "Norway",
    city: "Sandefjord",
    flag: "🇳🇴",
    security: "Reality (TCP)",
    ping: 152,
    status: "active",
  },
];

const INITIAL_LOGS: LogEntry[] = [
  {
    id: "l-1",
    timestamp: "18:44:15",
    level: "INFO",
    message: "[ConfigGenerator] Загружено 19 активных серверов из configs_tested.json",
  },
  {
    id: "l-2",
    timestamp: "18:44:16",
    level: "INFO",
    message: "[ConfigGenerator] Выбран лучший сервер: 56.69.159.191:53271 (42 ms)",
  },
  {
    id: "l-3",
    timestamp: "18:44:16",
    level: "INFO",
    message: "[Sing-box] Ядро успешно запущено на 127.0.0.1:2080 (Mixed HTTP/SOCKS5)",
  },
  {
    id: "l-4",
    timestamp: "18:44:18",
    level: "INFO",
    message: "[Watchdog] Проверка связи через 127.0.0.1:2080: OK (42.4 ms)",
  },
  {
    id: "l-5",
    timestamp: "18:44:24",
    level: "INFO",
    message: "[Watchdog] Проверка связи: OK (43.1 ms) | Потерь: 0%",
  },
];

// ============================================================================
// Главный компонент Dashboard
// ============================================================================
export default function Dashboard() {
  const [servers, setServers] = useState<ServerNode[]>(INITIAL_SERVERS);
  const [activeServerId, setActiveServerId] = useState<string>("node-1");
  const [isSwitching, setIsSwitching] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [sortAsc, setSortAsc] = useState<boolean>(true);
  const [daemonActive, setDaemonActive] = useState<boolean>(true);
  const [logs, setLogs] = useState<LogEntry[]>(INITIAL_LOGS);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [selectedLogLevel, setSelectedLogLevel] = useState<string>("ALL");
  const [uptimeSeconds, setUptimeSeconds] = useState<number>(3842);

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Текущий активный сервер
  const currentServer = useMemo(
    () => servers.find((s) => s.id === activeServerId) || servers[0],
    [servers, activeServerId]
  );

  // Таймер аптайма
  useEffect(() => {
    const timer = setInterval(() => {
      setUptimeSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Имитация динамического изменения пинга активного сервера и генерации логов
  useEffect(() => {
    if (!daemonActive) return;

    const interval = setInterval(() => {
      // Флуктуация пинга активного сервера (+/- 3 мс)
      setServers((prevServers) =>
        prevServers.map((srv) => {
          if (srv.id === activeServerId) {
            const jitter = Math.floor(Math.random() * 5) - 2;
            const newPing = Math.max(25, srv.ping + jitter);
            return { ...srv, ping: newPing };
          }
          return srv;
        })
      );

      // Генерация строки лога от Watchdog
      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0];
      const jitterMs = (Math.random() * 4 + 40).toFixed(1);

      const newLog: LogEntry = {
        id: `log-${Date.now()}`,
        timestamp: timeStr,
        level: "INFO",
        message: `[Watchdog] Запрос к http://www.gstatic.com/generate_204: OK (${jitterMs} ms)`,
      };

      setLogs((prev) => [...prev.slice(-99), newLog]);
    }, 4500);

    return () => clearInterval(interval);
  }, [daemonActive, activeServerId]);

  // Автопрокрутка логов
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  // Принудительное переключение на следующий сервер (Ручной Failover)
  const handleForceSwitch = () => {
    if (isSwitching) return;
    setIsSwitching(true);

    const now = new Date().toTimeString().split(" ")[0];
    setLogs((prev) => [
      ...prev,
      {
        id: `log-${Date.now()}`,
        timestamp: now,
        level: "WARNING",
        message: "[ManualTrigger] Инициирована принудительная смена узла пользователем...",
      },
    ]);

    setTimeout(() => {
      const currentIndex = servers.findIndex((s) => s.id === activeServerId);
      const nextIndex = (currentIndex + 1) % servers.length;
      const nextServer = servers[nextIndex];
      setActiveServerId(nextServer.id);

      const switchTime = new Date().toTimeString().split(" ")[0];
      setLogs((prev) => [
        ...prev,
        {
          id: `log-${Date.now() + 1}`,
          timestamp: switchTime,
          level: "INFO",
          message: `[ConfigGenerator] Сгенерирован config.json -> Узел #${nextIndex + 1} (${nextServer.server})`,
        },
        {
          id: `log-${Date.now() + 2}`,
          timestamp: switchTime,
          level: "INFO",
          message: `[Sing-box] Ядро перезапущено на узле [${nextServer.country}] (Пинг: ${nextServer.ping} ms)`,
        },
      ]);

      setIsSwitching(false);
    }, 900);
  };

  // Копирование конфигурационного URI
  const handleCopyConfig = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Очистить терминал
  const handleClearLogs = () => {
    setLogs([]);
  };

  // Фильтрация и сортировка серверов
  const filteredServers = useMemo(() => {
    return servers
      .filter(
        (s) =>
          s.country.toLowerCase().includes(searchQuery.toLowerCase()) ||
          s.city.toLowerCase().includes(searchQuery.toLowerCase()) ||
          s.server.includes(searchQuery) ||
          s.protocol.includes(searchQuery.toLowerCase())
      )
      .sort((a, b) => (sortAsc ? a.ping - b.ping : b.ping - a.ping));
  }, [servers, searchQuery, sortAsc]);

  // Фильтрация логов по уровню
  const filteredLogs = useMemo(() => {
    if (selectedLogLevel === "ALL") return logs;
    return logs.filter((l) => l.level === selectedLogLevel);
  }, [logs, selectedLogLevel]);

  // Форматирование секунд в HH:MM:SS
  const formatUptime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hrs.toString().padStart(2, "0")}:${mins
      .toString()
      .padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Фоновые декоративные градиенты */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-emerald-500/10 rounded-full blur-[128px]" />
        <div className="absolute top-1/3 -right-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-[128px]" />
        <div className="absolute -bottom-40 left-1/3 w-96 h-96 bg-blue-500/10 rounded-full blur-[128px]" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* ==================================================================== */}
        {/* 1. ШАПКА (HEADER)                                                    */}
        {/* ==================================================================== */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 backdrop-blur-xl border border-slate-800/80 shadow-2xl">
          <div className="flex items-center space-x-3.5">
            <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-500 text-white shadow-[0_0_20px_rgba(6,182,212,0.4)]">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                  Nexus VPN Automator
                </h1>
                <span className="px-2 py-0.5 text-[11px] font-semibold tracking-wide uppercase rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  Sing-box Core
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Автономный отказоустойчивый конвейер (Модули 1–4)
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* Статус демона */}
            <div className="flex items-center space-x-2.5 px-3.5 py-1.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs">
              <span className="relative flex h-2.5 w-2.5">
                {daemonActive ? (
                  <>
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500 shadow-[0_0_10px_#10b981]" />
                  </>
                ) : (
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500" />
                )}
              </span>
              <span className="font-medium text-slate-300">
                {daemonActive ? "Демон активен (Watchdog)" : "Демон остановлен"}
              </span>
            </div>

            {/* Аптайм */}
            <div className="hidden md:flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-400">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Аптайм:</span>
              <span className="font-mono text-slate-200">{formatUptime(uptimeSeconds)}</span>
            </div>

            {/* Кнопка включения/выключения демона */}
            <button
              onClick={() => setDaemonActive(!daemonActive)}
              title={daemonActive ? "Приостановить мониторинг" : "Запустить мониторинг"}
              className={`p-2 rounded-xl border transition-all duration-200 ${
                daemonActive
                  ? "bg-slate-800 hover:bg-slate-700/80 border-slate-700 text-emerald-400"
                  : "bg-rose-950/40 hover:bg-rose-900/40 border-rose-800/60 text-rose-400"
              }`}
            >
              {daemonActive ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            </button>
          </div>
        </header>

        {/* ==================================================================== */}
        {/* 2. БЫСТРЫЕ МЕТРИКИ СИСТЕМЫ                                          */}
        {/* ==================================================================== */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-2xl bg-slate-900/40 backdrop-blur-md border border-slate-800/80 hover:border-slate-700/80 transition-all">
            <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
              <span>Текущий пинг</span>
              <Wifi className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="flex items-baseline space-x-1.5">
              <span className="text-2xl font-bold font-mono text-emerald-400">
                {currentServer.ping}
              </span>
              <span className="text-xs text-slate-400">ms</span>
            </div>
            <p className="text-[11px] text-emerald-500/90 mt-1 flex items-center">
              <Check className="w-3 h-3 mr-1" /> Оптимальная задержка
            </p>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/40 backdrop-blur-md border border-slate-800/80 hover:border-slate-700/80 transition-all">
            <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
              <span>Активных узлов</span>
              <Server className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="flex items-baseline space-x-1.5">
              <span className="text-2xl font-bold font-mono text-cyan-400">
                {servers.length}
              </span>
              <span className="text-xs text-slate-400">серверов</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              В пуле <code className="text-slate-300">configs_tested.json</code>
            </p>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/40 backdrop-blur-md border border-slate-800/80 hover:border-slate-700/80 transition-all">
            <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
              <span>Локальный порт</span>
              <Zap className="w-4 h-4 text-amber-400" />
            </div>
            <div className="flex items-baseline space-x-1.5">
              <span className="text-2xl font-bold font-mono text-amber-400">2080</span>
              <span className="text-xs text-slate-400">Mixed</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              SOCKS5 & HTTP: 127.0.0.1:2080
            </p>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/40 backdrop-blur-md border border-slate-800/80 hover:border-slate-700/80 transition-all">
            <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
              <span>Защита протокола</span>
              <ShieldCheck className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="flex items-baseline space-x-1.5">
              <span className="text-xl font-bold text-indigo-300">XTLS Reality</span>
            </div>
            <p className="text-[11px] text-indigo-400/90 mt-1">
              uTLS Chrome • Anti-DPI bypass
            </p>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* 3. ГЛАВНАЯ КАРТОЧКА СТАТУСА (CURRENT CONNECTION HERO)                */}
        {/* ==================================================================== */}
        <section className="relative overflow-hidden p-6 rounded-3xl bg-gradient-to-br from-slate-900/90 via-slate-900/60 to-slate-950/80 backdrop-blur-2xl border border-slate-800/80 shadow-2xl">
          {/* Акцентная подсветка карточки */}
          <div className="absolute top-0 right-0 -mt-8 -mr-8 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="space-y-3">
              <div className="flex items-center space-x-2.5">
                <span className="px-3 py-1 text-xs font-semibold rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 flex items-center shadow-[0_0_12px_rgba(16,185,129,0.3)]">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse" />
                  АКТИВНОЕ ПОДКЛЮЧЕНИЕ
                </span>
                <span className="text-xs text-slate-400">
                  Ядро: <strong className="text-slate-200">Sing-box v1.9.0</strong>
                </span>
              </div>

              <div className="flex items-center space-x-3.5">
                <span className="text-4xl">{currentServer.flag}</span>
                <div>
                  <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
                    {currentServer.country}, {currentServer.city}
                  </h2>
                  <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-slate-400 font-mono">
                    <span className="px-2 py-0.5 rounded-md bg-slate-800/80 text-slate-200">
                      {currentServer.server}:{currentServer.port}
                    </span>
                    <span className="px-2 py-0.5 rounded-md bg-cyan-950/50 border border-cyan-800/40 text-cyan-300 uppercase">
                      {currentServer.protocol}
                    </span>
                    <span className="px-2 py-0.5 rounded-md bg-slate-800/80 text-slate-300">
                      {currentServer.security}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Метрика пинга и кнопка действия */}
            <div className="flex flex-wrap items-center gap-4 sm:gap-6 bg-slate-950/60 p-4 rounded-2xl border border-slate-800/80">
              <div className="text-right pr-2">
                <div className="text-xs text-slate-400 mb-0.5">Текущий RTT</div>
                <div className="flex items-baseline space-x-1 justify-end">
                  <span
                    className={`text-3xl font-extrabold font-mono transition-colors ${
                      currentServer.ping < 50
                        ? "text-emerald-400"
                        : currentServer.ping < 120
                        ? "text-amber-400"
                        : "text-rose-400"
                    }`}
                  >
                    {currentServer.ping}
                  </span>
                  <span className="text-xs font-semibold text-slate-400">ms</span>
                </div>
                <div className="text-[10px] text-slate-500 font-mono">
                  {currentServer.ping < 50 ? "Отличный пинг" : "Нормальный"}
                </div>
              </div>

              <button
                onClick={handleForceSwitch}
                disabled={isSwitching}
                className="group relative inline-flex items-center justify-center px-5 py-3 rounded-xl font-medium text-sm text-white bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 active:scale-[0.98] transition-all shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:shadow-[0_0_25px_rgba(6,182,212,0.5)] disabled:opacity-50 disabled:pointer-events-none"
              >
                <RefreshCw
                  className={`w-4 h-4 mr-2 transition-transform duration-700 ${
                    isSwitching ? "animate-spin" : "group-hover:rotate-180"
                  }`}
                />
                <span>
                  {isSwitching ? "Переключение..." : "Сменить сервер (Failover)"}
                </span>
              </button>
            </div>
          </div>
        </section>

        {/* ==================================================================== */}
        {/* 4. СЕТКА: СПИСОК СЕРВЕРОВ + ЖИВОЙ ТЕРМИНАЛ ЛОГОВ                     */}
        {/* ==================================================================== */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* ЛЕВАЯ КОЛОНКА: Список проверенных серверов (7 колонок) */}
          <div className="lg:col-span-7 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center space-x-2">
                <Server className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">
                  Проверенные узлы ({filteredServers.length})
                </h3>
              </div>

              {/* Поиск и сортировка */}
              <div className="flex items-center space-x-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Поиск узла, страны..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-44 sm:w-52 pl-8 pr-3 py-1.5 text-xs bg-slate-900/80 border border-slate-800 rounded-xl text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
                  />
                </div>

                <button
                  onClick={() => setSortAsc(!sortAsc)}
                  title="Сортировать по пингу"
                  className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-medium bg-slate-900/80 hover:bg-slate-800 border border-slate-800 rounded-xl text-slate-300 transition-colors"
                >
                  <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{sortAsc ? "Быстрые ↑" : "Медленные ↓"}</span>
                </button>
              </div>
            </div>

            {/* Таблица / Список серверов */}
            <div className="space-y-2.5 max-h-[480px] overflow-y-auto pr-1">
              {filteredServers.map((node, index) => {
                const isActive = node.id === activeServerId;
                return (
                  <div
                    key={node.id}
                    onClick={() => setActiveServerId(node.id)}
                    className={`group relative flex items-center justify-between p-3.5 rounded-2xl border transition-all cursor-pointer ${
                      isActive
                        ? "bg-slate-900/90 border-cyan-500/60 shadow-[0_0_15px_rgba(6,182,212,0.15)] ring-1 ring-cyan-500/30"
                        : "bg-slate-900/40 hover:bg-slate-900/70 border-slate-800/80 hover:border-slate-700"
                    }`}
                  >
                    {/* Левая часть: Флаг, Название, Протокол */}
                    <div className="flex items-center space-x-3 min-w-0">
                      <span className="text-2xl select-none">{node.flag}</span>
                      <div className="min-w-0">
                        <div className="flex items-center space-x-2">
                          <span className="text-sm font-semibold text-slate-100 truncate">
                            {node.country}
                          </span>
                          <span className="text-xs text-slate-400 truncate hidden sm:inline">
                            • {node.city}
                          </span>
                          {isActive && (
                            <span className="px-1.5 py-0.2 text-[10px] font-bold rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                              ACTIVE
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono truncate flex items-center gap-1.5 mt-0.5">
                          <span className="uppercase text-cyan-400 font-bold">
                            {node.protocol}
                          </span>
                          <span>{node.server}:{node.port}</span>
                        </div>
                      </div>
                    </div>

                    {/* Правая часть: Пинг, Копирование, Кнопка */}
                    <div className="flex items-center space-x-3 ml-2 flex-shrink-0">
                      {/* Индикатор пинга */}
                      <div className="text-right">
                        <span
                          className={`text-sm font-bold font-mono ${
                            node.ping < 50
                              ? "text-emerald-400"
                              : node.ping < 120
                              ? "text-amber-400"
                              : "text-rose-400"
                          }`}
                        >
                          {node.ping} ms
                        </span>
                      </div>

                      {/* Кнопка копирования ссылки */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopyConfig(node.id, node.config);
                        }}
                        title="Скопировать URI в буфер обмена"
                        className="p-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white transition-all"
                      >
                        {copiedId === node.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>

                      <ChevronRight
                        className={`w-4 h-4 transition-transform ${
                          isActive ? "text-cyan-400 translate-x-0.5" : "text-slate-600 group-hover:text-slate-400"
                        }`}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ПРАВАЯ КОЛОНКА: Терминал логов реального времени (5 колонок) */}
          <div className="lg:col-span-5 flex flex-col space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Terminal className="w-5 h-5 text-emerald-400" />
                <h3 className="text-base font-bold text-white">
                  Логи демона (vpn_daemon.log)
                </h3>
              </div>

              {/* Фильтр логов */}
              <div className="flex items-center space-x-1.5">
                {["ALL", "INFO", "WARNING"].map((lvl) => (
                  <button
                    key={lvl}
                    onClick={() => setSelectedLogLevel(lvl)}
                    className={`px-2 py-0.5 text-[10px] font-semibold rounded-md transition-all ${
                      selectedLogLevel === lvl
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                        : "text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800"
                    }`}
                  >
                    {lvl}
                  </button>
                ))}
                <button
                  onClick={handleClearLogs}
                  title="Очистить терминал"
                  className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Окно терминала */}
            <div className="flex-1 min-h-[380px] lg:min-h-[440px] flex flex-col rounded-2xl bg-black/80 backdrop-blur-xl border border-slate-800 shadow-2xl overflow-hidden font-mono text-xs">
              {/* Верхняя панель окна в стиле macOS/Unix */}
              <div className="flex items-center justify-between px-3.5 py-2.5 bg-slate-900/90 border-b border-slate-800 select-none">
                <div className="flex items-center space-x-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                  <span className="text-[11px] text-slate-400 ml-2">daemon.stdout</span>
                </div>
                <div className="flex items-center space-x-2 text-[10px] text-slate-400">
                  <label className="flex items-center space-x-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={autoScroll}
                      onChange={(e) => setAutoScroll(e.target.checked)}
                      className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0 w-3 h-3"
                    />
                    <span>Автоскролл</span>
                  </label>
                </div>
              </div>

              {/* Содержимое логов */}
              <div className="flex-1 p-3.5 overflow-y-auto space-y-1.5 leading-relaxed">
                {filteredLogs.length === 0 ? (
                  <div className="text-slate-600 italic text-center py-10">
                    Журнал пуст. Ожидание событий Watchdog...
                  </div>
                ) : (
                  filteredLogs.map((log) => {
                    let levelColor = "text-cyan-400";
                    if (log.level === "WARNING") levelColor = "text-amber-400";
                    if (log.level === "ERROR") levelColor = "text-rose-400";

                    return (
                      <div
                        key={log.id}
                        className="flex items-start space-x-2 text-[11px] hover:bg-slate-900/40 px-1 rounded transition-colors"
                      >
                        <span className="text-slate-500 flex-shrink-0 select-none">
                          {log.timestamp}
                        </span>
                        <span className={`font-bold flex-shrink-0 select-none ${levelColor}`}>
                          [{log.level}]
                        </span>
                        <span className="text-slate-300 break-all">{log.message}</span>
                      </div>
                    );
                  })
                )}
                <div ref={logsEndRef} />
              </div>

              {/* Нижняя строка состояния терминала */}
              <div className="px-3.5 py-1.5 bg-slate-950/90 border-t border-slate-900 text-[10px] text-slate-500 flex items-center justify-between">
                <span>Интервал проверки: 6.0s</span>
                <span className="flex items-center">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block mr-1 animate-pulse" />
                  Поток активен
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
