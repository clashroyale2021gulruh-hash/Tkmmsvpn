package com.example.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ConnectionStatus {
  DISCONNECTED,
  CONNECTING,
  CONNECTED
}

data class ServerLocation(
  val id: String,
  val country: String,
  val city: String,
  val flag: String,
  var pingMs: Int,
  val protocol: String,
  val configUri: String,
  val host: String = "185.158.113.45",
  val port: Int = 443,
  val category: String = "Игровые"
)

data class CountryGroup(
  val id: String,
  val country: String,
  val flag: String,
  val bestPing: Int,
  val servers: List<ServerLocation>
)

object VpnState {
  private val _status = MutableStateFlow(ConnectionStatus.DISCONNECTED)
  val status: StateFlow<ConnectionStatus> = _status.asStateFlow()

  private val _activeServer = MutableStateFlow<ServerLocation?>(null)
  val activeServer: StateFlow<ServerLocation?> = _activeServer.asStateFlow()

  private val _sessionDurationSeconds = MutableStateFlow(0)
  val sessionDurationSeconds: StateFlow<Int> = _sessionDurationSeconds.asStateFlow()

  private val _bytesReceived = MutableStateFlow(0L)
  val bytesReceived: StateFlow<Long> = _bytesReceived.asStateFlow()

  private val _bytesSent = MutableStateFlow(0L)
  val bytesSent: StateFlow<Long> = _bytesSent.asStateFlow()

  private val _downloadSpeedKb = MutableStateFlow(0f)
  val downloadSpeedKb: StateFlow<Float> = _downloadSpeedKb.asStateFlow()

  private val _uploadSpeedKb = MutableStateFlow(0f)
  val uploadSpeedKb: StateFlow<Float> = _uploadSpeedKb.asStateFlow()

  private val _realPingMs = MutableStateFlow(24)
  val realPingMs: StateFlow<Int> = _realPingMs.asStateFlow()

  // 10 полезных функций
  private val _isGamingMode = MutableStateFlow(true)
  val isGamingMode: StateFlow<Boolean> = _isGamingMode.asStateFlow()

  private val _isKillSwitch = MutableStateFlow(true)
  val isKillSwitch: StateFlow<Boolean> = _isKillSwitch.asStateFlow()

  private val _isAutoConnectOnLaunch = MutableStateFlow(false)
  val isAutoConnectOnLaunch: StateFlow<Boolean> = _isAutoConnectOnLaunch.asStateFlow()

  private val _selectedDns = MutableStateFlow("Yandex СНГ (77.88.8.8)")
  val selectedDns: StateFlow<String> = _selectedDns.asStateFlow()

  private val _isSplitTunneling = MutableStateFlow(false)
  val isSplitTunneling: StateFlow<Boolean> = _isSplitTunneling.asStateFlow()

  private val _isBatterySaverExempt = MutableStateFlow(true)
  val isBatterySaverExempt: StateFlow<Boolean> = _isBatterySaverExempt.asStateFlow()

  private val _autoRefreshEvery30Min = MutableStateFlow(true)
  val autoRefreshEvery30Min: StateFlow<Boolean> = _autoRefreshEvery30Min.asStateFlow()

  private val _lastRefreshTime = MutableStateFlow("Только что")
  val lastRefreshTime: StateFlow<String> = _lastRefreshTime.asStateFlow()

  fun setStatus(newStatus: ConnectionStatus) {
    _status.value = newStatus
  }

  fun setActiveServer(server: ServerLocation?) {
    _activeServer.value = server
    server?.let { _realPingMs.value = it.pingMs }
  }

  fun setRealPing(ping: Int) {
    _realPingMs.value = ping
  }

  fun updateTraffic(rx: Long, tx: Long, dlSpeed: Float, ulSpeed: Float) {
    _bytesReceived.value = rx
    _bytesSent.value = tx
    _downloadSpeedKb.value = dlSpeed
    _uploadSpeedKb.value = ulSpeed
  }

  fun updateDuration(duration: Int) {
    _sessionDurationSeconds.value = duration
  }

  fun setGamingMode(enabled: Boolean) { _isGamingMode.value = enabled }
  fun setKillSwitch(enabled: Boolean) { _isKillSwitch.value = enabled }
  fun setAutoConnectOnLaunch(enabled: Boolean) { _isAutoConnectOnLaunch.value = enabled }
  fun setSelectedDns(dns: String) { _selectedDns.value = dns }
  fun setSplitTunneling(enabled: Boolean) { _isSplitTunneling.value = enabled }
  fun setBatterySaverExempt(exempt: Boolean) { _isBatterySaverExempt.value = exempt }
  fun setAutoRefreshEvery30Min(enabled: Boolean) { _autoRefreshEvery30Min.value = enabled }
  fun setLastRefreshTime(time: String) { _lastRefreshTime.value = time }
}
