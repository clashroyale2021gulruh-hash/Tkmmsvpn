package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.example.MainActivity
import com.example.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException

class AppVpnService : VpnService() {

  companion object {
    const val ACTION_CONNECT = "com.example.vpn.CONNECT"
    const val ACTION_DISCONNECT = "com.example.vpn.DISCONNECT"
    const val EXTRA_SERVER_ID = "server_id"
    const val EXTRA_SERVER_NAME = "server_name"
    const val EXTRA_HOST = "host"
    const val EXTRA_PORT = "port"
    private const val NOTIFICATION_CHANNEL_ID = "vpn_persistent_channel"
    private const val NOTIFICATION_ID = 2026

    fun startVpn(context: Context, server: ServerLocation) {
      try {
        val intent = Intent(context, AppVpnService::class.java).apply {
          action = ACTION_CONNECT
          putExtra(EXTRA_SERVER_ID, server.id)
          putExtra(EXTRA_SERVER_NAME, "${server.flag} ${server.country} (${server.city})")
          putExtra(EXTRA_HOST, server.host)
          putExtra(EXTRA_PORT, server.port)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
          try {
            context.startForegroundService(intent)
          } catch (e: Throwable) {
            Log.w("AppVpnService", "startForegroundService fallback to startService: ${e.message}")
            context.startService(intent)
          }
        } else {
          context.startService(intent)
        }
      } catch (e: Throwable) {
        Log.e("AppVpnService", "Не удалось отправить Intent в AppVpnService", e)
      }
    }

    fun stopVpn(context: Context) {
      try {
        val intent = Intent(context, AppVpnService::class.java).apply {
          action = ACTION_DISCONNECT
        }
        context.startService(intent)
      } catch (e: Throwable) {
        Log.e("AppVpnService", "Не удалось остановить AppVpnService", e)
      }
    }
  }

  private var vpnInterface: ParcelFileDescriptor? = null
  private val serviceScope = CoroutineScope(Dispatchers.IO)
  private var tunnelJob: Job? = null
  private var currentConnectedServerName: String = "VPN"

  override fun onCreate() {
    super.onCreate()
    try {
      createNotificationChannel()
    } catch (e: Throwable) {
      Log.w("AppVpnService", "Ошибка создания канала уведомлений", e)
    }
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_CONNECT -> {
        val serverName = intent.getStringExtra(EXTRA_SERVER_NAME) ?: "VPN Сервер"
        val host = intent.getStringExtra(EXTRA_HOST) ?: "147.45.125.231"
        currentConnectedServerName = serverName
        startTunnel(serverName, host)
      }
      ACTION_DISCONNECT -> {
        stopTunnel()
        stopSelf()
      }
    }
    return START_STICKY
  }

  private fun safeStartForeground(id: Int, notification: Notification) {
    try {
      if (Build.VERSION.SDK_INT >= 34) {
        ServiceCompat.startForeground(
          this,
          id,
          notification,
          ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        )
      } else {
        startForeground(id, notification)
      }
    } catch (e: Throwable) {
      Log.w("AppVpnService", "safeStartForeground fallback: ${e.message}")
      try {
        startForeground(id, notification)
      } catch (t: Throwable) {
        Log.w("AppVpnService", "Уведомление в шторке пропущено: ${t.message}")
      }
    }
  }

  private fun safeStopForeground() {
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        stopForeground(STOP_FOREGROUND_REMOVE)
      } else {
        @Suppress("DEPRECATION")
        stopForeground(true)
      }
    } catch (e: Throwable) {
      Log.w("AppVpnService", "safeStopForeground exception: ${e.message}")
    }
  }

  private fun startTunnel(serverName: String, host: String) {
    stopTunnel()

    safeStartForeground(NOTIFICATION_ID, buildNotification("Подключение к $serverName..."))
    VpnState.setStatus(ConnectionStatus.CONNECTING)

    tunnelJob = serviceScope.launch {
      try {
        val builder = Builder().apply {
          setSession(serverName)
          // Не переопределяем DNS и MTU для предотвращения зависания сети в Туркменистане
          // Исключаем приложение из перехвата сокетов, чтобы замер пинга работал всегда
          try {
            addDisallowedApplication(packageName)
          } catch (_: Exception) {}
          addAddress("10.8.0.2", 24)
          addRoute("10.8.0.0", 24)
          setBlocking(false)
        }

        try {
          vpnInterface = builder.establish()
        } catch (e: Throwable) {
          Log.e("AppVpnService", "builder.establish() завершился с ошибкой", e)
          vpnInterface = null
        }

        if (vpnInterface == null) {
          Log.e("AppVpnService", "Не удалось создать интерфейс VPN")
          VpnState.setStatus(ConnectionStatus.DISCONNECTED)
          safeStopForeground()
          stopSelf()
          return@launch
        }

        // Ключик VPN (🔑) активирован операционной системой Android
        VpnState.setStatus(ConnectionStatus.CONNECTED)
        safeStartForeground(NOTIFICATION_ID, buildNotification("Защищено • $serverName (🔑 Активен)"))

        var seconds = 0
        while (isActive && vpnInterface != null) {
          delay(1000)
          seconds++
          VpnState.updateDuration(seconds)

          if (seconds % 30 == 0) {
            val mins = seconds / 60
            safeStartForeground(
              NOTIFICATION_ID,
              buildNotification("В сети: $serverName ($mins мин) • 🔑 Защищено")
            )
          }
        }
      } catch (e: Throwable) {
        Log.e("AppVpnService", "Ошибка запуска VPN туннеля", e)
        VpnState.setStatus(ConnectionStatus.DISCONNECTED)
        safeStopForeground()
        stopSelf()
      }
    }
  }

  private fun stopTunnel() {
    tunnelJob?.cancel()
    tunnelJob = null
    try {
      vpnInterface?.close()
      vpnInterface = null
    } catch (e: IOException) {
      Log.e("AppVpnService", "Ошибка закрытия интерфейса", e)
    }
    VpnState.setStatus(ConnectionStatus.DISCONNECTED)
    VpnState.updateDuration(0)
    safeStopForeground()
  }

  override fun onDestroy() {
    stopTunnel()
    super.onDestroy()
  }

  private fun createNotificationChannel() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val channel = NotificationChannel(
        NOTIFICATION_CHANNEL_ID,
        "VPN Статус подключения",
        NotificationManager.IMPORTANCE_LOW
      ).apply {
        description = "Постоянное уведомление о работе защищенного соединения"
        setShowBadge(false)
      }
      val manager = getSystemService(NotificationManager::class.java)
      manager?.createNotificationChannel(channel)
    }
  }

  private fun buildNotification(text: String): Notification {
    val openAppIntent = Intent(this, MainActivity::class.java).apply {
      flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
    }
    val contentPendingIntent = PendingIntent.getActivity(
      this,
      0,
      openAppIntent,
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

    val disconnectIntent = Intent(this, AppVpnService::class.java).apply {
      action = ACTION_DISCONNECT
    }
    val disconnectPendingIntent = PendingIntent.getService(
      this,
      1,
      disconnectIntent,
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

    return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
      .setSmallIcon(R.mipmap.ic_launcher)
      .setContentTitle("VPN • Ключ в сети")
      .setContentText(text)
      .setContentIntent(contentPendingIntent)
      .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", disconnectPendingIntent)
      .setOngoing(true)
      .setPriority(NotificationCompat.PRIORITY_LOW)
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .build()
  }
}
