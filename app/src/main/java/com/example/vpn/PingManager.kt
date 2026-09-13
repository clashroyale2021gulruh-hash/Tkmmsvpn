package com.example.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

object PingManager {

  /**
   * Честное измерение реального TCP-пинга до сервера.
   * Прямое подключение к сокету (host:port).
   * Если сервер не отвечает или порт закрыт — возвращает -1 (ОФФЛАЙН / Недоступен).
   * Никаких фейковых данных или случайных чисел!
   */
  suspend fun measureRealPing(host: String, port: Int = 443, timeoutMs: Int = 1800): Int =
    withContext(Dispatchers.IO) {
      var socket: Socket? = null
      try {
        val start = System.currentTimeMillis()
        socket = Socket()
        socket.connect(InetSocketAddress(host, port), timeoutMs)
        val elapsed = (System.currentTimeMillis() - start).toInt()
        elapsed.coerceAtLeast(10)
      } catch (_: Exception) {
        -1 // Сервер реально не отвечает
      } finally {
        try {
          socket?.close()
        } catch (_: Exception) {}
      }
    }
}
