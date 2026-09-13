package com.example

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.*
import com.example.vpn.*
import kotlinx.coroutines.*
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    setContent {
      MyApplicationTheme {
        Scaffold(
          modifier = Modifier
            .fillMaxSize()
            .background(DarkBg),
          contentWindowInsets = WindowInsets.systemBars
        ) { paddingValues ->
          VpnAppScreen(modifier = Modifier.padding(paddingValues))
        }
      }
    }
  }
}

@Composable
fun VpnAppScreen(modifier: Modifier = Modifier) {
  val context = LocalContext.current
  val coroutineScope = rememberCoroutineScope()

  // Состояния туннеля и серверов
  val connectionStatus by VpnState.status.collectAsState()
  val activeServer by VpnState.activeServer.collectAsState()
  val sessionDuration by VpnState.sessionDurationSeconds.collectAsState()
  val lastRefreshTime by VpnState.lastRefreshTime.collectAsState()

  // Список РЕАЛЬНЫХ проверенных серверов
  var servers by remember { mutableStateOf(ServerRepository.getInitialServers()) }
  val currentServer = activeServer ?: servers.first()

  // Статус обновления пинга
  var isUpdatingPings by remember { mutableStateOf(false) }

  // Раскрытые регионы в списке (по умолчанию открыты Россия Игры и Германия)
  var expandedRegions by remember {
    mutableStateOf(
      setOf(
        "🇷🇺 Россия (Игры • Gaming)",
        "⚡ Авто-выбор (Самый быстрый)",
        "🇩🇪 Германия (Франкфурт)"
      )
    )
  }

  // Лаунчер системного запроса Android VpnService.prepare()
  var pendingServerToConnect by remember { mutableStateOf<ServerLocation?>(null) }
  val vpnPrepareLauncher = rememberLauncherForActivityResult(
    contract = ActivityResultContracts.StartActivityForResult()
  ) { result ->
    if (result.resultCode == Activity.RESULT_OK) {
      pendingServerToConnect?.let { srv ->
        try {
          AppVpnService.startVpn(context, srv)
          Toast.makeText(context, "VPN активен • 🔑 Ключ в панели уведомлений", Toast.LENGTH_SHORT).show()
        } catch (e: Throwable) {
          Log.e("MainActivity", "Ошибка запуска VPN", e)
          Toast.makeText(context, "Не удалось запустить VPN: ${e.message}", Toast.LENGTH_SHORT).show()
          VpnState.setStatus(ConnectionStatus.DISCONNECTED)
        }
      }
    } else {
      Toast.makeText(context, "Для работы VPN подтвердите системный запрос", Toast.LENGTH_LONG).show()
      VpnState.setStatus(ConnectionStatus.DISCONNECTED)
    }
  }

  // Честное измерение пинга до всех серверов
  fun runPingMeasurement(silent: Boolean = false) {
    if (isUpdatingPings) return
    isUpdatingPings = true
    coroutineScope.launch {
      val updated = servers.map { srv ->
        async {
          if (srv.id == "auto") srv
          else {
            val realPing = PingManager.measureRealPing(srv.host, srv.port, 1800)
            srv.copy(pingMs = realPing)
          }
        }
      }.awaitAll()

      val activeNodes = updated.filter { it.id != "auto" && it.pingMs > 0 }
      val minPing = if (activeNodes.isNotEmpty()) activeNodes.minOf { it.pingMs } else -1

      val finalized = updated.map {
        if (it.id == "auto") it.copy(pingMs = minPing) else it
      }

      servers = finalized
      isUpdatingPings = false

      val timeStr = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date())
      VpnState.setLastRefreshTime(timeStr)

      if (!silent) {
        val aliveCount = activeNodes.size
        Toast.makeText(
          context,
          "Проверено: $aliveCount серверов доступно • Лучший: ${minPing}ms",
          Toast.LENGTH_SHORT
        ).show()
      }
    }
  }

  // Подключение к серверу с РЕАЛЬНОЙ проверкой доступности
  fun connectToServer(server: ServerLocation) {
    coroutineScope.launch {
      val targetServer = if (server.id == "auto") {
        servers.filter { it.id != "auto" && it.pingMs > 0 }.minByOrNull { it.pingMs }
          ?: servers.firstOrNull { it.id != "auto" }
          ?: server
      } else {
        server
      }

      VpnState.setActiveServer(targetServer)
      pendingServerToConnect = targetServer

      // Проверяем реальную доступность сокета перед запуском
      if (targetServer.id != "auto") {
        VpnState.setStatus(ConnectionStatus.CONNECTING)
        val check = PingManager.measureRealPing(targetServer.host, targetServer.port, 1500)
        if (check <= 0) {
          VpnState.setStatus(ConnectionStatus.DISCONNECTED)
          Toast.makeText(
            context,
            "Сервер ${targetServer.country} недоступен! Выберите другой узел.",
            Toast.LENGTH_LONG
          ).show()
          return@launch
        }
      }

      val prepareIntent = try {
        VpnService.prepare(context)
      } catch (e: Throwable) {
        Log.w("MainActivity", "VpnService.prepare error: ${e.message}")
        null
      }

      if (prepareIntent != null) {
        try {
          vpnPrepareLauncher.launch(prepareIntent)
        } catch (e: Throwable) {
          Log.w("MainActivity", "vpnPrepareLauncher failed, direct fallback: ${e.message}")
          AppVpnService.startVpn(context, targetServer)
        }
      } else {
        AppVpnService.startVpn(context, targetServer)
        Toast.makeText(
          context,
          "Подключено: ${targetServer.flag} ${targetServer.country} (${targetServer.pingMs} ms)",
          Toast.LENGTH_SHORT
        ).show()
      }
    }
  }

  // Переключение СТАРТ / СТОП
  fun toggleConnection() {
    when (connectionStatus) {
      ConnectionStatus.DISCONNECTED -> connectToServer(currentServer)
      ConnectionStatus.CONNECTING -> AppVpnService.stopVpn(context)
      ConnectionStatus.CONNECTED -> {
        AppVpnService.stopVpn(context)
        Toast.makeText(context, "VPN отключен", Toast.LENGTH_SHORT).show()
      }
    }
  }

  // Автообновление каждые 30 минут (как просил пользователь)
  LaunchedEffect(Unit) {
    runPingMeasurement(silent = true)
    while (true) {
      delay(30 * 60 * 1000L)
      runPingMeasurement(silent = true)
    }
  }

  // Анимация пульсации кнопки
  val infiniteTransition = rememberInfiniteTransition(label = "jumpTransition")
  val pulseScale by infiniteTransition.animateFloat(
    initialValue = 1f,
    targetValue = if (connectionStatus == ConnectionStatus.CONNECTED) 1.15f else 1.03f,
    animationSpec = infiniteRepeatable(
      animation = tween(1400, easing = FastOutSlowInEasing),
      repeatMode = RepeatMode.Reverse
    ),
    label = "pulseScale"
  )
  val pulseAlpha by infiniteTransition.animateFloat(
    initialValue = 0.4f,
    targetValue = 0.05f,
    animationSpec = infiniteRepeatable(
      animation = tween(1400, easing = FastOutSlowInEasing),
      repeatMode = RepeatMode.Reverse
    ),
    label = "pulseAlpha"
  )
  val rotateAngle by infiniteTransition.animateFloat(
    initialValue = 0f,
    targetValue = 360f,
    animationSpec = infiniteRepeatable(
      animation = tween(900, easing = LinearEasing),
      repeatMode = RepeatMode.Restart
    ),
    label = "rotateAngle"
  )

  fun formatTime(sec: Int): String {
    val h = sec / 3600
    val m = (sec % 3600) / 60
    val s = sec % 60
    return if (h > 0) String.format("%02d:%02d:%02d", h, m, s) else String.format("%02d:%02d", m, s)
  }

  // Группировка серверов по регионам/странам (Аккордеон, как просил пользователь)
  val groupedServers = remember(servers) {
    val map = linkedMapOf<String, MutableList<ServerLocation>>()
    // Авто сервер отдельно
    val auto = servers.find { it.id == "auto" }
    if (auto != null) {
      map["⚡ Авто-выбор"] = mutableListOf(auto)
    }
    servers.filter { it.id != "auto" }.forEach { srv ->
      val key = "${srv.flag} ${srv.country}"
      map.getOrPut(key) { mutableListOf() }.add(srv)
    }
    map
  }

  Column(
    modifier = modifier
      .fillMaxSize()
      .background(DarkBg)
      .padding(horizontal = 16.dp, vertical = 8.dp),
    horizontalAlignment = Alignment.CenterHorizontally
  ) {
    // -------------------------------------------------------------------------
    // 1. ВЕРХНЯЯ ПАНЕЛЬ JUMP JUMP VPN (ЧИСТАЯ, ЛЕГКАЯ)
    // -------------------------------------------------------------------------
    Row(
      modifier = Modifier
        .fillMaxWidth()
        .padding(vertical = 8.dp),
      horizontalArrangement = Arrangement.SpaceBetween,
      verticalAlignment = Alignment.CenterVertically
    ) {
      Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Box(
          modifier = Modifier
            .size(42.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(
              Brush.linearGradient(
                if (connectionStatus == ConnectionStatus.CONNECTED) listOf(NeonEmerald, NeonCyan)
                else listOf(DarkSurfaceVariant, DarkBorder)
              )
            ),
          contentAlignment = Alignment.Center
        ) {
          Icon(
            imageVector = Icons.Default.VpnKey,
            contentDescription = "VPN Key",
            tint = Color.White,
            modifier = Modifier.size(24.dp)
          )
        }

        Column {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(text = "JUMP VPN", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            Box(
              modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .background(
                  if (connectionStatus == ConnectionStatus.CONNECTED) NeonEmerald.copy(alpha = 0.15f)
                  else DarkSurfaceVariant
                )
                .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
              Text(
                text = when (connectionStatus) {
                  ConnectionStatus.CONNECTED -> "🔑 ПОДКЛЮЧЕНО"
                  ConnectionStatus.CONNECTING -> "СОЕДИНЕНИЕ..."
                  ConnectionStatus.DISCONNECTED -> "ОТКЛЮЧЕНО"
                },
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = when (connectionStatus) {
                  ConnectionStatus.CONNECTED -> NeonEmerald
                  ConnectionStatus.CONNECTING -> NeonAmber
                  ConnectionStatus.DISCONNECTED -> TextMuted
                }
              )
            }
          }
          Text(
            text = "Обновлено: $lastRefreshTime (каждые 30 мин)",
            fontSize = 11.sp,
            color = TextMuted
          )
        }
      }

      // Кнопка принудительного обновления пинга
      IconButton(
        onClick = { runPingMeasurement(silent = false) },
        modifier = Modifier
          .size(40.dp)
          .clip(RoundedCornerShape(10.dp))
          .background(DarkSurfaceVariant)
      ) {
        Icon(
          imageVector = Icons.Default.Refresh,
          contentDescription = "Обновить серверы",
          tint = NeonCyan,
          modifier = Modifier
            .size(20.dp)
            .rotate(if (isUpdatingPings) rotateAngle else 0f)
        )
      }
    }

    // -------------------------------------------------------------------------
    // 2. ЦЕНТРАЛЬНАЯ КНОПКА ПОДКЛЮЧЕНИЯ (JUMP JUMP СТИЛЬ)
    // -------------------------------------------------------------------------
    Spacer(modifier = Modifier.height(10.dp))

    Box(
      contentAlignment = Alignment.Center,
      modifier = Modifier
        .size(190.dp)
        .clickable(
          interactionSource = remember { MutableInteractionSource() },
          indication = null
        ) { toggleConnection() }
        .testTag("vpn_connect_button")
    ) {
      // Пульсирующий внешний ореол
      Box(
        modifier = Modifier
          .size(190.dp)
          .scale(pulseScale)
          .clip(CircleShape)
          .background(
            (if (connectionStatus == ConnectionStatus.CONNECTED) NeonEmerald else NeonCyan)
              .copy(alpha = pulseAlpha)
          )
      )

      // Внутренний круг кнопки
      Surface(
        modifier = Modifier.size(140.dp),
        shape = CircleShape,
        color = DarkSurface,
        border = androidx.compose.foundation.BorderStroke(
          3.dp,
          Brush.linearGradient(
            when (connectionStatus) {
              ConnectionStatus.CONNECTED -> listOf(NeonEmerald, NeonCyan)
              ConnectionStatus.CONNECTING -> listOf(NeonAmber, NeonCyan)
              ConnectionStatus.DISCONNECTED -> listOf(DarkBorder, DarkSurfaceVariant)
            }
          )
        ),
        shadowElevation = 12.dp
      ) {
        Column(
          modifier = Modifier.fillMaxSize(),
          horizontalAlignment = Alignment.CenterHorizontally,
          verticalArrangement = Arrangement.Center
        ) {
          Icon(
            imageVector = when (connectionStatus) {
              ConnectionStatus.CONNECTED -> Icons.Default.VpnKey
              ConnectionStatus.CONNECTING -> Icons.Default.Sync
              ConnectionStatus.DISCONNECTED -> Icons.Default.PowerSettingsNew
            },
            contentDescription = "Кнопка VPN",
            tint = when (connectionStatus) {
              ConnectionStatus.CONNECTED -> NeonEmerald
              ConnectionStatus.CONNECTING -> NeonAmber
              ConnectionStatus.DISCONNECTED -> Color.White
            },
            modifier = Modifier
              .size(46.dp)
              .rotate(if (connectionStatus == ConnectionStatus.CONNECTING) rotateAngle else 0f)
          )

          Spacer(modifier = Modifier.height(6.dp))

          Text(
            text = when (connectionStatus) {
              ConnectionStatus.CONNECTED -> formatTime(sessionDuration)
              ConnectionStatus.CONNECTING -> "ПОДКЛЮЧЕНИЕ"
              ConnectionStatus.DISCONNECTED -> "СТАРТ"
            },
            fontSize = 13.sp,
            fontWeight = FontWeight.ExtraBold,
            color = when (connectionStatus) {
              ConnectionStatus.CONNECTED -> NeonEmerald
              ConnectionStatus.CONNECTING -> NeonAmber
              ConnectionStatus.DISCONNECTED -> TextPrimary
            },
            fontFamily = FontFamily.Monospace
          )
        }
      }
    }

    Spacer(modifier = Modifier.height(10.dp))

    // -------------------------------------------------------------------------
    // 3. КАРТОЧКА ВЫБРАННОГО СЕРВЕРА С ПРЯМЫМ КОПИРОВАНИЕМ КЛЮЧА
    // -------------------------------------------------------------------------
    Surface(
      modifier = Modifier
        .fillMaxWidth()
        .clip(RoundedCornerShape(16.dp)),
      color = DarkSurface,
      border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
    ) {
      Column(modifier = Modifier.padding(14.dp)) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(text = currentServer.flag, fontSize = 28.sp)
            Column {
              Text(
                text = "${currentServer.country} • ${currentServer.city}",
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary
              )
              Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(text = currentServer.protocol, fontSize = 11.sp, color = NeonCyan)
                Text(text = "•", fontSize = 11.sp, color = TextMuted)
                Text(
                  text = if (currentServer.pingMs > 0) "${currentServer.pingMs} ms" else "Недоступен",
                  fontSize = 11.sp,
                  fontWeight = FontWeight.Bold,
                  color = when {
                    currentServer.pingMs in 1..200 -> NeonEmerald
                    currentServer.pingMs > 200 -> NeonAmber
                    else -> NeonRose
                  }
                )
              }
            }
          }

          // Кнопка быстрого копирования рабочего конфига в буфер
          Button(
            onClick = {
              val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
              val clip = ClipData.newPlainText("VPN Config", currentServer.configUri)
              clipboard.setPrimaryClip(clip)
              Toast.makeText(context, "Ключ скопирован в буфер! Вставьте в V2RayNG/Sing-box", Toast.LENGTH_SHORT).show()
            },
            colors = ButtonDefaults.buttonColors(containerColor = DarkSurfaceVariant),
            shape = RoundedCornerShape(10.dp),
            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
          ) {
            Icon(Icons.Default.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(15.dp), tint = NeonCyan)
            Spacer(modifier = Modifier.width(4.dp))
            Text(text = "Ключ", fontSize = 11.sp, color = NeonCyan, fontWeight = FontWeight.Bold)
          }
        }
      }
    }

    Spacer(modifier = Modifier.height(14.dp))

    // -------------------------------------------------------------------------
    // 4. СПИСОК СЕРВЕРОВ: АККОРДЕОН ПО РЕГИОНАМ (КАК В JUMP JUMP VPN)
    // -------------------------------------------------------------------------
    Row(
      modifier = Modifier
        .fillMaxWidth()
        .padding(horizontal = 4.dp, vertical = 2.dp),
      horizontalArrangement = Arrangement.SpaceBetween,
      verticalAlignment = Alignment.CenterVertically
    ) {
      Text(
        text = "СПИСОК СЕРВЕРОВ ПО СТРАНАМ",
        fontSize = 11.sp,
        fontWeight = FontWeight.ExtraBold,
        color = TextSecondary,
        letterSpacing = 1.sp
      )
      Text(
        text = "${servers.size} серверов",
        fontSize = 11.sp,
        color = TextMuted
      )
    }

    Spacer(modifier = Modifier.height(6.dp))

    LazyColumn(
      modifier = Modifier
        .fillMaxWidth()
        .weight(1f),
      verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
      groupedServers.forEach { (regionName, regionServers) ->
        val isExpanded = expandedRegions.contains(regionName)
        val bestRegionPing = regionServers.filter { it.pingMs > 0 }.minOfOrNull { it.pingMs } ?: -1

        item(key = "group_$regionName") {
          Surface(
            modifier = Modifier
              .fillMaxWidth()
              .clip(RoundedCornerShape(12.dp))
              .clickable {
                expandedRegions = if (isExpanded) expandedRegions - regionName else expandedRegions + regionName
              },
            color = DarkSurface,
            border = androidx.compose.foundation.BorderStroke(1.dp, DarkBorder)
          ) {
            Column {
              // Заголовок региона (кликабельный)
              Row(
                modifier = Modifier
                  .fillMaxWidth()
                  .padding(horizontal = 14.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
              ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                  Text(text = regionName, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                  Box(
                    modifier = Modifier
                      .clip(RoundedCornerShape(6.dp))
                      .background(DarkSurfaceVariant)
                      .padding(horizontal = 6.dp, vertical = 2.dp)
                  ) {
                    Text(text = "${regionServers.size}", fontSize = 10.sp, color = TextSecondary)
                  }
                }

                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                  if (bestRegionPing > 0) {
                    Text(
                      text = "${bestRegionPing} ms",
                      fontSize = 11.sp,
                      fontWeight = FontWeight.Bold,
                      color = if (bestRegionPing < 200) NeonEmerald else NeonAmber
                    )
                  } else {
                    Text(text = "Оффлайн", fontSize = 11.sp, color = NeonRose)
                  }

                  Icon(
                    imageVector = if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = "Expand",
                    tint = TextSecondary,
                    modifier = Modifier.size(18.dp)
                  )
                }
              }

              // Выпадающий список серверов данного региона
              AnimatedVisibility(visible = isExpanded) {
                Column(
                  modifier = Modifier
                    .fillMaxWidth()
                    .background(DarkSurfaceVariant.copy(alpha = 0.3f))
                    .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                  regionServers.forEach { server ->
                    val isSelected = currentServer.id == server.id

                    Surface(
                      modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .clickable {
                          VpnState.setActiveServer(server)
                          if (connectionStatus == ConnectionStatus.CONNECTED) {
                            connectToServer(server)
                          }
                        },
                      color = if (isSelected) NeonEmerald.copy(alpha = 0.12f) else Color.Transparent,
                      border = if (isSelected) androidx.compose.foundation.BorderStroke(1.dp, NeonEmerald.copy(alpha = 0.5f)) else null
                    ) {
                      Row(
                        modifier = Modifier
                          .fillMaxWidth()
                          .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                      ) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                          Icon(
                            imageVector = if (isSelected) Icons.Default.CheckCircle else Icons.Default.RadioButtonUnchecked,
                            contentDescription = "Selected",
                            tint = if (isSelected) NeonEmerald else TextMuted,
                            modifier = Modifier.size(16.dp)
                          )
                          Column {
                            Text(
                              text = server.city,
                              fontSize = 12.sp,
                              fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                              color = if (isSelected) NeonEmerald else TextPrimary
                            )
                            Text(text = server.protocol, fontSize = 10.sp, color = TextMuted)
                          }
                        }

                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                          Text(
                            text = if (server.pingMs > 0) "${server.pingMs} ms" else "🔴",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = when {
                              server.pingMs in 1..200 -> NeonEmerald
                              server.pingMs > 200 -> NeonAmber
                              else -> NeonRose
                            }
                          )

                          // Кнопка копирования
                          IconButton(
                            onClick = {
                              val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                              val clip = ClipData.newPlainText("VPN Config", server.configUri)
                              clipboard.setPrimaryClip(clip)
                              Toast.makeText(context, "Ключ скопирован в буфер!", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.size(28.dp)
                          ) {
                            Icon(
                              imageVector = Icons.Default.ContentCopy,
                              contentDescription = "Copy",
                              tint = NeonCyan,
                              modifier = Modifier.size(14.dp)
                            )
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
