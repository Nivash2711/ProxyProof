package com.proxyproof.proxyproof_app

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.*
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import androidx.core.app.ActivityCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList

class MainActivity : FlutterActivity() {
    private val channel = "proxyproof/ble"
    private val marker = 0x5050524F // "PPRO"
    private var advertiseCallback: AdvertiseCallback? = null
    private var scanCallback: ScanCallback? = null
    private val handler = Handler(Looper.getMainLooper())
    private val adapter by lazy { (getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter }
    private val serviceUuid = UUID.fromString("9e1c0001-7a31-4d2b-9c0f-50524f585950")

    override fun onCreate(savedInstanceState: android.os.Bundle?) { super.onCreate(savedInstanceState); requestBlePermissions() }
    private fun requestBlePermissions() {
        if (Build.VERSION.SDK_INT >= 31) {
            val required = arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
            val missing = required.filter { ActivityCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
            if (missing.isNotEmpty()) ActivityCompat.requestPermissions(this, missing.toTypedArray(), 818)
        } else if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 818)
        }
    }
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channel).setMethodCallHandler { call, result ->
            when (call.method) {
                "startAdvertising" -> {
                    if (!checkPermission(Manifest.permission.BLUETOOTH_ADVERTISE, 31) || !checkPermission(Manifest.permission.BLUETOOTH_CONNECT, 31)) { result.error("PERMISSION", "Grant Nearby devices permissions and try again.", null); return@setMethodCallHandler }
                    try {
                        if (!adapter.isEnabled) { result.error("BLUETOOTH_OFF", "Enable Bluetooth first.", null); return@setMethodCallHandler }
                        val sid = call.argument<Int>("sessionId") ?: 0
                        val token = call.argument<String>("token") ?: ""
                        if (sid <= 0 || token.length != 16) { result.error("BAD_PAYLOAD", "Invalid session ID/token.", null); return@setMethodCallHandler }
                        stopAdvertise()
                        val bytes = ByteBuffer.allocate(16).putInt(marker).putInt(sid).put(hexToBytes(token)).array()
                        val payloadUuid = uuidFromBytes(bytes)
                        val data = AdvertiseData.Builder().addServiceUuid(ParcelUuid(payloadUuid)).setIncludeDeviceName(false).build()
                        val settings = AdvertiseSettings.Builder().setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY).setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM).setConnectable(false).build()
                        advertiseCallback = object : AdvertiseCallback() {
                            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) { runOnUiThread { result.success(true) } }
                            override fun onStartFailure(errorCode: Int) { runOnUiThread { result.error("ADVERTISE_FAILED", "BLE advertising failed ($errorCode).", null) } }
                        }
                        adapter.bluetoothLeAdvertiser?.startAdvertising(settings, data, advertiseCallback) ?: result.error("NO_ADVERTISER", "BLE advertising is not supported on this phone.", null)
                    } catch (e: Exception) { result.error("BLE_ERROR", e.message, null) }
                }
                "stopAdvertising" -> { stopAdvertise(); result.success(true) }
                "stopScan" -> { stopScan(); result.success(true) }
                "scan" -> {
                    if (!checkPermission(Manifest.permission.BLUETOOTH_SCAN, 31) || !checkPermission(Manifest.permission.BLUETOOTH_CONNECT, 31)) { result.error("PERMISSION", "Grant Nearby devices permissions and try again.", null); return@setMethodCallHandler }
                    try {
                        if (!adapter.isEnabled) { result.error("BLUETOOTH_OFF", "Enable Bluetooth first.", null); return@setMethodCallHandler }
                        val duration = call.argument<Int>("durationMs") ?: 10000
                        val found = CopyOnWriteArrayList<Map<String, Any>>()
                        stopScan()
                        scanCallback = object : ScanCallback() {
                            override fun onScanResult(callbackType: Int, resultScan: ScanResult) {
                                val uuids = resultScan.scanRecord?.serviceUuids ?: return
                                for (parcel in uuids) {
                                    val bytes = bytesFromUuid(parcel.uuid)
                                    if (bytes.size != 16) continue
                                    val buffer = ByteBuffer.wrap(bytes)
                                    if (buffer.int != marker) continue
                                    val sid = buffer.int
                                    val tokenBytes = ByteArray(8); buffer.get(tokenBytes)
                                    val token = tokenBytes.joinToString("") { "%02x".format(it) }
                                    if (found.none { it["session_id"] == sid }) found.add(mapOf("session_id" to sid, "token" to token, "rssi" to resultScan.rssi))
                                }
                            }
                            override fun onScanFailed(errorCode: Int) { runOnUiThread { result.error("SCAN_FAILED", "BLE scan failed ($errorCode).", null) } }
                        }
                        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
                        adapter.bluetoothLeScanner?.startScan(null, settings, scanCallback) ?: run { result.error("NO_SCANNER", "BLE scanning is not supported.", null); return@setMethodCallHandler }
                        handler.postDelayed({ stopScan(); result.success(found.toList()) }, duration.toLong())
                    } catch (e: Exception) { result.error("BLE_ERROR", e.message, null) }
                }
                else -> result.notImplemented()
            }
        }
    }
    private fun checkPermission(permission: String, fromSdk: Int): Boolean = Build.VERSION.SDK_INT < fromSdk || ActivityCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
    private fun stopAdvertise() { try { advertiseCallback?.let { adapter.bluetoothLeAdvertiser?.stopAdvertising(it) } } catch (_: Exception) {}; advertiseCallback = null }
    private fun stopScan() { try { scanCallback?.let { adapter.bluetoothLeScanner?.stopScan(it) } } catch (_: Exception) {}; scanCallback = null }
    private fun hexToBytes(hex: String): ByteArray = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun uuidFromBytes(bytes: ByteArray): UUID { val b=ByteBuffer.wrap(bytes); return UUID(b.long,b.long) }
    private fun bytesFromUuid(uuid: UUID): ByteArray { val b=ByteBuffer.allocate(16); b.putLong(uuid.mostSignificantBits); b.putLong(uuid.leastSignificantBits); return b.array() }
    override fun onDestroy() { stopAdvertise(); stopScan(); super.onDestroy() }
}
