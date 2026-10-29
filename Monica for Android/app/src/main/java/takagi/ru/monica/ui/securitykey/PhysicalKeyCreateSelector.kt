package takagi.ru.monica.ui.securitykey

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.os.Build
import android.provider.Settings as AndroidSettings
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import takagi.ru.monica.R
import takagi.ru.monica.securitykey.PhysicalKeyViewModel
import takagi.ru.monica.securitykey.UsbTransport

private const val ACTION_USB_PERMISSION = "takagi.ru.monica.physical_key.CREATE_USB_PERMISSION"

data class PhysicalKeyConnectionUi(
    val nfcSupported: Boolean,
    val nfcEnabled: Boolean,
    val usbDevices: List<UsbDevice>,
    val onOpenNfcSettings: () -> Unit,
    val onConnectUsb: (UsbDevice) -> Unit,
)

/**
 * Keeps NFC reader mode and USB attach detection alive while the credential
 * creation screen is visible, so the physical-key option can enable itself as
 * soon as a key is connected.
 */
@Composable
fun rememberPhysicalKeyConnection(
    viewModel: PhysicalKeyViewModel,
): PhysicalKeyConnectionUi {
    val context = LocalContext.current
    val state by viewModel.state.collectAsStateWithLifecycle()
    val nfcAdapter = remember(context) { NfcAdapter.getDefaultAdapter(context) }
    var nfcEnabled by remember {
        mutableStateOf(runCatching { nfcAdapter?.isEnabled == true }.getOrDefault(false))
    }
    val usbManager = remember(context) {
        context.getSystemService(Context.USB_SERVICE) as? UsbManager
    }
    var usbDevices by remember { mutableStateOf(emptyList<UsbDevice>()) }

    DisposableEffect(context, nfcAdapter) {
        if (nfcAdapter == null) return@DisposableEffect onDispose {}
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(receiverContext: Context, intent: Intent) {
                nfcEnabled = runCatching { nfcAdapter.isEnabled }.getOrDefault(false)
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        nfcEnabled = runCatching { nfcAdapter.isEnabled }.getOrDefault(false)
        onDispose { context.unregisterReceiver(receiver) }
    }

    DisposableEffect(nfcAdapter, state.connected, nfcEnabled) {
        val activity = context.findActivity()
        if (nfcAdapter == null || activity == null || state.connected) {
            return@DisposableEffect onDispose {}
        }
        val flags = NfcAdapter.FLAG_READER_NFC_A or
            NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        runCatching {
            nfcAdapter.enableReaderMode(activity, { tag ->
                viewModel.onTagDiscovered(tag)
            }, flags, null)
        }
        onDispose { runCatching { nfcAdapter.disableReaderMode(activity) } }
    }

    DisposableEffect(context, usbManager) {
        if (usbManager == null) return@DisposableEffect onDispose {}

        fun refreshDevices() {
            usbDevices = usbManager.deviceList.values.filter { UsbTransport.isFidoDevice(it) }
        }

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(receiverContext: Context, intent: Intent) {
                when (intent.action) {
                    ACTION_USB_PERMISSION -> {
                        val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                        } else {
                            @Suppress("DEPRECATION")
                            intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                        }
                        val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                        if (granted && device != null) {
                            viewModel.connectUsb(usbManager, device)
                        }
                        refreshDevices()
                    }
                    else -> refreshDevices()
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(ACTION_USB_PERMISSION)
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        refreshDevices()
        onDispose { context.unregisterReceiver(receiver) }
    }

    return remember(context, usbManager, nfcAdapter, nfcEnabled, usbDevices) {
        PhysicalKeyConnectionUi(
            nfcSupported = nfcAdapter != null,
            nfcEnabled = nfcEnabled,
            usbDevices = usbDevices,
            onOpenNfcSettings = {
                runCatching { context.startActivity(Intent(AndroidSettings.ACTION_NFC_SETTINGS)) }
            },
            onConnectUsb = { device ->
                usbManager?.let { manager ->
                    if (manager.hasPermission(device)) {
                        viewModel.connectUsb(manager, device)
                    } else {
                        requestUsbPermission(context, manager, device)
                    }
                }
            },
        )
    }
}

@Composable
fun PhysicalKeyCreateCard(
    state: PhysicalKeyViewModel.UiState,
    selected: Boolean,
    onSelectedChange: (Boolean) -> Unit,
    connection: PhysicalKeyConnectionUi,
    modifier: Modifier = Modifier,
) {
    LaunchedEffect(state.connected) {
        if (!state.connected && selected) onSelectedChange(false)
    }

    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .alpha(if (state.connected) 1f else 0.6f)
                    .clickable(enabled = state.connected) {
                        onSelectedChange(!selected)
                    },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Default.Usb,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.width(14.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.physical_key_title),
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        text = when {
                            state.connecting -> stringResource(R.string.physical_key_connecting)
                            state.connected -> stringResource(
                                R.string.physical_key_connected_via,
                                state.transport?.value?.uppercase()
                                    ?: stringResource(R.string.physical_key_transport_unknown),
                            )
                            else -> stringResource(R.string.physical_key_selector_disconnected)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                RadioButton(
                    selected = selected,
                    onClick = if (state.connected) {
                        { onSelectedChange(!selected) }
                    } else {
                        null
                    },
                    enabled = state.connected,
                )
            }

            if (!state.connected) {
                Text(
                    text = stringResource(R.string.physical_key_selector_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (connection.nfcSupported && !connection.nfcEnabled) {
                    OutlinedButton(onClick = connection.onOpenNfcSettings) {
                        Text(stringResource(R.string.physical_key_open_nfc_settings))
                    }
                }
                if (state.connecting) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(10.dp))
                        Text(
                            text = stringResource(R.string.physical_key_connecting),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                connection.usbDevices.forEach { device ->
                    OutlinedButton(
                        onClick = { connection.onConnectUsb(device) },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Default.Usb, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = device.productName
                                ?: stringResource(R.string.physical_key_usb_device_fallback),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            } else if (selected) {
                Text(
                    text = stringResource(R.string.physical_key_selector_selected_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                if (state.pinSet == false) {
                    Text(
                        text = stringResource(R.string.physical_key_selector_no_pin),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

@Composable
fun PhysicalKeyPinDialog(
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var pin by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.physical_key_enter_pin)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.physical_key_enter_pin_body))
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it },
                    label = { Text(stringResource(R.string.physical_key_pin)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(pin) }, enabled = pin.isNotEmpty()) {
                Text(stringResource(R.string.ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        },
    )
}

private fun requestUsbPermission(
    context: Context,
    manager: UsbManager,
    device: UsbDevice,
) {
    val intent = Intent(ACTION_USB_PERMISSION).setPackage(context.packageName)
    val mutable = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        PendingIntent.FLAG_MUTABLE
    } else {
        0
    }
    val pendingIntent = PendingIntent.getBroadcast(
        context,
        device.deviceId,
        intent,
        mutable or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    runCatching { manager.requestPermission(device, pendingIntent) }
}

private fun Context.findActivity(): Activity? {
    var current: Context? = this
    while (current is ContextWrapper) {
        if (current is Activity) return current
        current = current.baseContext
    }
    return current as? Activity
}
