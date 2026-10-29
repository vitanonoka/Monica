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
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Nfc
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import takagi.ru.monica.R
import takagi.ru.monica.data.PasskeyEntry
import takagi.ru.monica.securitykey.DeviceInfo
import takagi.ru.monica.securitykey.KeyFailure
import takagi.ru.monica.securitykey.KeyNotice
import takagi.ru.monica.securitykey.PhysicalKeyViewModel
import takagi.ru.monica.securitykey.StoredCredential
import takagi.ru.monica.securitykey.UsbTransport
import takagi.ru.monica.securitykey.WritePasskeyRequest

private const val ACTION_USB_PERMISSION = "takagi.ru.monica.physical_key.USB_PERMISSION"

/**
 * Optional Dock page for programming and managing FIDO2 hardware security keys.
 * The private key material is generated inside the key; only credential metadata
 * is ever read back into Monica.
 */
@Composable
fun PhysicalKeyPane(
    passkeys: List<PasskeyEntry>,
    modifier: Modifier = Modifier,
    showStandaloneSettingsEntry: Boolean = false,
    onOpenStandaloneSettings: () -> Unit = {},
) {
    val context = LocalContext.current
    val viewModel: PhysicalKeyViewModel = viewModel()
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    val nfcAdapter = remember(context) { NfcAdapter.getDefaultAdapter(context) }
    var nfcEnabled by remember {
        mutableStateOf(runCatching { nfcAdapter?.isEnabled == true }.getOrDefault(false))
    }
    val usbManager = remember(context) {
        context.getSystemService(Context.USB_SERVICE) as? UsbManager
    }
    var usbDevices by remember { mutableStateOf(emptyList<UsbDevice>()) }

    var pinPrompt by remember { mutableStateOf<PinPrompt?>(null) }
    var showSetPin by remember { mutableStateOf(false) }
    var showChangePin by remember { mutableStateOf(false) }
    var showWrite by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf<StoredCredential?>(null) }

    // Reader mode is only active while this page is visible and no key is attached.
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
            nfcEnabled = nfcAdapter.isEnabled
        }
        onDispose {
            runCatching { nfcAdapter.disableReaderMode(activity) }
        }
    }

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

    val noticeText = state.notice?.localized(context)
    LaunchedEffect(noticeText) {
        if (noticeText != null) {
            snackbarHostState.showSnackbar(noticeText)
            viewModel.consumeNotice()
        }
    }

    Box(modifier = modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .widthIn(max = 820.dp)
                .align(Alignment.TopCenter),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "header") {
                PhysicalKeyHeader(
                    connected = state.connected,
                    connecting = state.connecting,
                    transportLabel = state.transport?.value?.uppercase(),
                    onDisconnect = viewModel::disconnect,
                    showSettingsEntry = showStandaloneSettingsEntry,
                    onOpenSettings = onOpenStandaloneSettings,
                )
            }

            if (!state.connected) {
                item(key = "connect") {
                    ConnectCard(
                        connecting = state.connecting,
                        nfcSupported = nfcAdapter != null,
                        nfcEnabled = nfcEnabled,
                        onOpenNfcSettings = {
                            runCatching {
                                context.startActivity(Intent(AndroidSettings.ACTION_NFC_SETTINGS))
                            }
                        },
                        usbDevices = usbDevices,
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
                item(key = "hint") {
                    InfoCard(
                        icon = Icons.Default.Info,
                        title = context.getString(R.string.physical_key_connect_help_title),
                        body = context.getString(R.string.physical_key_connect_help_body),
                    )
                }
            } else {
                item(key = "device") {
                    DeviceCard(
                        info = state.deviceInfo,
                        pinSet = state.pinSet,
                        pinRetries = state.pinRetries,
                    )
                }

                item(key = "pin") {
                    PinActionsCard(
                        pinSet = state.pinSet,
                        busy = state.busy,
                        onSetPin = { showSetPin = true },
                        onChangePin = { showChangePin = true },
                    )
                }

                item(key = "write") {
                    ActionCard(
                        icon = Icons.Default.Add,
                        title = context.getString(R.string.physical_key_write_title),
                        body = context.getString(R.string.physical_key_write_body),
                        buttonLabel = context.getString(R.string.physical_key_write_action),
                        enabled = !state.busy,
                        onClick = { showWrite = true },
                    )
                }

                state.lastWritten?.let { written ->
                    item(key = "written") {
                        InfoCard(
                            icon = Icons.Default.Key,
                            title = context.getString(R.string.physical_key_write_success),
                            body = context.getString(
                                R.string.physical_key_written_detail,
                                written.rpId,
                                written.shortId,
                            ),
                        )
                    }
                }

                item(key = "credentials_header") {
                    CredentialsHeader(
                        busy = state.busy,
                        loaded = state.credentialsLoaded,
                        count = state.credentials.size,
                        onLoad = {
                            requestPin(viewModel, state.pinSet, pinPrompt = { pinPrompt = it }) { pin ->
                                viewModel.loadCredentials(pin)
                            }
                        },
                    )
                }

                if (state.credentials.isEmpty()) {
                    item(key = "credentials_empty") {
                        Text(
                            text = if (state.credentialsLoaded) {
                                context.getString(R.string.physical_key_no_credentials)
                            } else {
                                context.getString(R.string.physical_key_credentials_locked)
                            },
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 8.dp),
                        )
                    }
                } else {
                    items(state.credentials, key = { it.shortId + it.rpId }) { credential ->
                        CredentialRow(
                            credential = credential,
                            busy = state.busy,
                            onDelete = { deleting = credential },
                        )
                    }
                }
            }
        }

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(16.dp),
        )
    }

    pinPrompt?.let { prompt ->
        PinPromptDialog(
            title = context.getString(prompt.titleRes),
            message = context.getString(prompt.messageRes),
            confirmLabel = context.getString(prompt.confirmRes),
            onDismiss = { pinPrompt = null },
            onConfirm = { pin ->
                pinPrompt = null
                prompt.onConfirm(pin)
            },
        )
    }

    if (showSetPin) {
        SetPinDialog(
            onDismiss = { showSetPin = false },
            onConfirm = { pin ->
                showSetPin = false
                viewModel.setPin(pin)
            },
        )
    }

    if (showChangePin) {
        ChangePinDialog(
            onDismiss = { showChangePin = false },
            onConfirm = { current, new ->
                showChangePin = false
                viewModel.changePin(current, new)
            },
        )
    }

    if (showWrite) {
        WritePasskeyDialog(
            passkeys = passkeys,
            requiresPin = state.pinSet == true,
            onDismiss = { showWrite = false },
            onConfirm = { request, pin ->
                showWrite = false
                viewModel.writePasskey(request, pin)
            },
        )
    }

    deleting?.let { credential ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text(context.getString(R.string.physical_key_delete_credential)) },
            text = {
                Text(context.getString(R.string.physical_key_delete_credential_body, credential.rpId.orEmpty()))
            },
            confirmButton = {
                TextButton(onClick = {
                    val target = credential
                    deleting = null
                    requestPin(viewModel, state.pinSet, pinPrompt = { pinPrompt = it }) { pin ->
                        viewModel.deleteCredential(target, pin)
                    }
                }) {
                    Text(context.getString(R.string.delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { deleting = null }) {
                    Text(context.getString(R.string.cancel))
                }
            },
        )
    }
}

private data class PinPrompt(
    @StringRes val titleRes: Int,
    @StringRes val messageRes: Int,
    @StringRes val confirmRes: Int,
    val onConfirm: (String) -> Unit,
)

private fun requestPin(
    viewModel: PhysicalKeyViewModel,
    pinSet: Boolean?,
    pinPrompt: (PinPrompt) -> Unit,
    action: (String?) -> Unit,
) {
    if (pinSet == true) {
        pinPrompt(
            PinPrompt(
                titleRes = R.string.physical_key_enter_pin,
                messageRes = R.string.physical_key_enter_pin_body,
                confirmRes = R.string.ok,
                onConfirm = { pin -> action(pin) },
            )
        )
    } else {
        action(null)
    }
}

@Composable
private fun PhysicalKeyHeader(
    connected: Boolean,
    connecting: Boolean,
    transportLabel: String?,
    onDisconnect: () -> Unit,
    showSettingsEntry: Boolean,
    onOpenSettings: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Default.Key,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.physical_key_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = when {
                    connecting -> stringResource(R.string.physical_key_connecting)
                    connected -> stringResource(
                        R.string.physical_key_connected_via,
                        transportLabel ?: stringResource(R.string.physical_key_transport_unknown),
                    )
                    else -> stringResource(R.string.physical_key_disconnected)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (connected) {
            IconButton(onClick = onDisconnect) {
                Icon(Icons.Default.Close, contentDescription = stringResource(R.string.physical_key_disconnect))
            }
        }
        if (showSettingsEntry) {
            IconButton(onClick = onOpenSettings) {
                Icon(Icons.Default.Settings, contentDescription = stringResource(R.string.nav_settings))
            }
        }
    }
}

@Composable
private fun ConnectCard(
    connecting: Boolean,
    nfcSupported: Boolean,
    nfcEnabled: Boolean,
    onOpenNfcSettings: () -> Unit,
    usbDevices: List<UsbDevice>,
    onConnectUsb: (UsbDevice) -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (connecting) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.physical_key_connecting))
                }
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Nfc, contentDescription = null)
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(
                            text = stringResource(R.string.physical_key_nfc_title),
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Text(
                            text = when {
                                !nfcSupported -> stringResource(R.string.physical_key_nfc_unsupported)
                                !nfcEnabled -> stringResource(R.string.physical_key_nfc_disabled)
                                else -> stringResource(R.string.physical_key_nfc_ready)
                            },
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                if (nfcSupported && !nfcEnabled) {
                    OutlinedButton(onClick = onOpenNfcSettings) {
                        Text(stringResource(R.string.physical_key_open_nfc_settings))
                    }
                }

                HorizontalDivider()

                Text(
                    text = stringResource(R.string.physical_key_usb_title),
                    style = MaterialTheme.typography.titleMedium,
                )
                if (usbDevices.isEmpty()) {
                    Text(
                        text = stringResource(R.string.physical_key_usb_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    usbDevices.forEach { device ->
                        OutlinedButton(
                            onClick = { onConnectUsb(device) },
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
                }
            }
        }
    }
}

@Composable
private fun DeviceCard(info: DeviceInfo?, pinSet: Boolean?, pinRetries: Int?) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = stringResource(R.string.physical_key_device_info),
                style = MaterialTheme.typography.titleMedium,
            )
            if (info == null) {
                Text(stringResource(R.string.physical_key_device_info_unavailable))
                return@Column
            }
            info.aaguid?.let { aaguid ->
                DetailLine(stringResource(R.string.physical_key_aaguid), aaguid.toString())
            }
            if (info.versions.isNotEmpty()) {
                DetailLine(stringResource(R.string.physical_key_versions), info.versions.joinToString(", "))
            }
            info.firmwareVersion?.let {
                DetailLine(stringResource(R.string.physical_key_firmware), it.toString())
            }
            DetailLine(
                stringResource(R.string.physical_key_pin_status),
                when (pinSet) {
                    true -> pinRetries?.let {
                        stringResource(R.string.physical_key_pin_retries, it)
                    } ?: stringResource(R.string.physical_key_pin_set)
                    false -> stringResource(R.string.physical_key_pin_not_set)
                    null -> stringResource(R.string.physical_key_unknown)
                },
            )
            DetailLine(
                stringResource(R.string.physical_key_resident_support),
                if (info.options["rk"] == true) stringResource(R.string.physical_key_yes)
                else stringResource(R.string.physical_key_no),
            )
            DetailLine(
                stringResource(R.string.physical_key_uv_support),
                if (info.supportsBuiltInUv) stringResource(R.string.physical_key_yes)
                else stringResource(R.string.physical_key_no),
            )
        }
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.widthIn(min = 110.dp),
        )
        Spacer(Modifier.width(12.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun PinActionsCard(
    pinSet: Boolean?,
    busy: Boolean,
    onSetPin: () -> Unit,
    onChangePin: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.physical_key_pin_section),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = if (pinSet == true) {
                    stringResource(R.string.physical_key_pin_required_for_management)
                } else {
                    stringResource(R.string.physical_key_set_pin_first)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (pinSet != true) {
                    Button(onClick = onSetPin, enabled = !busy) {
                        Icon(Icons.Default.Lock, contentDescription = null)
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.physical_key_set_pin))
                    }
                }
                OutlinedButton(onClick = onChangePin, enabled = !busy && pinSet != false) {
                    Text(stringResource(R.string.physical_key_change_pin))
                }
            }
        }
    }
}

@Composable
private fun ActionCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    body: String,
    buttonLabel: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null)
                Spacer(Modifier.width(10.dp))
                Text(title, style = MaterialTheme.typography.titleMedium)
            }
            Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Button(onClick = onClick, enabled = enabled) {
                Text(buttonLabel)
            }
        }
    }
}

@Composable
private fun InfoCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    body: String,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Row(Modifier.padding(16.dp)) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(body, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun CredentialsHeader(
    busy: Boolean,
    loaded: Boolean,
    count: Int,
    onLoad: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.physical_key_credentials_title),
                style = MaterialTheme.typography.titleMedium,
            )
            if (loaded) {
                Text(
                    text = stringResource(R.string.physical_key_credentials_count, count),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        OutlinedButton(onClick = onLoad, enabled = !busy) {
            Text(
                if (loaded) stringResource(R.string.physical_key_credentials_refresh)
                else stringResource(R.string.physical_key_credentials_load)
            )
        }
    }
}

@Composable
private fun CredentialRow(
    credential: StoredCredential,
    busy: Boolean,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Row(
            modifier = Modifier.padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = credential.rpId ?: credential.rpName
                        ?: stringResource(R.string.physical_key_unknown_relying_party),
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val account = listOfNotNull(
                    credential.userName?.takeIf { it.isNotBlank() },
                    credential.userDisplayName?.takeIf { it.isNotBlank() },
                ).joinToString(" · ")
                Text(
                    text = if (account.isBlank()) credential.shortId
                    else "$account · ${credential.shortId}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            IconButton(onClick = onDelete, enabled = !busy) {
                Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.delete))
            }
        }
    }
}

@Composable
private fun PinPromptDialog(
    title: String,
    message: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var pin by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(message)
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
                Text(confirmLabel)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        },
    )
}

@Composable
private fun SetPinDialog(
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var pin by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    val valid = pin.length >= 4 && pin == confirmation
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.physical_key_set_pin)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(R.string.physical_key_set_pin_body),
                    style = MaterialTheme.typography.bodyMedium,
                )
                PinField(value = pin, onValueChange = { pin = it }, label = stringResource(R.string.physical_key_new_pin))
                PinField(
                    value = confirmation,
                    onValueChange = { confirmation = it },
                    label = stringResource(R.string.physical_key_confirm_pin),
                )
                if (pin.isNotEmpty() && pin.length < 4) {
                    Text(
                        stringResource(R.string.physical_key_pin_too_short),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                } else if (confirmation.isNotEmpty() && pin != confirmation) {
                    Text(
                        stringResource(R.string.physical_key_pin_mismatch),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(pin) }, enabled = valid) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
    )
}

@Composable
private fun ChangePinDialog(
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit,
) {
    var current by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    val valid = current.isNotEmpty() && pin.length >= 4 && pin == confirmation
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.physical_key_change_pin)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                PinField(
                    value = current,
                    onValueChange = { current = it },
                    label = stringResource(R.string.physical_key_current_pin),
                )
                PinField(value = pin, onValueChange = { pin = it }, label = stringResource(R.string.physical_key_new_pin))
                PinField(
                    value = confirmation,
                    onValueChange = { confirmation = it },
                    label = stringResource(R.string.physical_key_confirm_pin),
                )
                if (confirmation.isNotEmpty() && pin != confirmation) {
                    Text(
                        stringResource(R.string.physical_key_pin_mismatch),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(current, pin) }, enabled = valid) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
    )
}

@Composable
private fun PinField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
    )
}

@Composable
private fun WritePasskeyDialog(
    passkeys: List<PasskeyEntry>,
    requiresPin: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (WritePasskeyRequest, String?) -> Unit,
) {
    var rpId by rememberSaveable { mutableStateOf("") }
    var rpName by rememberSaveable { mutableStateOf("") }
    var userName by rememberSaveable { mutableStateOf("") }
    var userDisplayName by rememberSaveable { mutableStateOf("") }
    var residentKey by rememberSaveable { mutableStateOf(true) }
    var pin by remember { mutableStateOf("") }
    var selectedUserId by remember { mutableStateOf<ByteArray?>(null) }
    var passkeyMenuOpen by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.physical_key_write_dialog_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(R.string.physical_key_write_dialog_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Box {
                    OutlinedButton(
                        onClick = { passkeyMenuOpen = true },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.physical_key_from_vault))
                    }
                    DropdownMenu(
                        expanded = passkeyMenuOpen,
                        onDismissRequest = { passkeyMenuOpen = false },
                    ) {
                        passkeys.take(30).forEach { passkey ->
                            DropdownMenuItem(
                                text = {
                                    Column {
                                        Text(passkey.rpId, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                        Text(
                                            passkey.userName,
                                            style = MaterialTheme.typography.bodySmall,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                    }
                                },
                                onClick = {
                                    rpId = passkey.rpId
                                    rpName = passkey.rpName
                                    userName = passkey.userName
                                    userDisplayName = passkey.userDisplayName
                                    selectedUserId = decodeUserHandle(passkey.userId)
                                    passkeyMenuOpen = false
                                },
                            )
                        }
                    }
                }
                OutlinedTextField(
                    value = rpId,
                    onValueChange = { rpId = it.trim() },
                    label = { Text(stringResource(R.string.physical_key_rp_id)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = rpName,
                    onValueChange = { rpName = it },
                    label = { Text(stringResource(R.string.physical_key_rp_name)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = userName,
                    onValueChange = { userName = it },
                    label = { Text(stringResource(R.string.physical_key_user_name)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = userDisplayName,
                    onValueChange = { userDisplayName = it },
                    label = { Text(stringResource(R.string.physical_key_user_display_name)) },
                    singleLine = true,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = residentKey, onCheckedChange = { residentKey = it })
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text(
                            stringResource(R.string.physical_key_resident_key),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            stringResource(R.string.physical_key_resident_key_body),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                if (requiresPin) {
                    PinField(
                        value = pin,
                        onValueChange = { pin = it },
                        label = stringResource(R.string.physical_key_pin),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm(
                        WritePasskeyRequest(
                            rpId = rpId,
                            rpName = rpName,
                            userName = userName,
                            userDisplayName = userDisplayName,
                            residentKey = residentKey,
                            userId = selectedUserId
                                ?: WritePasskeyRequest.stableUserId(rpId, userName),
                        ),
                        pin.takeIf { requiresPin && it.isNotEmpty() },
                    )
                },
                enabled = rpId.isNotBlank() && (!requiresPin || pin.isNotEmpty()),
            ) {
                Text(stringResource(R.string.physical_key_write_action))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
    )
}

private fun decodeUserHandle(raw: String): ByteArray? {
    if (raw.isBlank()) return null
    val flags = android.util.Base64.URL_SAFE or
        android.util.Base64.NO_PADDING or
        android.util.Base64.NO_WRAP
    return runCatching { android.util.Base64.decode(raw, flags) }
        .recoverCatching { android.util.Base64.decode(raw, android.util.Base64.DEFAULT) }
        .getOrNull()
        ?.takeIf { it.isNotEmpty() }
}

private fun Context.findActivity(): Activity? {
    var current: Context? = this
    while (current is ContextWrapper) {
        if (current is Activity) return current
        current = current.baseContext
    }
    return current as? Activity
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
