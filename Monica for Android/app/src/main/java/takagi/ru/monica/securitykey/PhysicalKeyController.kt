package takagi.ru.monica.securitykey

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.nfc.Tag
import android.nfc.TagLostException
import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import takagi.ru.monica.R

/** A resident credential that currently lives on the physical key. */
data class StoredCredential(
    val rpId: String?,
    val rpName: String?,
    val userName: String?,
    val userDisplayName: String?,
    val credentialId: ByteArray,
) {
    val shortId: String
        get() = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(credentialId)
            .take(18)
}

/** Parameters needed to program a discoverable passkey into a security key. */
data class WritePasskeyRequest(
    val rpId: String,
    val rpName: String = "",
    val userName: String = "",
    val userDisplayName: String = "",
    val residentKey: Boolean = true,
    val userId: ByteArray = stableUserId(rpId, userName),
) {
    companion object {
        fun stableUserId(rpId: String, userName: String): ByteArray =
            MessageDigest.getInstance("SHA-256")
                .digest("$rpId:$userName".toByteArray(Charsets.UTF_8))
    }
}

data class WrittenCredential(
    val rpId: String,
    val userName: String,
    val credentialId: ByteArray,
) {
    val shortId: String
        get() = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(credentialId)
            .take(18)
}

/** A WebAuthn creation request forwarded by Android's Credential Manager. */
data class WebAuthnCreateRequest(
    val clientDataHash: ByteArray,
    val rpId: String,
    val rpName: String?,
    val userId: ByteArray,
    val userName: String?,
    val userDisplayName: String?,
    val algorithms: List<Int>,
    val excludeCredentialIds: List<ByteArray> = emptyList(),
    val requireResidentKey: Boolean = true,
    val pin: String? = null,
)

/** The authenticator's answer, ready to be wrapped in a WebAuthn creation response. */
data class WebAuthnCreateResult(
    val credentialId: ByteArray,
    val authenticatorData: ByteArray,
    val attestationObject: ByteArray,
    val transports: Set<String>,
    val userVerified: Boolean,
)

/** Transport-independent user-facing outcomes. The UI owns the localized text. */
sealed interface KeyFailure {
    data object Connection : KeyFailure
    data object NotSecurityKey : KeyFailure
    data object Disconnected : KeyFailure
    data object NfcLost : KeyFailure
    data object PinNotSet : KeyFailure
    data object PinRequired : KeyFailure
    data object PinIncorrect : KeyFailure
    data object PinBlocked : KeyFailure
    data object PinPolicy : KeyFailure
    data object NoCredentials : KeyFailure
    data object StoreFull : KeyFailure
    data object Timeout : KeyFailure
    data object OperationDenied : KeyFailure
    data object CredentialExcluded : KeyFailure
    data object Unsupported : KeyFailure
    data class Other(val detail: String) : KeyFailure
}

sealed interface KeyNotice {
    data class Success(@StringRes val message: Int) : KeyNotice
    data class Failure(val failure: KeyFailure) : KeyNotice
}

fun Throwable.toKeyFailure(): KeyFailure = when (this) {
    is SecurityKeyError.NotIsoDepTag, is SecurityKeyError.FidoAppletNotFound -> KeyFailure.NotSecurityKey
    is SecurityKeyError.NotConnected -> KeyFailure.Disconnected
    is SecurityKeyError.ConnectionFailed -> KeyFailure.Connection
    is SecurityKeyError.UserVerificationRequiredNoPin -> KeyFailure.PinNotSet
    is SecurityKeyError.PinBlocked, is SecurityKeyError.UvBlocked -> KeyFailure.PinBlocked
    is SecurityKeyError.PinProtocolNotInitialized,
    is SecurityKeyError.PinProtocolInitFailed,
    is SecurityKeyError.PinNotSupportedForOperation -> KeyFailure.Unsupported
    is TagLostException -> KeyFailure.NfcLost
    is PinProtocol.PinSetError.PinAlreadySet -> KeyFailure.PinPolicy
    is PinProtocol.PinSetError.PinPolicyViolation -> KeyFailure.PinPolicy
    is PinProtocol.PinSetError.PinTooLong -> KeyFailure.PinPolicy
    is PinProtocol.PinSetError.PinBlocked -> KeyFailure.PinBlocked
    is PinProtocol.PinChangeError.InvalidPin -> KeyFailure.PinIncorrect
    is PinProtocol.PinChangeError.PinBlocked -> KeyFailure.PinBlocked
    is PinProtocol.PinChangeError.PinPolicyViolation -> KeyFailure.PinPolicy
    is PinProtocol.PinChangeError.PinTooLong -> KeyFailure.PinPolicy
    is PinProtocol.PinChangeError.PinNotSet -> KeyFailure.PinNotSet
    is CTAP.Exception -> when (error) {
        CTAP.Error.PIN_INVALID -> KeyFailure.PinIncorrect
        CTAP.Error.PIN_AUTH_INVALID -> KeyFailure.PinIncorrect
        CTAP.Error.PIN_BLOCKED, CTAP.Error.PIN_AUTH_BLOCKED, CTAP.Error.UV_BLOCKED -> KeyFailure.PinBlocked
        CTAP.Error.PIN_NOT_SET -> KeyFailure.PinNotSet
        CTAP.Error.PIN_REQUIRED -> KeyFailure.PinRequired
        CTAP.Error.PIN_POLICY_VIOLATION -> KeyFailure.PinPolicy
        CTAP.Error.NO_CREDENTIALS -> KeyFailure.NoCredentials
        CTAP.Error.KEY_STORE_FULL -> KeyFailure.StoreFull
        CTAP.Error.TIMEOUT, CTAP.Error.USER_ACTION_TIMEOUT, CTAP.Error.ACTION_TIMEOUT -> KeyFailure.Timeout
        CTAP.Error.OPERATION_DENIED, CTAP.Error.KEEPALIVE_CANCEL -> KeyFailure.OperationDenied
        CTAP.Error.CREDENTIAL_EXCLUDED -> KeyFailure.CredentialExcluded
        CTAP.Error.UNSUPPORTED_ALGORITHM, CTAP.Error.UNSUPPORTED_OPTION, CTAP.Error.INVALID_COMMAND -> KeyFailure.Unsupported
        else -> KeyFailure.Other(error.name)
    }
    else -> KeyFailure.Other(message.orEmpty())
}

/**
 * Owns the connection to a FIDO2 security key. Credentials never leave the key:
 * only public metadata is read back, and "writing" creates a new discoverable
 * credential on the authenticator.
 */
class PhysicalKeyViewModel : ViewModel() {

    data class UiState(
        val connecting: Boolean = false,
        val connected: Boolean = false,
        val transport: TransportType? = null,
        val deviceInfo: DeviceInfo? = null,
        val pinSet: Boolean? = null,
        val pinRetries: Int? = null,
        val credentials: List<StoredCredential> = emptyList(),
        val credentialsLoaded: Boolean = false,
        val busy: Boolean = false,
        val notice: KeyNotice? = null,
        val lastWritten: WrittenCredential? = null,
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private var session: CtapSession? = null

    private val io = Dispatchers.IO

    override fun onCleared() {
        session?.close()
        session = null
        super.onCleared()
    }

    fun onTagDiscovered(tag: Tag) {
        if (_state.value.connected || _state.value.connecting) return
        connect { NfcTransport.connect(tag) }
    }

    fun connectUsb(manager: UsbManager, device: UsbDevice) {
        if (_state.value.connected || _state.value.connecting) return
        connect { UsbTransport.connect(manager, device) }
    }

    private fun connect(open: suspend () -> FidoTransport) {
        _state.update { it.copy(connecting = true, notice = null, lastWritten = null) }
        viewModelScope.launch {
            val transport = runCatching { withContext(io) { open() } }
                .getOrElse {
                    session?.close()
                    session = null
                    _state.update { state ->
                        state.copy(connecting = false, connected = false, notice = KeyNotice.Failure(it.toKeyFailure()))
                    }
                    return@launch
                }

            runCatching { CtapSession.attach(transport) }
                .onSuccess { attached ->
                    session?.close()
                    session = attached
                    val info = attached.deviceInfo
                    val pinStatus = runCatching {
                        withContext(io) { readPinStatus(attached.transport, info) }
                    }.getOrDefault(null to null)
                    _state.update {
                        it.copy(
                            connecting = false,
                            connected = true,
                            transport = attached.transportType,
                            deviceInfo = info,
                            pinSet = pinStatus.first,
                            pinRetries = pinStatus.second,
                            credentials = emptyList(),
                            credentialsLoaded = false,
                        )
                    }
                }
                .onFailure {
                    transport.close()
                    session = null
                    _state.update { state ->
                        state.copy(connecting = false, connected = false, notice = KeyNotice.Failure(it.toKeyFailure()))
                    }
                }
        }
    }

    private suspend fun readPinStatus(transport: FidoTransport, info: DeviceInfo): Pair<Boolean?, Int?> {
        if (info.clientPinSet) {
            val retries = PinProtocol(transport).getPinRetries().getOrNull()
            return true to retries
        }
        if (info.options["clientPin"] == false) return false to null
        return PinProtocol(transport).getPinRetries().fold(
            onSuccess = { true to it },
            onFailure = { error ->
                when ((error as? CTAP.Exception)?.error) {
                    CTAP.Error.PIN_NOT_SET -> false to null
                    else -> null to null
                }
            }
        )
    }

    fun disconnect() {
        session?.close()
        session = null
        _state.value = UiState()
    }

    fun consumeNotice() {
        _state.update { it.copy(notice = null) }
    }

    fun setPin(pin: String) = privileged {
        val active = requireSession()
        val initialized = PinProtocol(active.transport).initialize().getOrThrow()
        initialized.setPin(pin).getOrThrow()
        updatePinState(true)
        notifySuccess(R.string.physical_key_pin_saved)
    }

    fun changePin(currentPin: String, newPin: String) = privileged {
        val active = requireSession()
        val initialized = PinProtocol(active.transport).initialize().getOrThrow()
        initialized.changePin(currentPin, newPin).getOrThrow()
        updatePinState(true)
        notifySuccess(R.string.physical_key_pin_changed)
    }

    fun loadCredentials(pin: String?) = privileged {
        val active = requireSession()
        val token = authenticate(active, pin, PinProtocol.PERMISSION_CM, rpId = null)
        val management = CredentialManagement(
            active.transport,
            token,
            active.deviceInfo.usePreviewCommand,
        )
        val relyingParties = management.enumerateRelyingParties().getOrThrow()
        val credentials = mutableListOf<StoredCredential>()
        relyingParties.forEach { rp ->
            management.enumerateCredentials(rp.rpIdHash).getOrThrow().forEach { credential ->
                credentials += StoredCredential(
                    rpId = rp.rpId ?: credential.rpId,
                    rpName = rp.rpName,
                    userName = credential.userName,
                    userDisplayName = credential.userDisplayName,
                    credentialId = credential.credentialId,
                )
            }
        }
        _state.update {
            it.copy(credentials = credentials, credentialsLoaded = true)
        }
    }

    fun deleteCredential(credential: StoredCredential, pin: String?) = privileged {
        val active = requireSession()
        val token = authenticate(active, pin, PinProtocol.PERMISSION_CM, rpId = null)
        val management = CredentialManagement(
            active.transport,
            token,
            active.deviceInfo.usePreviewCommand,
        )
        management.deleteCredential(credential.credentialId).getOrThrow()
        _state.update { it.copy(credentials = it.credentials.filterNot { item ->
            item.credentialId.contentEquals(credential.credentialId)
        }) }
        notifySuccess(R.string.physical_key_credential_deleted)
    }

    fun writePasskey(request: WritePasskeyRequest, pin: String?) = privileged {
        require(request.rpId.isNotBlank()) { "RP ID is required" }
        val active = requireSession()
        val clientDataHash = MessageDigest.getInstance("SHA-256")
            .digest(clientDataJson(request.rpId))

        val uvMode = resolveUvMode(active, pin, clientDataHash, request.rpId)

        val response = withContext(io) {
            active.transport.sendCtapCommand(
                FidoCommands.buildMakeCredential(
                    clientDataHash = clientDataHash,
                    rpId = request.rpId,
                    rpName = request.rpName.ifBlank { null },
                    userId = request.userId.take(64).toByteArray(),
                    userName = request.userName.ifBlank { null },
                    userDisplayName = request.userDisplayName.ifBlank { null },
                    pubKeyCredParams = listOf("public-key" to -7),
                    requireResidentKey = request.residentKey,
                    uvMode = uvMode,
                )
            )
        }
        val parsed = FidoCommands.parseMakeCredentialResponse(response).getOrThrow()
        val authData = AuthenticatorData.parse(parsed.authData)
        val credential = authData?.attestedCredentialData
        requireNotNull(credential) { "Authenticator did not return a credential" }

        _state.update {
            it.copy(
                lastWritten = WrittenCredential(
                    rpId = request.rpId,
                    userName = request.userName,
                    credentialId = credential.credentialId,
                ),
                credentialsLoaded = false,
                credentials = emptyList(),
            )
        }
        notifySuccess(R.string.physical_key_write_success)
    }

    /**
     * Creates a credential on the connected hardware key for a Credential Manager
     * request. The caller supplies its own clientDataHash because the returned
     * attestation must match the clientDataJSON it will return to the RP.
     */
    suspend fun createWebAuthnCredential(
        request: WebAuthnCreateRequest,
    ): Result<WebAuthnCreateResult> = runCatching {
        withContext(io) {
            require(request.rpId.isNotBlank()) { "Relying party ID is required" }
            val active = requireSession()
            val uvMode = resolveUvMode(active, request.pin, request.clientDataHash, request.rpId)
            val excludeList = request.excludeCredentialIds
                .filter { it.isNotEmpty() }
                .map { FidoCommands.CredentialDescriptor("public-key", it) }
                .ifEmpty { null }
            val response = active.transport.sendCtapCommand(
                FidoCommands.buildMakeCredential(
                    clientDataHash = request.clientDataHash,
                    rpId = request.rpId,
                    rpName = request.rpName,
                    userId = request.userId.take(64).toByteArray(),
                    userName = request.userName,
                    userDisplayName = request.userDisplayName,
                    pubKeyCredParams = request.algorithms.ifEmpty { listOf(-7) }
                        .map { "public-key" to it },
                    excludeList = excludeList,
                    requireResidentKey = request.requireResidentKey,
                    uvMode = uvMode,
                )
            )
            val parsed = FidoCommands.parseMakeCredentialResponse(response).getOrThrow()
            val authenticatorData = AuthenticatorData.parse(parsed.authData)
                ?: error("Authenticator returned invalid authenticator data")
            val credential = authenticatorData.attestedCredentialData
                ?: error("Authenticator did not return attested credential data")
            val attestationObject = cbor {
                map {
                    1 to parsed.fmt
                    2 to bytes(parsed.authData)
                    3 to parsed.attStmt
                }
            }
            val transports = (setOf(active.transportType.value) +
                active.deviceInfo.transports.map { it.value }).toSet()
            WebAuthnCreateResult(
                credentialId = credential.credentialId,
                authenticatorData = parsed.authData,
                attestationObject = attestationObject,
                transports = transports,
                userVerified = authenticatorData.userVerified,
            )
        }
    }

    private suspend fun resolveUvMode(
        active: CtapSession,
        pin: String?,
        clientDataHash: ByteArray,
        rpId: String,
    ): FidoCommands.UvMode = when {
        pin != null -> {
            val token = authenticate(active, pin, PinProtocol.PERMISSION_MC, rpId)
            FidoCommands.UvMode.AuthToken(token.computeAuthParam(clientDataHash), 1)
        }
        active.deviceInfo.supportsBuiltInUv -> {
            val token = authenticate(active, null, PinProtocol.PERMISSION_MC, rpId)
            FidoCommands.UvMode.AuthToken(token.computeAuthParam(clientDataHash), 1)
        }
        else -> FidoCommands.UvMode.None
    }

    private fun privileged(block: suspend () -> Unit) {
        if (_state.value.busy) return
        _state.update { it.copy(busy = true, notice = null) }
        viewModelScope.launch {
            runCatching { withContext(io) { block() } }
                .onFailure { error ->
                    _state.update { it.copy(notice = KeyNotice.Failure(error.toKeyFailure())) }
                }
            _state.update { it.copy(busy = false) }
        }
    }

    private suspend fun authenticate(
        active: CtapSession,
        pin: String?,
        permission: Int,
        rpId: String?,
    ): PinProtocol.Authenticated {
        val protocol = PinProtocol(active.transport)
        val initialized = protocol.initialize().getOrThrow()
        if (pin != null) {
            return initialized.requestPinToken(pin, permission, rpId).getOrThrow()
        }
        if (active.deviceInfo.supportsBuiltInUv) {
            return initialized.requestUvToken(permission, rpId).getOrThrow()
        }
        throw SecurityKeyError.UserVerificationRequiredNoPin()
    }

    private fun requireSession(): CtapSession =
        session?.takeIf { it.isConnected } ?: throw SecurityKeyError.NotConnected()

    private fun updatePinState(set: Boolean) {
        _state.update { it.copy(pinSet = set) }
    }

    private fun notifySuccess(@StringRes message: Int) {
        _state.update { it.copy(notice = KeyNotice.Success(message)) }
    }

    private fun fail(failure: KeyFailure) {
        _state.update { it.copy(notice = KeyNotice.Failure(failure)) }
    }

    private fun clientDataJson(rpId: String): ByteArray {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val encodedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge)
        val origin = "https://$rpId"
        return """{"type":"webauthn.create","challenge":"$encodedChallenge","origin":"$origin","crossOrigin":false}"""
            .toByteArray(Charsets.UTF_8)
    }
}
