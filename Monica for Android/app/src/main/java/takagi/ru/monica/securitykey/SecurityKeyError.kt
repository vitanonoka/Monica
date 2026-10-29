package takagi.ru.monica.securitykey

sealed class SecurityKeyError(message: String) : Exception(message) {
    // Connection errors
    class NotIsoDepTag : SecurityKeyError("Not an ISO-DEP tag")
    class FidoAppletNotFound : SecurityKeyError("FIDO applet not found")
    class ConnectionFailed : SecurityKeyError("Connection failed")
    class NotConnected : SecurityKeyError("Not connected")

    // PIN protocol errors
    class PinProtocolNotInitialized : SecurityKeyError("PIN protocol not initialized")
    class PinProtocolInitFailed : SecurityKeyError("PIN protocol initialization failed")

    // Authentication errors
    class UserVerificationRequiredNoPin : SecurityKeyError("User verification required but no PIN set")
    class PinNotSupportedForOperation : SecurityKeyError("PIN cannot be used for this operation")
    class PinBlocked : SecurityKeyError("PIN is blocked")

    // On-device UV errors
    class UvBlocked : SecurityKeyError("Biometric verification is blocked")
}
