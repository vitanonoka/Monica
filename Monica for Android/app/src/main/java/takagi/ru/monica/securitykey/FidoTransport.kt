package takagi.ru.monica.securitykey

/**
 * Common interface for FIDO transport (NFC or USB)
 */
interface FidoTransport {
    val transportType: TransportType
    val isConnected: Boolean

    /**
     * Verify that the transport connection is still active and usable.
     * Throws [SecurityKeyError.NotConnected] if the connection has been lost
     * (e.g. another app claimed the USB interface, or an NFC tag moved out of range).
     */
    @Throws(SecurityKeyError.NotConnected::class)
    fun reclaimConnection()

    @Throws(Exception::class)
    suspend fun sendCtapCommand(command: ByteArray): ByteArray

    fun close()
}
