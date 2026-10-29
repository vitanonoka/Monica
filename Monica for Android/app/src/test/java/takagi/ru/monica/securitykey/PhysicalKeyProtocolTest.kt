package takagi.ru.monica.securitykey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PhysicalKeyProtocolTest {

    @Test
    fun makeCredentialCarriesEveryWebAuthnFieldAndPinAuth() {
        val clientDataHash = ByteArray(32) { 0x11 }
        val userId = byteArrayOf(1, 2, 3, 4)
        val pinAuth = byteArrayOf(0x51, 0x52)

        val command = FidoCommands.buildMakeCredential(
            clientDataHash = clientDataHash,
            rpId = "example.com",
            rpName = "Example",
            userId = userId,
            userName = "alice",
            userDisplayName = "Alice",
            pubKeyCredParams = listOf("public-key" to -7),
            requireResidentKey = true,
            uvMode = FidoCommands.UvMode.AuthToken(pinAuth, 1),
        )

        assertEquals(CTAP.CMD_MAKE_CREDENTIAL, command[0].toInt())
        val payload = CborMap.decode(command.copyOfRange(1, command.size))
        assertNotNull(payload)
        assertArrayEquals(clientDataHash, payload!!.bytes(1))
        assertEquals("example.com", payload.map(2)?.string("id"))
        assertEquals("Example", payload.map(2)?.string("name"))
        assertArrayEquals(userId, payload.map(3)?.bytes("id"))
        assertEquals("alice", payload.map(3)?.string("name"))
        assertEquals("Alice", payload.map(3)?.string("displayName"))
        assertEquals(-7, payload.mapList(4)?.single()?.int("alg"))
        assertEquals(true, payload.map(7)?.bool("rk"))
        assertArrayEquals(pinAuth, payload.bytes(8))
        assertEquals(1, payload.int(9))
    }

    @Test
    fun authenticatorDataExposesTheWrittenCredentialId() {
        val credentialId = byteArrayOf(9, 8, 7, 6, 5)
        val coseKey = cbor {
            map {
                1 to 2
                3 to -7
                -1 to 1
                -2 to bytes(ByteArray(32) { 0x21 })
                -3 to bytes(ByteArray(32) { 0x22 })
            }
        }
        val authData = ByteArray(37) +
            ByteArray(16) { 0x33 } +
            byteArrayOf((credentialId.size shr 8).toByte(), credentialId.size.toByte()) +
            credentialId +
            coseKey
        authData[32] = (CTAP.AUTH_DATA_FLAG_UP or CTAP.AUTH_DATA_FLAG_AT).toByte()

        val parsed = AuthenticatorData.parse(authData)

        assertNotNull(parsed)
        assertTrue(parsed!!.hasAttestedCredentialData)
        assertArrayEquals(credentialId, parsed.attestedCredentialData?.credentialId)
        assertEquals(-7, parsed.attestedCredentialData?.publicKeyAlgorithm)
    }

    @Test
    fun attestationStatementMapsRoundTrip() {
        val attStmt = HashMap<Any?, Any?>()
        attStmt["alg"] = -7
        attStmt["sig"] = byteArrayOf(9, 8)
        val encoded = cbor {
            map {
                1 to "packed"
                2 to bytes(byteArrayOf(1, 2, 3))
                3 to attStmt
            }
        }

        val decoded = CborMap.decode(encoded)
        assertNotNull(decoded)
        assertEquals("packed", decoded!!.string(1))
        assertArrayEquals(byteArrayOf(1, 2, 3), decoded.bytes(2))
        assertEquals(-7, decoded.map(3)?.int("alg"))
        assertArrayEquals(byteArrayOf(9, 8), decoded.map(3)?.bytes("sig"))
    }

    @Test
    fun keyFailuresMapToStableUiStates() {
        assertEquals(KeyFailure.PinIncorrect, CTAP.Exception(CTAP.Error.PIN_INVALID).toKeyFailure())
        assertEquals(KeyFailure.PinBlocked, CTAP.Exception(CTAP.Error.PIN_BLOCKED).toKeyFailure())
        assertEquals(KeyFailure.StoreFull, CTAP.Exception(CTAP.Error.KEY_STORE_FULL).toKeyFailure())
        assertEquals(KeyFailure.NotSecurityKey, SecurityKeyError.NotIsoDepTag().toKeyFailure())
        assertEquals(KeyFailure.PinNotSet, SecurityKeyError.UserVerificationRequiredNoPin().toKeyFailure())
    }

    @Test
    fun stableUserIdIsDeterministicAndSizedForCtap() {
        val first = WritePasskeyRequest.stableUserId("example.com", "alice")
        val second = WritePasskeyRequest.stableUserId("example.com", "alice")
        val other = WritePasskeyRequest.stableUserId("example.com", "bob")

        assertArrayEquals(first, second)
        assertEquals(32, first.size)
        assertTrue(!first.contentEquals(other))
    }
}
