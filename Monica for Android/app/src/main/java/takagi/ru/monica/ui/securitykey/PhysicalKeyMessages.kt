package takagi.ru.monica.ui.securitykey

import android.content.Context
import takagi.ru.monica.R
import takagi.ru.monica.securitykey.KeyFailure
import takagi.ru.monica.securitykey.KeyNotice

internal fun KeyNotice.localized(context: Context): String = when (this) {
    is KeyNotice.Success -> context.getString(message)
    is KeyNotice.Failure -> failure.localized(context)
}

internal fun KeyFailure.localized(context: Context): String = when (this) {
    KeyFailure.Connection -> context.getString(R.string.physical_key_error_connection)
    KeyFailure.NotSecurityKey -> context.getString(R.string.physical_key_error_not_key)
    KeyFailure.Disconnected -> context.getString(R.string.physical_key_error_disconnected)
    KeyFailure.NfcLost -> context.getString(R.string.physical_key_error_nfc_lost)
    KeyFailure.PinNotSet -> context.getString(R.string.physical_key_error_pin_not_set)
    KeyFailure.PinRequired -> context.getString(R.string.physical_key_error_pin_required)
    KeyFailure.PinIncorrect -> context.getString(R.string.physical_key_error_pin_incorrect)
    KeyFailure.PinBlocked -> context.getString(R.string.physical_key_error_pin_blocked)
    KeyFailure.PinPolicy -> context.getString(R.string.physical_key_error_pin_policy)
    KeyFailure.NoCredentials -> context.getString(R.string.physical_key_error_no_credentials)
    KeyFailure.StoreFull -> context.getString(R.string.physical_key_error_store_full)
    KeyFailure.Timeout -> context.getString(R.string.physical_key_error_timeout)
    KeyFailure.OperationDenied -> context.getString(R.string.physical_key_error_denied)
    KeyFailure.CredentialExcluded -> context.getString(R.string.physical_key_error_excluded)
    KeyFailure.Unsupported -> context.getString(R.string.physical_key_error_unsupported)
    is KeyFailure.Other -> context.getString(R.string.physical_key_error_other, detail)
}
