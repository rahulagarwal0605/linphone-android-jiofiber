/*
 * Copyright (c) 2010-2023 Belledonne Communications SARL.
 *
 * This file is part of linphone-android
 * (see https://www.linphone.org).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package org.linphone.ui.assistant.viewmodel

import androidx.annotation.UiThread
import androidx.annotation.WorkerThread
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.MutableLiveData
import java.net.URLEncoder
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Locale
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.xml.parsers.DocumentBuilderFactory
import org.linphone.LinphoneApplication.Companion.coreContext
import org.linphone.LinphoneApplication.Companion.corePreferences
import org.linphone.R
import org.linphone.core.Account
import org.linphone.core.AuthInfo
import org.linphone.core.Core
import org.linphone.core.CoreListenerStub
import org.linphone.core.Factory
import org.linphone.core.Reason
import org.linphone.core.RegistrationState
import org.linphone.core.TransportType
import org.linphone.core.tools.Log
import org.linphone.ui.GenericViewModel
import org.linphone.utils.AppUtils
import org.linphone.utils.Event

class ThirdPartySipAccountLoginViewModel
    @UiThread
    constructor() : GenericViewModel() {
    companion object {
        private const val TAG = "[Third Party SIP Account Login ViewModel]"
    }

    val username = MutableLiveData<String>()

    val authId = MutableLiveData<String>()

    val password = MutableLiveData<String>()

    val domain = MutableLiveData<String>()

    val displayName = MutableLiveData<String>()

    val transport = MutableLiveData<String>()

    val internationalPrefix = MutableLiveData<String>()

    val internationalPrefixIsoCountryCode = MutableLiveData<String>()

    val showPassword = MutableLiveData<Boolean>()

    val expandAdvancedSettings = MutableLiveData<Boolean>()

    val proxy = MutableLiveData<String>()

    val outboundProxy = MutableLiveData<String>()

    val loginEnabled = MediatorLiveData<Boolean>()

    val registrationInProgress = MutableLiveData<Boolean>()

    val accountLoggedInEvent: MutableLiveData<Event<Boolean>> by lazy {
        MutableLiveData<Event<Boolean>>()
    }

    val accountLoginErrorEvent: MutableLiveData<Event<String>> by lazy {
        MutableLiveData<Event<String>>()
    }

    val defaultTransportIndexEvent: MutableLiveData<Event<Int>> by lazy {
        MutableLiveData<Event<Int>>()
    }

    val availableTransports = arrayListOf<String>()

    private lateinit var newlyCreatedAuthInfo: AuthInfo
    private lateinit var newlyCreatedAccount: Account

    private val coreListener = object : CoreListenerStub() {
        @WorkerThread
        override fun onAccountRegistrationStateChanged(
            core: Core,
            account: Account,
            state: RegistrationState?,
            message: String
        ) {
            if (account == newlyCreatedAccount) {
                Log.i("$TAG Newly created account registration state is [$state] ($message)")

                if (state == RegistrationState.Ok) {
                    registrationInProgress.postValue(false)
                    core.removeListener(this)

                    // Set new account as default
                    core.defaultAccount = newlyCreatedAccount
                    accountLoggedInEvent.postValue(Event(true))
                } else if (state == RegistrationState.Failed) {
                    registrationInProgress.postValue(false)
                    core.removeListener(this)

                    val error = when (account.error) {
                        Reason.Forbidden -> {
                            AppUtils.getString(R.string.assistant_account_login_forbidden_error)
                        }
                        else -> {
                            AppUtils.getFormattedString(
                                R.string.assistant_account_login_error,
                                account.error.toString()
                            )
                        }
                    }
                    accountLoginErrorEvent.postValue(Event(error))

                    Log.e("$TAG Account failed to REGISTER [$message], removing it")
                    core.removeAuthInfo(newlyCreatedAuthInfo)
                    core.removeAccount(newlyCreatedAccount)
                }
            }
        }
    }

    init {
        showPassword.value = false
        expandAdvancedSettings.value = false
        registrationInProgress.value = false

        loginEnabled.addSource(username) {
            loginEnabled.value = isLoginButtonEnabled()
        }
        loginEnabled.addSource(domain) {
            loginEnabled.value = isLoginButtonEnabled()
        }

        // TODO: handle formatting errors ?

        availableTransports.add(TransportType.Udp.name.uppercase(Locale.getDefault()))
        availableTransports.add(TransportType.Tcp.name.uppercase(Locale.getDefault()))
        availableTransports.add(TransportType.Tls.name.uppercase(Locale.getDefault()))

        coreContext.postOnCoreThread {
            domain.postValue(corePreferences.thirdPartySipAccountDefaultDomain)

            val defaultTransport = corePreferences.thirdPartySipAccountDefaultTransport.uppercase(
                Locale.getDefault()
            )
            val index = if (defaultTransport.isNotEmpty()) {
                availableTransports.indexOf(defaultTransport)
            } else {
                availableTransports.size - 1
            }
            defaultTransportIndexEvent.postValue(Event(index))
        }
    }

    @UiThread
    fun login() {
        // If JioFiber credentials were prefilled, use direct login for reliable registration
        val creds = jioFiberCreds
        if (creds != null) {
            val sipUser = creds["username"] ?: return
            val sipPwd = creds["password"] ?: return
            val sipDomain = creds["domain"] ?: return
            jioFiberDirectLogin(sipUser, sipPwd, sipDomain)
            return
        }

        coreContext.postOnCoreThread { core ->
            core.loadConfigFromXml(corePreferences.thirdPartyDefaultValuesPath)

            // Remove sip: in front of domain, just in case...
            val domainValue = domain.value.orEmpty().trim()
            val domainWithoutSip = if (domainValue.startsWith("sip:")) {
                domainValue.substring("sip:".length)
            } else {
                domainValue
            }
            val domainAddress = Factory.instance().createAddress("sip:$domainWithoutSip")
            val port = domainAddress?.port ?: -1
            if (port != -1) {
                Log.w("$TAG It seems a port [$port] was set in the domain [$domainValue], removing it from SIP identity but setting it to proxy server URI")
            }
            val domain = domainAddress?.domain ?: domainWithoutSip

            // Allow to enter SIP identity instead of simply username
            // in case identity domain doesn't match proxy domain
            var user = username.value.orEmpty().trim()
            if (user.startsWith("sip:")) {
                user = user.substring("sip:".length)
            } else if (user.startsWith("sips:")) {
                user = user.substring("sips:".length)
            }
            if (user.contains("@")) {
                user = user.split("@")[0]
            }

            val userId = authId.value.orEmpty().trim()

            Log.i("$TAG Parsed username is [$user], user ID [$userId] and domain [$domain]")
            val identity = "sip:$user@$domain"
            val identityAddress = Factory.instance().createAddress(identity)
            if (identityAddress == null) {
                Log.e("$TAG Can't parse [$identity] as Address!")
                showRedToast(R.string.assistant_login_cant_parse_address_toast, R.drawable.warning_circle)
                return@postOnCoreThread
            }
            Log.i("$TAG Computed SIP identity is [${identityAddress.asStringUriOnly()}]")

            val accounts = core.accountList
            val found = accounts.find {
                it.params.identityAddress?.weakEqual(identityAddress) == true
            }
            if (found != null) {
                Log.w("$TAG An account with the same identity address [${found.params.identityAddress?.asStringUriOnly()}] already exists, do not add it again!")
                showRedToast(R.string.assistant_account_login_already_connected_error, R.drawable.warning_circle)
                return@postOnCoreThread
            }

            newlyCreatedAuthInfo = Factory.instance().createAuthInfo(
                user,
                userId,
                password.value.orEmpty().trim(),
                null,
                null,
                domainAddress?.domain ?: domainValue
            )
            core.addAuthInfo(newlyCreatedAuthInfo)

            val accountParams = core.createAccountParams()

            if (displayName.value.orEmpty().isNotEmpty()) {
                identityAddress.displayName = displayName.value.orEmpty().trim()
            }
            accountParams.identityAddress = identityAddress

            val proxyServerValue = proxy.value.orEmpty().trim()
            val proxyServerAddress = if (proxyServerValue.isNotEmpty()) {
                val server = if (proxyServerValue.startsWith("sip:")) {
                    proxyServerValue
                } else {
                    "sip:$proxyServerValue"
                }
                Factory.instance().createAddress(server)
            } else {
                domainAddress ?: Factory.instance().createAddress("sip:$domainWithoutSip")
            }
            proxyServerAddress?.transport = when (transport.value.orEmpty().trim()) {
                TransportType.Tcp.name.uppercase(Locale.getDefault()) -> TransportType.Tcp
                TransportType.Tls.name.uppercase(Locale.getDefault()) -> TransportType.Tls
                else -> TransportType.Udp
            }
            Log.i("$TAG Created proxy server SIP address [${proxyServerAddress?.asStringUriOnly()}]")
            accountParams.serverAddress = proxyServerAddress

            val outboundProxyValue = outboundProxy.value.orEmpty().trim()
            val outboundProxyAddress = if (outboundProxyValue.isNotEmpty()) {
                val server = if (outboundProxyValue.startsWith("sip:")) {
                    outboundProxyValue
                } else {
                    "sip:$outboundProxyValue"
                }
                Factory.instance().createAddress(server)
            } else {
                null
            }
            if (outboundProxyAddress != null) {
                outboundProxyAddress.transport = when (transport.value.orEmpty().trim()) {
                    TransportType.Tcp.name.uppercase(Locale.getDefault()) -> TransportType.Tcp
                    TransportType.Tls.name.uppercase(Locale.getDefault()) -> TransportType.Tls
                    else -> TransportType.Udp
                }
                Log.i("$TAG Created outbound proxy server SIP address [${outboundProxyAddress?.asStringUriOnly()}]")
                accountParams.setRoutesAddresses(arrayOf(outboundProxyAddress))
            }

            val prefix = internationalPrefix.value.orEmpty().trim()
            val isoCountryCode = internationalPrefixIsoCountryCode.value.orEmpty()
            if (prefix.isNotEmpty()) {
                val prefixDigits = if (prefix.startsWith("+")) {
                    prefix.substring(1)
                } else {
                    prefix
                }
                if (prefixDigits.isNotEmpty()) {
                    Log.i(
                        "$TAG Setting international prefix [$prefixDigits]($isoCountryCode) in account params"
                    )
                    accountParams.internationalPrefix = prefixDigits
                    accountParams.internationalPrefixIsoCountryCode = isoCountryCode
                }
            }

            newlyCreatedAccount = core.createAccount(accountParams)

            registrationInProgress.postValue(true)
            core.addListener(coreListener)
            core.addAccount(newlyCreatedAccount)
        }
    }

    @UiThread
    fun toggleShowPassword() {
        showPassword.value = showPassword.value == false
    }

    @UiThread
    private fun isLoginButtonEnabled(): Boolean {
        // Password isn't mandatory as authentication could be Bearer
        return username.value.orEmpty().isNotEmpty() && domain.value.orEmpty().isNotEmpty()
    }

    @UiThread
    fun toggleAdvancedSettingsExpand() {
        expandAdvancedSettings.value = expandAdvancedSettings.value == false
    }

    // Stores provisioned JioFiber credentials for use by login()
    private var jioFiberCreds: Map<String, String>? = null

    @UiThread
    fun prefillJioFiberCredentials() {
        Thread {
            try {
                val creds = provisionFromJioFiber()
                if (creds != null) {
                    jioFiberCreds = creds
                    val sipUser = creds["username"] ?: return@Thread
                    val sipPwd = creds["password"] ?: return@Thread
                    val sipDomain = creds["domain"] ?: return@Thread

                    // Prefill UI fields
                    username.postValue("+$sipUser")
                    authId.postValue(sipUser)
                    password.postValue(sipPwd)
                    domain.postValue(sipDomain)
                    displayName.postValue("JioFiber")
                    transport.postValue("TLS")
                    val tlsIndex = availableTransports.indexOf("TLS")
                    if (tlsIndex >= 0) {
                        defaultTransportIndexEvent.postValue(Event(tlsIndex))
                    }
                    outboundProxy.postValue("sip:192.168.29.1:5068;transport=tls")
                    Log.i("$TAG JioFiber credentials prefilled, user can tap Login")
                } else {
                    Log.w("$TAG JioFiber provisioning returned no credentials")
                }
            } catch (e: Exception) {
                Log.e("$TAG JioFiber provisioning failed: ${e.message}")
            }
        }.start()
    }

    private fun jioFiberDirectLogin(sipUser: String, sipPwd: String, sipDomain: String) {
        coreContext.postOnCoreThread { core ->
            core.loadConfigFromXml(corePreferences.thirdPartyDefaultValuesPath)

            val identity = "sip:+$sipUser@$sipDomain"
            val identityAddress = Factory.instance().createAddress(identity)
            if (identityAddress == null) {
                Log.e("$TAG Can't parse [$identity] as Address!")
                showRedToast(R.string.assistant_login_cant_parse_address_toast, R.drawable.warning_circle)
                return@postOnCoreThread
            }
            identityAddress.displayName = "JioFiber"

            Log.i("$TAG JioFiber direct login: identity=[${identityAddress.asStringUriOnly()}] authUser=[$sipUser]")

            // Auth info: username is the SIP user (+number), userid is the bare number for digest
            // realm=* to match any challenge realm
            newlyCreatedAuthInfo = Factory.instance().createAuthInfo(
                "+$sipUser",    // username (SIP identity user part)
                sipUser,        // userid (used in digest Authorization username field)
                sipPwd,         // password
                null,           // ha1
                sipDomain,      // realm
                sipDomain       // domain
            )
            core.addAuthInfo(newlyCreatedAuthInfo)

            val accountParams = core.createAccountParams()
            accountParams.identityAddress = identityAddress
            accountParams.expires = 300

            // Use outbound proxy directly as registrar
            val proxyAddress = Factory.instance().createAddress("sip:192.168.29.1:5068;transport=tls")
            accountParams.serverAddress = proxyAddress
            accountParams.setRoutesAddresses(arrayOf(proxyAddress))
            accountParams.isOutboundProxyEnabled = true

            // Disable AVPF (RTCP feedback) — B2BUA rejects rtcp-fb attributes
            accountParams.avpfMode = org.linphone.core.AVPFMode.Disabled
            accountParams.avpfRrInterval = 0

            accountParams.isDialEscapePlusEnabled = false

            // Override +sip.instance to use raw UUID format (no urn:uuid: prefix)
            // UUID must match the MAC used for provisioning
            val deviceMac = hostnameToMac(android.os.Build.MODEL).replace(":", "")
            val sipInstanceUuid = "00000000-0000-1000-8000-$deviceMac"
            Log.i("$TAG Using +sip.instance UUID: $sipInstanceUuid")
            accountParams.contactParameters = "+sip.instance=\"<$sipInstanceUuid>\""

            val prefix = internationalPrefix.value.orEmpty().trim()
            val isoCountryCode = internationalPrefixIsoCountryCode.value.orEmpty()
            if (prefix.isNotEmpty()) {
                val prefixDigits = if (prefix.startsWith("+")) prefix.substring(1) else prefix
                if (prefixDigits.isNotEmpty()) {
                    accountParams.internationalPrefix = prefixDigits
                    accountParams.internationalPrefixIsoCountryCode = isoCountryCode
                }
            }

            newlyCreatedAccount = core.createAccount(accountParams)

            registrationInProgress.postValue(true)
            core.addListener(coreListener)
            core.addAccount(newlyCreatedAccount)
            core.defaultAccount = newlyCreatedAccount
        }
    }

    private fun provisionFromJioFiber(): Map<String, String>? {
        val gatewayIp = "192.168.29.1"
        val port = 8443
        val hostname = android.os.Build.MODEL
        val mac = hostnameToMac(hostname)

        val params = mapOf(
            "terminal_sw_version" to "RCSAndrd",
            "terminal_vendor" to hostname,
            "terminal_model" to hostname,
            "SMS_port" to "0",
            "act_type" to "volatile",
            "IMSI" to "",
            "msisdn" to "",
            "IMEI" to "",
            "vers" to "0",
            "token" to "",
            "rcs_state" to "0",
            "rcs_version" to "5.1B",
            "rcs_profile" to "joyn_blackbird",
            "client_vendor" to "JUIC",
            "default_sms_app" to "2",
            "default_vvm_app" to "0",
            "device_type" to "vvm",
            "client_version" to "JSEAndrd-1.0",
            "mac_address" to mac,
            "alias" to hostname,
            "nwk_intf" to "eth"
        )

        val query = params.entries.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
        }

        // Trust all certs (JioFiber uses self-signed)
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}

            override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(null, trustAll, SecureRandom())

        val url = java.net.URL("https://$gatewayIp:$port/?$query")
        val conn = url.openConnection() as HttpsURLConnection
        conn.sslSocketFactory = sslCtx.socketFactory
        conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
        conn.connectTimeout = 10000
        conn.readTimeout = 10000

        val responseCode = conn.responseCode
        if (responseCode != 200) {
            Log.e("$TAG JioFiber provisioning HTTP $responseCode")
            return null
        }

        val body = conn.inputStream.bufferedReader().readText()
        conn.disconnect()

        // Parse XML response
        val factory = DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        val doc = builder.parse(body.byteInputStream())
        val parms = doc.getElementsByTagName("parm")

        val extracted = mutableMapOf<String, String>()
        for (i in 0 until parms.length) {
            val node = parms.item(i)
            val name = node.attributes.getNamedItem("name")?.nodeValue ?: continue
            val value = node.attributes.getNamedItem("value")?.nodeValue ?: continue
            extracted[name] = value
        }

        val sipDomain = extracted["home_network_domain_name"] ?: return null
        val sipUserRaw = extracted["username"] ?: return null
        val sipPwd = extracted["userpwd"] ?: return null

        // username may be "user@domain" format — strip domain part
        val sipUser = if (sipUserRaw.contains("@")) sipUserRaw.split("@")[0] else sipUserRaw

        Log.i("$TAG JioFiber provisioned: user=$sipUser (raw=$sipUserRaw) domain=$sipDomain")

        return mapOf(
            "username" to sipUser,
            "password" to sipPwd,
            "domain" to sipDomain
        )
    }

    private fun hostnameToMac(hostname: String): String {
        var h = 0L
        for (b in hostname.toByteArray(Charsets.UTF_8)) {
            h = (h * 33 + (b.toInt() and 0xFF)) and 0xFFFFFFFFL
        }
        val hex = String.format("%08X", h)
        val reversed = hex.chunked(2).reversed().joinToString("")
        val padded = reversed.lowercase().padStart(12, '0')
        return padded.chunked(2).joinToString(":")
    }
}
