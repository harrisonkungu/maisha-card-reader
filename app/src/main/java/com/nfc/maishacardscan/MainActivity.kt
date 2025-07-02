/*
 * Copyright 2025 Harrison Kungu  (harrisonkungu96@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@file:Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")

package com.nfc.maishacardscan

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.graphics.Bitmap
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.AsyncTask
import android.os.Bundle
import android.preference.PreferenceManager
import android.text.Editable
import android.text.TextWatcher
import android.util.Base64
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.nfc.maishacardscan.ImageUtil.decodeImage
import com.wdullaer.materialdatetimepicker.date.DatePickerDialog
import net.sf.scuba.smartcards.CardService
import net.sf.scuba.smartcards.CardServiceException
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.x509.Certificate
import org.jmrtd.BACKey
import org.jmrtd.BACKeySpec
import org.jmrtd.PACEException
import org.jmrtd.PassportService
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.SecurityInfo
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.icao.DG7File
import org.jmrtd.lds.iso19794.FaceImageInfo
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.*

abstract class MainActivity : AppCompatActivity() {

    private lateinit var passportNumberView: EditText
    private lateinit var expirationDateView: EditText
    private lateinit var birthDateView: EditText
    private var passportNumberFromIntent = false
    private var encodePhotoToBase64 = false
    private lateinit var mainLayout: View
    private lateinit var loadingLayout: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val preferences = PreferenceManager.getDefaultSharedPreferences(this)
        val dateOfBirth = intent.getStringExtra("dateOfBirth")
        val dateOfExpiry = intent.getStringExtra("dateOfExpiry")
        val passportNumber = intent.getStringExtra("passportNumber")
        encodePhotoToBase64 = intent.getBooleanExtra("photoAsBase64", false)
        if (dateOfBirth != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                .edit().putString(KEY_BIRTH_DATE, dateOfBirth).apply()
        }
        if (dateOfExpiry != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                .edit().putString(KEY_EXPIRATION_DATE, dateOfExpiry).apply()
        }
        if (passportNumber != null) {
            PreferenceManager.getDefaultSharedPreferences(this)
                .edit().putString(KEY_PASSPORT_NUMBER, passportNumber).apply()
            passportNumberFromIntent = true
        }

        passportNumberView = findViewById(R.id.input_passport_number)
        expirationDateView = findViewById(R.id.input_expiration_date)
        birthDateView = findViewById(R.id.input_date_of_birth)
        mainLayout = findViewById(R.id.main_layout)
        loadingLayout = findViewById(R.id.loading_layout)

        passportNumberView.setText(preferences.getString(KEY_PASSPORT_NUMBER, null))
        expirationDateView.setText(preferences.getString(KEY_EXPIRATION_DATE, null))
        birthDateView.setText(preferences.getString(KEY_BIRTH_DATE, null))

        passportNumberView.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable) {
                PreferenceManager.getDefaultSharedPreferences(this@MainActivity)
                    .edit().putString(KEY_PASSPORT_NUMBER, s.toString()).apply()
            }
        })

        expirationDateView.setOnClickListener {
            val c = loadDate(expirationDateView)
            val dialog = DatePickerDialog.newInstance(
                { _, year, monthOfYear, dayOfMonth ->
                    saveDate(
                        expirationDateView,
                        year,
                        monthOfYear,
                        dayOfMonth,
                        KEY_EXPIRATION_DATE,
                    )
                },
                c[Calendar.YEAR],
                c[Calendar.MONTH],
                c[Calendar.DAY_OF_MONTH],
            )
            dialog.showYearPickerFirst(true)
            fragmentManager.beginTransaction().add(dialog, null).commit()
        }

        birthDateView.setOnClickListener {
            val c = loadDate(birthDateView)
            val dialog = DatePickerDialog.newInstance(
                { _, year, monthOfYear, dayOfMonth ->
                    saveDate(birthDateView, year, monthOfYear, dayOfMonth, KEY_BIRTH_DATE)
                },
                c[Calendar.YEAR],
                c[Calendar.MONTH],
                c[Calendar.DAY_OF_MONTH],
            )
            dialog.showYearPickerFirst(true)
            fragmentManager.beginTransaction().add(dialog, null).commit()
        }
    }

    override fun onResume() {
        super.onResume()
        val adapter = NfcAdapter.getDefaultAdapter(this)
        if (adapter != null) {
            val intent = Intent(applicationContext, this.javaClass)
            intent.flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE)
            val filter = arrayOf(arrayOf("android.nfc.tech.IsoDep"))
            adapter.enableForegroundDispatch(this, pendingIntent, null, filter)
        }
        if (passportNumberFromIntent) {
            // When the passport number field is populated from the caller, we hide the
            // soft keyboard as otherwise it can obscure the 'Reading data' progress indicator.
            window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN)
        }
    }

    override fun onPause() {
        super.onPause()
        val adapter = NfcAdapter.getDefaultAdapter(this)
        adapter?.disableForegroundDispatch(this)
    }

    public override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            val tag: Tag? = intent.extras?.getParcelable(NfcAdapter.EXTRA_TAG)
            if (tag?.techList?.contains("android.nfc.tech.IsoDep") == true) {
                val preferences = PreferenceManager.getDefaultSharedPreferences(this)
                val passportNumber = preferences.getString(KEY_PASSPORT_NUMBER, null)
                val expirationDate = convertDate(preferences.getString(KEY_EXPIRATION_DATE, null))
                val birthDate = convertDate(preferences.getString(KEY_BIRTH_DATE, null))
                if (!passportNumber.isNullOrEmpty() && !expirationDate.isNullOrEmpty() && !birthDate.isNullOrEmpty()) {
                    val bacKey: BACKeySpec = BACKey(passportNumber, birthDate, expirationDate)
                    ReadTask(IsoDep.get(tag), bacKey).execute()
                    mainLayout.visibility = View.GONE
                    loadingLayout.visibility = View.VISIBLE
                } else {
                    Snackbar.make(passportNumberView, R.string.error_input, Snackbar.LENGTH_SHORT).show()
                }
            }
        }
    }

    @SuppressLint("StaticFieldLeak")
    private inner class ReadTask(private val isoDep: IsoDep, private val bacKey: BACKeySpec) : AsyncTask<Void?, Void?, Exception?>() {

        private lateinit var dg1File: DG1File
        private lateinit var dg2File: DG2File
        private lateinit var dg14File: DG14File
        private lateinit var sodFile: SODFile
        private var imageBase64: String? = null
        private var bitmap: Bitmap? = null
        private var chipAuthSucceeded = false
        private var passiveAuthSuccess = false
        private lateinit var dg14Encoded: ByteArray
        private var signatureBase64: String? = null

        override fun doInBackground(vararg params: Void?): Exception? {
            var cardService: CardService? = null
            var service: PassportService? = null

            try {
                // Check if task is cancelled before starting
                if (isCancelled) {
                    return MrzProcessingException(errorCode = 100, message = "Task was cancelled due to user action.")

//                    return Exception("Task was cancelled")
                }

                isoDep.timeout = 10000
                cardService = CardService.getInstance(isoDep)

                // Check connection before opening
//                if (!isoDep.isConnected) {
//                    return Exception("NFC connection lost before opening card service")
//                }

                cardService.open()
                service = PassportService(
                    cardService,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false,
                )
                service.open()

                var paceSucceeded = false

                // PACE Protocol with connection monitoring
                try {
                    if (isCancelled) return MrzProcessingException(errorCode = 200, message = "Task cancelled during PACE setup.")

                    val cardAccessFile = CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS))
                    val securityInfoCollection = cardAccessFile.securityInfos

                    for (securityInfo: SecurityInfo in securityInfoCollection) {
                        if (isCancelled) return Exception("Task cancelled during PACE iteration")

                        if (securityInfo is PACEInfo) {
                            try {
                                service.doPACE(
                                    bacKey,
                                    securityInfo.objectIdentifier,
                                    PACEInfo.toParameterSpec(securityInfo.parameterId),
                                    null,
                                )
                                paceSucceeded = true
                                break
                            } catch (e: PACEException) {
                                Log.w(TAG, "PACE failed: ${e.message}")
                                // Check if it's a connection issue
                                if (e.cause is CardServiceException &&
                                    e.cause?.message?.contains("Tag was lost") == true) {
                                    return MrzProcessingException(errorCode = 200, message = "NFC connection lost during PACE protocol.")
                                }
                                // Continue with other PACE info or fallback to BAC
                            } catch (e: CardServiceException) {
                                Log.w(TAG, "Card service error during PACE: ${e.message}")
                                if (e.message?.contains("Tag was lost") == true) {
                                    return MrzProcessingException(errorCode = 200, message = "NFC connection lost during PACE protocol.")
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "PACE setup failed: ${e.message}")
                    // Check if connection was lost
                    if (isConnectionLost(e)) {
                        return MrzProcessingException(errorCode = 200, message = "NFC connection lost during PACE setup")
                    }
                }

                // Check connection before continuing
                if (!isNfcConnected()) {
                    return MrzProcessingException(errorCode = 200, message = "NFC connection lost after PACE")
                }

                if (isCancelled) return MrzProcessingException(errorCode = 200, message = "Task cancelled before applet selection")


                try {
                    service.sendSelectApplet(paceSucceeded)
                } catch (e: CardServiceException) {
                    if (isConnectionLost(e)) {
                        return Exception("NFC connection lost during applet selection")
                    }
                    throw e
                }

                // BAC fallback if PACE failed
                if (!paceSucceeded) {
                    if (isCancelled) return Exception("Task cancelled before BAC")

                    try {
                        service.getInputStream(PassportService.EF_COM).read()
                    } catch (e: Exception) {
                        if (isConnectionLost(e)) {
                            return Exception("NFC connection lost during COM file read")
                        }

                        try {
                            service.doBAC(bacKey)
                        } catch (bacException: Exception) {
                            if (isConnectionLost(bacException)) {
                                return Exception("NFC connection lost during BAC")
                            }
                            throw bacException
                        }
                    }
                }

                // Read passport data with connection checks
                if (isCancelled) return Exception("Task cancelled before reading DG1")

                try {
                    // Read DG1 (MRZ data)
                    val dg1In = service.getInputStream(PassportService.EF_DG1)
                    dg1File = DG1File(dg1In)
                } catch (e: Exception) {
                    if (isConnectionLost(e)) {
                        return Exception("NFC connection lost while reading DG1")
                    }
                    throw e
                }

                if (isCancelled) return Exception("Task cancelled before reading DG2")

                try {
                    // Read DG2 (face image data)
                    val dg2In = service.getInputStream(PassportService.EF_DG2)
                    dg2File = DG2File(dg2In)
                } catch (e: Exception) {
                    if (isConnectionLost(e)) {
                        return Exception("NFC connection lost while reading DG2")
                    }
                    throw e
                }

                if (isCancelled) return Exception("Task cancelled before reading SOD")

                try {
                    // Read SOD (security data)
                    val sodIn = service.getInputStream(PassportService.EF_SOD)
                    sodFile = SODFile(sodIn)
                } catch (e: Exception) {
                    if (isConnectionLost(e)) {
                        return Exception("NFC connection lost while reading SOD")
                    }
                    throw e
                }

                // Read DG7 (signature) - optional
                try {
                    if (!isCancelled && isNfcConnected()) {
                        val dg7In = service.getInputStream(PassportService.EF_DG7)
                        val dg7File = DG7File(dg7In)
                        val signatureImage = extractSignatureFromDG7(dg7File)
                        if (signatureImage != null) {
                            signatureBase64 = Base64.encodeToString(signatureImage, Base64.DEFAULT)
                        }
                    }
                } catch (e: Exception) {
                    // DG7 is optional, log but continue
                    Log.w(TAG, "Failed to read DG7 (signature): ${e.message}")
                    if (isConnectionLost(e)) {
                        Log.w(TAG, "Connection lost while reading DG7, continuing without signature")
                    }
                }

                // Perform authentication
                if (!isCancelled && isNfcConnected()) {
                    try {
                        doChipAuth(service)
                    } catch (e: Exception) {
                        if (isConnectionLost(e)) {
                            Log.w(TAG, "Connection lost during chip authentication")
                        } else {
                            Log.w(TAG, "Chip authentication failed: ${e.message}")
                        }
                    }
                }

                // Passive authentication doesn't require NFC connection
                if (!isCancelled) {
                    try {
                        doPassiveAuth()
                    } catch (e: Exception) {
                        Log.w(TAG, "Passive authentication failed: ${e.message}")
                    }
                }

                // Process face image
                if (!isCancelled) {
                    try {
                        val allFaceImageInfo: MutableList<FaceImageInfo> = ArrayList()
                        dg2File.faceInfos?.forEach {
                            allFaceImageInfo.addAll(it.faceImageInfos)
                        }

                        if (allFaceImageInfo.isNotEmpty()) {
                            val faceImageInfo = allFaceImageInfo.first()
                            Log.d(TAG, "Face Image MimeType: ${faceImageInfo.mimeType}")

                            val imageLength = faceImageInfo.imageLength
                            val dataInputStream = DataInputStream(faceImageInfo.imageInputStream)
                            val buffer = ByteArray(imageLength)
                            dataInputStream.readFully(buffer, 0, imageLength)
                            val inputStream: InputStream = ByteArrayInputStream(buffer, 0, imageLength)
                            bitmap = decodeImage(faceImageInfo.mimeType, inputStream)
                            imageBase64 = Base64.encodeToString(buffer, Base64.DEFAULT)
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to process face image: ${e.message}")
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error during passport reading", e)
                return e
            } finally {
                // Clean up resources
                try {
                    service?.close()
                } catch (e: Exception) {
                    Log.w(TAG, "Error closing passport service: ${e.message}")
                }

                try {
                    cardService?.close()
                } catch (e: Exception) {
                    Log.w(TAG, "Error closing card service: ${e.message}")
                }
            }

            return null
        }

        // Helper method to check if exception indicates connection loss
        private fun isConnectionLost(exception: Throwable?): Boolean {
            return when {
                exception is CardServiceException &&
                        exception.message?.contains("Tag was lost") == true -> true
                exception is PACEException &&
                        exception.cause is CardServiceException &&
                        exception.cause?.message?.contains("Tag was lost") == true -> true
                exception?.message?.contains("Tag was lost") == true -> true
                exception?.message?.contains("connection lost") == true -> true
                exception?.message?.contains("NFC") == true &&
                        exception.message?.contains("lost") == true -> true
                else -> false
            }
        }

        // Helper method to check NFC connection status
        private fun isNfcConnected(): Boolean {
            return try {
                isoDep.isConnected
            } catch (e: Exception) {
                false
            }
        }

        // Method to cancel the reading operation
        fun cancelReading() {
            cancel(true)
        }

        // Override onCancelled to handle cleanup
        override fun onCancelled(result: Exception?) {
            super.onCancelled(result)
            Log.d(TAG, "Passport reading cancelled")
            // Perform any additional cleanup here
        }


        private fun doChipAuth(service: PassportService) {
            try {
                val dg14In = service.getInputStream(PassportService.EF_DG14)
                dg14Encoded = IOUtils.toByteArray(dg14In)
                val dg14InByte = ByteArrayInputStream(dg14Encoded)
                dg14File = DG14File(dg14InByte)
                val dg14FileSecurityInfo = dg14File.securityInfos
                for (securityInfo: SecurityInfo in dg14FileSecurityInfo) {
                    if (securityInfo is ChipAuthenticationPublicKeyInfo) {
                        service.doEACCA(
                            securityInfo.keyId,
                            ChipAuthenticationPublicKeyInfo.ID_CA_ECDH_AES_CBC_CMAC_256,
                            securityInfo.objectIdentifier,
                            securityInfo.subjectPublicKey,
                        )
                        chipAuthSucceeded = true
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, e)
            }
        }

        @OptIn(ExperimentalStdlibApi::class)
        private fun doPassiveAuth() {
            try {
                val digest = MessageDigest.getInstance(sodFile.digestAlgorithm)
                val dataHashes = sodFile.dataGroupHashes
                val dg14Hash = if (chipAuthSucceeded) digest.digest(dg14Encoded) else ByteArray(0)

                val dg1Hash = digest.digest(dg1File.encoded)
                val dg2Hash = digest.digest(dg2File.encoded)

                Log.d(TAG, "Computed DG1 Hash: ${dg1Hash.toHexString()}")
                Log.d(TAG, "Stored DG1 Hash: ${dataHashes[1]?.toHexString()}")
                Log.d(TAG, "Computed DG2 Hash: ${dg2Hash.toHexString()}")
                Log.d(TAG, "Stored DG2 Hash: ${dataHashes[2]?.toHexString()}")
                if (chipAuthSucceeded) {
                    Log.d(TAG, "Computed DG14 Hash: ${dg14Hash.toHexString()}")
                    Log.d(TAG, "Stored DG14 Hash: ${dataHashes[14]?.toHexString()}")
                }



                if (Arrays.equals(dg1Hash, dataHashes[1]) && Arrays.equals(dg2Hash, dataHashes[2])
                    && (!chipAuthSucceeded || Arrays.equals(dg14Hash, dataHashes[14]))) {

                    val asn1InputStream = ASN1InputStream(assets.open("masterList"))
                    val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
                    keystore.load(null, null)
                    val cf = CertificateFactory.getInstance("X.509")

                    var p: ASN1Primitive?
                    while (asn1InputStream.readObject().also { p = it } != null) {
                        val asn1 = ASN1Sequence.getInstance(p)
                        if (asn1 == null || asn1.size() == 0) {
                            throw IllegalArgumentException("Null or empty sequence passed.")
                        }
                        if (asn1.size() != 2) {
                            throw IllegalArgumentException("Incorrect sequence size: " + asn1.size())
                        }
                        val certSet = ASN1Set.getInstance(asn1.getObjectAt(1))
                        for (i in 0 until certSet.size()) {
                            val certificate = Certificate.getInstance(certSet.getObjectAt(i))
                            val pemCertificate = certificate.encoded
                            val javaCertificate = cf.generateCertificate(ByteArrayInputStream(pemCertificate))
                            keystore.setCertificateEntry(i.toString(), javaCertificate)
                        }
                    }

                    val docSigningCertificates = sodFile.docSigningCertificates
                    for (docSigningCertificate: X509Certificate in docSigningCertificates) {
                        docSigningCertificate.checkValidity()
                    }

                    val cp = cf.generateCertPath(docSigningCertificates)
                    val pkixParameters = PKIXParameters(keystore)
                    pkixParameters.isRevocationEnabled = false
                    val cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType())
                    cpv.validate(cp, pkixParameters)
                    var sodDigestEncryptionAlgorithm = sodFile.docSigningCertificate.sigAlgName
                    var isSSA = false
                    if ((sodDigestEncryptionAlgorithm == "SSAwithRSA/PSS")) {
                        sodDigestEncryptionAlgorithm = "SHA256withRSA/PSS"
                        isSSA = true
                    }
                    val sign = Signature.getInstance(sodDigestEncryptionAlgorithm)
                    if (isSSA) {
                        sign.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
                    }
                    sign.initVerify(sodFile.docSigningCertificate)
                    sign.update(sodFile.eContent)
                    passiveAuthSuccess = sign.verify(sodFile.encryptedDigest)
                }
            } catch (e: Exception) {
                Log.w(TAG, e)
            }
        }

        override fun onPostExecute(result: Exception?) {
            mainLayout.visibility = View.VISIBLE
            loadingLayout.visibility = View.GONE
            if (result == null) {
                val intent = if (callingActivity != null) {
                    Intent()
                } else {
                    Intent(this@MainActivity, ResultActivity::class.java)
                }
                val mrzInfo = dg1File.mrzInfo
                intent.putExtra(ResultActivity.KEY_FIRST_NAME, mrzInfo.secondaryIdentifier.replace("<", " "))
                intent.putExtra(ResultActivity.KEY_LAST_NAME, mrzInfo.primaryIdentifier.replace("<", " "))
                intent.putExtra(ResultActivity.KEY_GENDER, mrzInfo.gender.toString())
                intent.putExtra(ResultActivity.KEY_STATE, mrzInfo.issuingState)
                intent.putExtra(ResultActivity.KEY_NATIONALITY, mrzInfo.nationality)
                val passiveAuthStr = if (passiveAuthSuccess) {
                    getString(R.string.pass)
                } else {
                    getString(R.string.failed)
                }


                val chipAuthStr = if (chipAuthSucceeded) {
                    getString(R.string.pass)
                } else {
                    getString(R.string.failed)
                }
                intent.putExtra(ResultActivity.KEY_PASSIVE_AUTH, passiveAuthStr)
                intent.putExtra(ResultActivity.KEY_CHIP_AUTH, chipAuthStr)
                bitmap?.let { bitmap ->
                    if (encodePhotoToBase64) {
                        Log.d("Photooo", encodePhotoToBase64.toString())
                        intent.putExtra(ResultActivity.KEY_PHOTO_BASE64, imageBase64)
                    } else {
                        Log.d("Photooo1", encodePhotoToBase64.toString())
                        val ratio = 320.0 / bitmap.height
                        val targetHeight = (bitmap.height * ratio).toInt()
                        val targetWidth = (bitmap.width * ratio).toInt()
                        intent.putExtra(
                            ResultActivity.KEY_PHOTO,
                            Bitmap.createScaledBitmap(bitmap, targetWidth, targetHeight, false)
                        )
                    }
                }

                signatureBase64?.let { signature ->
                    intent.putExtra(ResultActivity.KEY_CARD_SIGNATURE, signature)
                }




                if (callingActivity != null) {
                    setResult(RESULT_OK, intent)
                    finish()
                } else {
                    startActivity(intent)
                }
            } else {
                Snackbar.make(passportNumberView, result.message.toString(), Snackbar.LENGTH_LONG).show()
            }
        }
    }


    private fun extractSignatureFromDG7(dg7File: DG7File): ByteArray? {
        return try {
            // DG7 contains displayed data - this might include signature
            val imageInfos = dg7File.images
            if (imageInfos.isNotEmpty()) {
                val signatureInfo = imageInfos.first() // Assuming first image is signature
                val imageLength = signatureInfo.imageLength
                val dataInputStream = DataInputStream(signatureInfo.imageInputStream)
                val buffer = ByteArray(imageLength)
                dataInputStream.readFully(buffer, 0, imageLength)
                buffer
            } else null
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting signature from DG7", e)
            null
        }
    }


    private fun convertDate(input: String?): String? {
        if (input == null) {
            return null
        }
        return try {
            SimpleDateFormat("yyMMdd", Locale.US).format(SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(input)!!)
        } catch (e: ParseException) {
            Log.w(MainActivity::class.java.simpleName, e)
            null
        }
    }

    private fun loadDate(editText: EditText): Calendar {
        val calendar = Calendar.getInstance()
        if (editText.text.isNotEmpty()) {
            try {
                calendar.timeInMillis = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(editText.text.toString())!!.time
            } catch (e: ParseException) {
                Log.w(MainActivity::class.java.simpleName, e)
            }
        }
        return calendar
    }

    private fun saveDate(editText: EditText, year: Int, monthOfYear: Int, dayOfMonth: Int, preferenceKey: String) {
        val value = String.format(Locale.US, "%d-%02d-%02d", year, monthOfYear + 1, dayOfMonth)
        PreferenceManager.getDefaultSharedPreferences(this)
            .edit().putString(preferenceKey, value).apply()
        editText.setText(value)
    }


    companion object {
//        private val TAG = MainActivity::class.java.simpleName
        private val TAG = "MaishaCard Reader"
        private const val KEY_PASSPORT_NUMBER = "passportNumber"
        private const val KEY_EXPIRATION_DATE = "expirationDate"
        private const val KEY_BIRTH_DATE = "birthDate"
    }
}


class MrzProcessingException(
    val errorCode: Int,
    message: String
) : Exception(message)
