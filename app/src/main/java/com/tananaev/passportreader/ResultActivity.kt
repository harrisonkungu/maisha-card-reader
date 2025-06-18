/*
 * Copyright 2016 - 2022 Anton Tananaev (anton.tananaev@gmail.com)
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
package com.tananaev.passportreader

import android.graphics.BitmapFactory
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class ResultActivity : AppCompatActivity() {
    private lateinit var signatureImageView: ImageView


    override fun onCreate(savedInstanceState: Bundle?) {


        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_result)
        findViewById<TextView>(R.id.output_first_name).text = intent.getStringExtra(KEY_FIRST_NAME)
        findViewById<TextView>(R.id.output_last_name).text = intent.getStringExtra(KEY_LAST_NAME)
        findViewById<TextView>(R.id.output_gender).text = intent.getStringExtra(KEY_GENDER)
        findViewById<TextView>(R.id.output_state).text = intent.getStringExtra(KEY_STATE)
        findViewById<TextView>(R.id.output_nationality).text = intent.getStringExtra(KEY_NATIONALITY)
        findViewById<TextView>(R.id.output_passive_auth).text = intent.getStringExtra(KEY_PASSIVE_AUTH)
        findViewById<TextView>(R.id.output_chip_auth).text = intent.getStringExtra(KEY_CHIP_AUTH)
        if (intent.hasExtra(KEY_PHOTO)) {
            @Suppress("DEPRECATION")
            findViewById<ImageView>(R.id.view_photo).setImageBitmap(intent.getParcelableExtra(KEY_PHOTO))
        }
        if (intent.hasExtra(KEY_CARD_SIGNATURE)) {
            @Suppress("DEPRECATION")
            findViewById<ImageView>(R.id.signature_view_photo).setImageBitmap(intent.getParcelableExtra(KEY_CARD_SIGNATURE))
        }






        signatureImageView = findViewById(R.id.signature_view_photo)

        // Get signature data from intent
        val signatureBase64 = intent.getStringExtra(KEY_CARD_SIGNATURE)

        if (signatureBase64 != null) {
            displaySignature(signatureBase64)
        } else {
            // Hide signature view or show placeholder
            signatureImageView.visibility = View.GONE
            // Or show "No signature available" message
        }





    }

    private fun displaySignature(signatureBase64: String) {
        try {
            val signatureBytes = Base64.decode(signatureBase64, Base64.DEFAULT)
            val signatureBitmap = BitmapFactory.decodeByteArray(signatureBytes, 0, signatureBytes.size)

            if (signatureBitmap != null) {
                signatureImageView.setImageBitmap(signatureBitmap)
                signatureImageView.visibility = View.VISIBLE
            } else {
                // Handle case where signature couldn't be decoded
                signatureImageView.visibility = View.GONE
                Log.e("ResultActivity", "Failed to decode signature bitmap")
            }
        } catch (e: Exception) {
            Log.e("ResultActivity", "Error displaying signature", e)
            signatureImageView.visibility = View.GONE
        }
    }


    companion object {
        const val KEY_FIRST_NAME = "firstName"
        const val KEY_LAST_NAME = "lastName"
        const val KEY_GENDER = "gender"
        const val KEY_STATE = "state"
        const val KEY_NATIONALITY = "nationality"
        const val KEY_PHOTO = "photo"
        const val KEY_PHOTO_BASE64 = "photoBase64"
        const val KEY_PASSIVE_AUTH = "passiveAuth"
        const val KEY_CHIP_AUTH = "chipAuth"
        const val KEY_CARD_SIGNATURE = "cardSignature"
    }
}
