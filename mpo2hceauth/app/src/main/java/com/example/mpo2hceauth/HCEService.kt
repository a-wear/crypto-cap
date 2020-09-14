package com.example.mpo2hceauth


import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import com.example.mpo2hceauth.APDU.UserWBB


class HCEService : HostApduService() {

    private val LOG_TAG = "LOG_HCE"
    private var user = User()
    private var userWBB = UserWBB()



    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {


        var response: ByteArray? = null

        var data: ByteArray? = null
        val apdu = APDU(commandApdu);

        // APDU command select application
        if (apdu.cla === 0x00.toByte()) {

            return rCodeAPDU.PROCESS_SUCESS         // successful process

        }

        // APDU command select application
        return if (apdu.cla === 0x80.toByte()) {
            val bytes = when (apdu.ins) {

                //---------------------------------------------------------------------------//
                //---------------      AUTHENTICATION PROTOCOL 1 (AES-GCM)  -----------------//
                //---------------------------------------------------------------------------//
                0x00.toByte() -> {

                    user.init(commandApdu)
                    Log.i(LOG_TAG, "comm 0x00 done")
                    return rCodeAPDU.PROCESS_SUCESS
                    //data = user.message2(commandApdu);
                    //
                    //apdu.responseAPDU(data)
                }

                // APDU command Authentication phase 1
                // generate ESDH parameters, compute shared key between HCE an SAM, initialization of AES encryption algorithm
                // return ECDH public key of HCE
                0x01.toByte() -> {

                    data = user.message1()
                    //  data = user.message2(ID_vi, vnonce);
                    Log.i(LOG_TAG, "comm 0x01 done")
                    return apdu.responseAPDU(data)
                }

                // APDU command Authentication phase 3
                // compute proof from IMA reader request
                // return byte array:  proof || IDdevice (encrypted)
                0x02.toByte() -> {

                    data = user.message2(commandApdu)
                    //  data = user.message2(ID_vi, vnonce);
                    Log.i(LOG_TAG, "comm 0x01 done")
                    return apdu.responseAPDU(data)

                    //Log.i(LOG_TAG, Util.bytesToHex(apdu.data))
                    //   data = auth.comptDataAut3(apdu.data)
                    //Log.i(LOG_TAG, Util.bytesToHex(apdu.responseAPDU(data)))

                    // return apdu.responseAPDU(data)
                }
                0x03.toByte() -> {


                    var res = user.message3(commandApdu)
                    //  data = user.message2(ID_vi, vnonce);
                    Log.i(LOG_TAG, "comm 0x01 done")

                    if(res==1)
                        return rCodeAPDU.AUTHENTICATION_OK
                    else
                        return rCodeAPDU.AUTHENTICATION_FAILD

                    //Log.i(LOG_TAG, Util.bytesToHex(apdu.data))
                    //   data = auth.comptDataAut3(apdu.data)
                    //Log.i(LOG_TAG, Util.bytesToHex(apdu.responseAPDU(data)))

                    // return apdu.responseAPDU(data)



                }

                //---------------------------------------------------------------------------//
                //---------------      AUTHENTICATION PROTOCOL 2 (wBB)  -----------------//
                //---------------------------------------------------------------------------//
                0x10.toByte() -> {

                    userWBB.init(commandApdu)
                    Log.i(LOG_TAG, "comm 0x10 done")
                    return rCodeAPDU.PROCESS_SUCESS
                    //data = user.message2(commandApdu);
                    //
                    //apdu.responseAPDU(data)
                }

                0x20.toByte() -> {

                    data = userWBB.message1(commandApdu)
                    Log.i(LOG_TAG, "comm 0x20 done")

                    return apdu.responseAPDU(data)
                    //data = user.message2(commandApdu);
                    //
                    //apdu.responseAPDU(data)
                }



                else -> rCodeAPDU.WRONG_INSTANCE
            }
            bytes

        } else
            rCodeAPDU.WRONG_CLASS                  // class is not supported


    }

    override fun onDeactivated(reason: Int) {

    }



    private fun forwardTheResult(success: Boolean) {
        startActivity(
            Intent(this, MainActivity::class.java)
                .apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    putExtra("success", true)
                }
        )
    }
}


