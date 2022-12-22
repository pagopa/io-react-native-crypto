package com.pagopa.ioreactnativecrypto

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import com.facebook.react.bridge.PromiseImpl
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.WritableNativeMap
import com.facebook.soloader.SoLoader
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class IoReactNativeCryptoModuleTest {
  private lateinit var instrumentationContext: Context
  private lateinit var cryptoModule: IoReactNativeCryptoModule
  @Before
  fun setup() {
    instrumentationContext = InstrumentationRegistry.getInstrumentation().context
    cryptoModule = IoReactNativeCryptoModule(
      reactContext = ReactApplicationContext(instrumentationContext)
    )
    SoLoader.init(instrumentationContext, false)
  }

  @Test fun nameEqualToIoReactNativeCrypto() {
    val moduleName = cryptoModule.name
    assertEquals(moduleName, "IoReactNativeCrypto")
  }

  @Test fun deleteKeyTest() {
    val lock = CountDownLatch(1)
    var promiseResolved = false
    cryptoModule.deletePublicKey(
      keyTag = "keyTag",
      PromiseImpl(
        // Resolve callback
        {
          assertTrue(
            "Key successfully deleted!",
            it.first() == true
          )
          promiseResolved = true
        },
        // Reject callback
        {
          fail("Key deletion rejected ${it.joinToString()}")
        }
      )
    )
    lock.await(3, TimeUnit.SECONDS)
    assertTrue(promiseResolved)
  }

  @Test fun generateTest() {
    val lock = CountDownLatch(1)
    var promiseRejected = false
    var promiseResolved = false
    cryptoModule.generate(
      keyTag = "keyTag",
      PromiseImpl(
        // Resolve callback
        {
          // On emulator we never enter here
          (it.first() as? WritableNativeMap)?.let {
            val kty = it.getString("kty")
            val expectedKeyTypeMatch = kty.equals("EC") || kty.equals("RSA")
            assertTrue(expectedKeyTypeMatch)
          }
          promiseResolved = true
        },
        // Reject callback
        {
          (it.first() as? WritableNativeMap)?.let {
            val exceptionMessage = it.getString("message")
            assertEquals(exceptionMessage, "UNKNOWN_EXCEPTION")
          }
          promiseRejected = true
        }
      )
    )
    lock.await(10, TimeUnit.SECONDS)
    assertTrue(promiseRejected)
    assertFalse(promiseResolved)
  }
}
