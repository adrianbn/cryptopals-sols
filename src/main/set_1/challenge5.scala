package main.set_1

import java.util.Base64

/**
  * Created by Adrian Bravo on 12/22/16.
  */
object challenge5 extends App {
  def expand_key(key: String, length: Int): Array[Byte] = {
    (key * ((length / key.length) + 1)).take(length).getBytes("UTF-8")
  }

  def xor_repeated_key(key: String, ciphertext: Array[Byte]): Array[Byte] = {
    val keystream: Array[Byte] = expand_key(key, ciphertext.length)
    challenge2.xor_ba(ciphertext, keystream)
  }

  val key = "ICE"
  val msg1: String = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"

  val ct1: Array[Byte] = xor_repeated_key(key, msg1.getBytes("UTF-8"))
  val ct1_hex: String = challenge2.ba2hex(ct1)
  println(ct1_hex)
  val expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
  println(ct1_hex == expected)

}
