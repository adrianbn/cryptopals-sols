package main.set_1

import java.util.Base64

/**
  * Created by Adrian Bravo on 12/21/16.
  */
object challenge1 extends App {
  def hex2b64(hex_str: String) = {
    val hex_ba: Array[Byte] = hex_str.sliding(2, 2).map(
      (hex_pair: String) => Integer.decode("0x" + hex_pair).byteValue()
    ).toArray
    Base64.getEncoder.encodeToString(hex_ba)
  }

  val hexstr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
  val expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

  val out = challenge1.hex2b64(hexstr)
  println(out)
  println(out == expected)
}
