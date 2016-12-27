package main.set_1

/**
  * Created by Adrian Bravo on 12/21/16.
  */
object challenge2 extends App {

  /*
   * Takes a hex string and returns a ByteArray
   */
  def hex2ba(hex_str: String): Array[Byte] = {
    val hex_ba: Array[Byte] = hex_str.sliding(2, 2).map(
      (hex_pair: String) => Integer.decode("0x" + hex_pair).byteValue()
    ).toArray
    hex_ba
  }

  /*
   * Takes a ByteArray and returns a Hex string
   */
  def ba2hex(arr: Array[Byte]): String = {
    arr.foldLeft("") { (z, e: Byte) => z + "%02x".format(e) }
  }

  /*
   * Takes two byte arrays of the same size and returns
   * the XOR of both byte arrays formatted as a byte array
   */
  def xor_ba(ba1: Array[Byte], ba2: Array[Byte]): Array[Byte] = {
    if (ba1.length != ba2.length) {
      println(ba1.length)
      println(ba2.length)
      throw new RuntimeException("Can't xor two byte arrays of different lengths: |" + new String(ba1) + "|, |" + new String(ba2)+"|")
    }
    for {
      (i: Byte, j: Byte) <- ba1.zip(ba2)
    } yield (i ^ j).toByte
  }

  /*
   * Takes two hex strings of the same size and returns
   * the XOR of both strings formatted as a hex string
   */
  def xor(hex1: String, hex2: String): String = {
    ba2hex(xor_ba(hex2ba(hex1), hex2ba(hex2)))
  }

  val s1 = "1c0111001f010100061a024b53535009181c"
  val s2 = "686974207468652062756c6c277320657965"
  val expected = "746865206b696420646f6e277420706c6179"
  val xored = xor(s1, s2)
  println(xored)
  println(xored == expected)
}
