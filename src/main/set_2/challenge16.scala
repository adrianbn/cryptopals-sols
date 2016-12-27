package main.set_2

import java.security.SecureRandom

/**
  * Created by Adrian Bravo on 12/27/16.
  */
object challenge16 extends App {
  val key = challenge11.rand_key()

  def escape(str: String): String = {
    str.replaceAll(";", "").replaceAll("=", "")
  }

  def preppend_and_append(str: String): String = {
    "comment1=cooking%20MCs;userdata=" + escape(str) + ";comment2=%20like%20a%20pound%20of%20bacon"
  }

  /*
   * Takes the input, removes ; and =, appends and prepends a constant string, and then encrypts it
   * with a random key and iv
  */
  def process_and_encrypt(input: String): Array[Byte] = {
    val plaintext = preppend_and_append(input)
    val iv: Array[Byte] = new Array[Byte](challenge10.BLOCK_SIZE)
    val prng: SecureRandom = new SecureRandom()
    prng.nextBytes(iv)
    challenge10.cbc_encrypt(key, plaintext.getBytes("UTF-8"), iv)
  }

  /*
   * Transforms a string of the form key1=value1;key2=value2 into a dictionary
   * { key1: value1, key2: value2 }
   */
  def to_map(input: String): Map[String, String] = {
    val pairs: Array[String] = input.split(";") // [foo=bar, baz=qux, zap=zazzle]
    pairs.foldLeft(Map.empty[String, String]) { (acc: Map[String, String], pair: String) =>
      acc ++ pair.split("=").grouped(2).map {
        case Array(k, v) => k -> v
        case Array(k) => k -> ""
      }.toMap
    }
  }

  /*
   * Decrypts the ciphertext, converts it to a dictionary and returns true if the dict contains
   * a tuple admin: true
   */
  def decrypt_and_process(ciphertext: Array[Byte]): Boolean = {
    val plaintext: Array[Byte] = challenge10.cbc_decrypt(key, ciphertext)
    println("Decrypted: " + new String(plaintext))
    val dict: Map[String, String] = to_map(new String(plaintext))
    dict.exists(_ == "admin" -> "true")
  }

  /*
   * Perform bit flipping attack
   */
  // Encrypt the initial payload. Make it similar to what we're after to minimize the amount of flipping
  // : is one flip away from ; and < from =
  val payload: String = ":admin<true"
  val enc_payload: Array[Byte] = process_and_encrypt(payload)
  // Notice that comment1=cooking%20MCs;userdata= ends at exactly the three block boundary. We have to
  // attack the third block to affect the fourth one (Note that the first CT block is the IV)
  val blocks: List[Array[Byte]] = enc_payload.sliding(challenge10.BLOCK_SIZE, challenge10.BLOCK_SIZE).toList
  val second_block: Array[Byte] = blocks(2)
  // Need to attack the first and seventh bytes of the block
  List(0, 6) foreach { pos =>
    second_block.update(pos, (second_block(pos) ^ 0x01).toByte)
  }
  // Replace the original block with our modified version
  blocks.updated(2, second_block)
  // Decrypt and succeed
  println(decrypt_and_process(blocks.toArray.flatten))

  // A test that should return false
  val test = "Hello darling;admin=true"
  println(decrypt_and_process(process_and_encrypt(test)))
}
