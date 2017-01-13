package main.set_3

import java.security.SecureRandom
import java.util.{Base64, Random}
import javax.crypto.{BadPaddingException, SecretKey}

import main.set_1.challenge2
import main.set_2.{challenge10, challenge12, challenge15}

import scala.collection.mutable.ArrayBuffer

/**
  * Created by Adrian Bravo on 12/31/16.
  */
object challenge17 extends App {
  val STRINGS = List(
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
  )
  val key: SecretKey = challenge12.rand_key()

  def random_string: String = {
    val prng: Random = new java.util.Random()
    STRINGS(prng.nextInt(STRINGS.length))
  }

  def rand_bytes(size: Int): Array[Byte] = {
    val ba: Array[Byte] = new Array[Byte](size)
    val prng: SecureRandom = new SecureRandom()
    prng.nextBytes(ba)
    ba
  }

  def rand_iv: Array[Byte] = {
    rand_bytes(challenge10.BLOCK_SIZE)
  }

  def oracle_encrypt(key: SecretKey)(): Array[Byte] = {
    val iv: Array[Byte] = rand_iv
    val plaintext: Array[Byte] = Base64.getDecoder.decode(random_string)
    challenge10.cbc_encrypt(key, plaintext, iv)
  }

  def oracle_decrypt(key: SecretKey)(ciphertext: Array[Byte]): Boolean = {
    try {
      val pt: Array[Byte] = challenge10.cbc_decrypt(key, ciphertext)
      // println("Debug: PT = " + new String(plaintext))
      true
    } catch {
      case bp: BadPaddingException => false
    }
  }

  // Note this is a bit nasty because we take a by ref param 'intermediate' and modify it inside
  def find_char(oracle: Array[Byte] => Boolean, exp_pad: Byte, intermediate: Array[Byte],
                prev_block: Vector[Byte], target_block: Vector[Byte]): Option[Char] = {

    val pos: Int = challenge10.BLOCK_SIZE - exp_pad
    // Some smarts; printable ASCII chars are more likely so try those first
    val guesses: Vector[Byte] = ((32 to 127) ++ (0 to 31) ++ (128 to 255)).toVector.map(_.toByte)
    // iterate through the guesses in the position we're trying to solve
    def inner_fc(guess_idx: Int): Option[Char] = {
      if (guess_idx > 255) return None
      val guess = guesses(guess_idx)
      intermediate.update(pos, guess.toByte)
      // println(s"Update I($pos) = ${guess} | ${intermediate.toList} | P = $exp_pad | PB($pos) = ${prev_block(pos)}")
      // Generate a guess block composed of 0s followed by the discovered intermediate stated xored
      // with the expected padding for this iteration
      val guess_block: Array[Byte] = intermediate.take(pos + 1) ++
        challenge2.xor_ba(intermediate.takeRight(exp_pad - 1), Array.fill[Byte](exp_pad - 1)(exp_pad))

      if (oracle(guess_block ++ target_block)) {
        intermediate.update(pos, (guess ^ exp_pad).toByte)
        Some((guess ^ prev_block(pos) ^ exp_pad).toChar)
      } else inner_fc(guess_idx + 1)
    }

    inner_fc(0)
  }

  def attack_oracle(oracle: Array[Byte] => Boolean, ct: Array[Byte]): String = {
    // split ciphertext in chunks of size block size
    val ct_iv_chunks: Vector[Vector[Byte]] = ct.toVector.grouped(challenge10.BLOCK_SIZE).toVector
    // Retrieve the IV from the ciphertext (first 16 bytes, first element of the list)
    val (iv: Vector[Vector[Byte]], blocks: Vector[Vector[Byte]]) = ct_iv_chunks.splitAt(1)
    // To store the intermediate state of the CBC decryption for each block
    var intermediate: Array[Byte] = Array.fill[Byte](challenge10.BLOCK_SIZE)(0)
    // The discovered plaintext
    val plaintext: ArrayBuffer[Char] = new ArrayBuffer[Char]()
    var prev_block = iv.head

    blocks foreach { block =>
      (1 to challenge10.BLOCK_SIZE) foreach { exp_pad: Int =>
        val found: Char = find_char(oracle, exp_pad.toByte, intermediate, prev_block, block).getOrElse('?')
        plaintext += found
        // println("Found: " + found.toByte)
      }
      prev_block = block
      intermediate = Array.fill[Byte](challenge10.BLOCK_SIZE)(0)
    }
    val sorted_pt: Vector[Char] = plaintext.grouped(challenge10.BLOCK_SIZE).flatMap(_.reverse).toVector
    // remove the padding to avoid things like backspace codes and similar from breaking our string on display
    challenge15.validatePKCS7(sorted_pt.map(_.toByte).toArray).map(_.toChar).mkString
  }

  // 
  val ct: Array[Byte] = oracle_encrypt(key)()

  println("Decrypted Result = " + attack_oracle(oracle_decrypt(key), ct))
  // println(sorted_pt.toList)
}
