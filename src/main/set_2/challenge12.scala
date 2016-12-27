package main.set_2

import java.util.{Base64, Random}
import javax.crypto.{KeyGenerator, SecretKey}

import scala.annotation.tailrec
import scala.collection.mutable.ArrayBuffer

/**
  * Created by Adrian Bravo on 12/26/16.
  */
object challenge12 extends App {

  val key: SecretKey = rand_key()
  val b64_suffix = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

  /*
  * Generates a random AES SecretKey of the specified key size
  */
  def rand_key(key_size: Int = 128): SecretKey = {
    val key_gen: KeyGenerator = KeyGenerator.getInstance("AES")
    key_gen.init(key_size)
    key_gen.generateKey()
  }

  /*
   * Generates a random number between low and high (both included)
   */
  def rnd_num_bytes(low: Int, high: Int): Int = {
    val rng: Random = new Random()
    rng.nextInt(high - low + 1) + low
  }

  def encryption_oracle()(plaintext: Array[Byte]): Array[Byte] = {
    val suffix: Array[Byte] = Base64.getDecoder.decode(b64_suffix)
    val pt: Array[Byte] = plaintext ++ suffix
    val padded_pt: Array[Byte] = challenge9.pkcs7(pt, challenge10.BLOCK_SIZE)
    challenge10.ecb_encrypt(key.getEncoded, padded_pt)
  }

  // Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
  // then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.

  // Finds the cipher block size and the size of the secret string appended to the plaintext
  def find_block_secret_length(enc_func: (Array[Byte] => Array[Byte])): (Int, Int) = {
    val orig_length: Int = enc_func("".getBytes("UTF-8")).length // The length of encrypting the secret suffix only
    @tailrec
    def inner_fbl(input_len: Int): (Int, Int) = {
      if (input_len >= 40) return (-1, -1) // didn't find the block length
      val pt: String = "A" * input_len
      val ct_len: Int = enc_func(pt.getBytes("UTF-8")).length
      if (ct_len > orig_length) {
        val bsize: Int = ct_len - orig_length
        //((ct_len / (ct_len - orig_length)) - 1) * (ct_len - orig_length) - input_len
        val secret_size: Int = orig_length - input_len
        (bsize, secret_size)
      } else inner_fbl(input_len + 1)
    }
    inner_fbl(0)
  }

  val (bsize, secret_size) = find_block_secret_length(encryption_oracle())
  println("[+] Block size: " + bsize)
  println("[+] Secret size: " + secret_size)
  // Detect that the function is using ECB. You already know, but do this step anyways.
  val is_ecb: Boolean = challenge11.detect_ecb(encryption_oracle())
  println("[+] ECB encryption?: " + is_ecb)
  // The length of the plaintext to submit in order to recover the whole secret
  val input_blocks: Int = math.ceil(secret_size.toDouble / bsize).toInt
  println("[+] Need to send " + input_blocks + " input blocks")
  val input_size: Int = input_blocks * bsize
  println("[+] Input size is " + input_size)

  def attack_ecb(enc_func: (Array[Byte] => Array[Byte]), secret_size: Int, input_size: Int, bsize: Int, input_blocks: Int): ArrayBuffer[Byte] = {
    var found: ArrayBuffer[Byte] = new ArrayBuffer[Byte]()
    0 until secret_size foreach { i =>
      val payload: Array[Byte] = ("A" * (input_size - (i + 1))).getBytes("UTF-8")

      // Generate all block guesses formed from iterating the last byte prepended by what we've found
      // so far or the initial filler
      val guess_dict: List[List[Byte]] = (0 to 255 map { e =>
        val guess = payload.take(bsize - found.length - 1) ++ found.takeRight(bsize - 1) :+ e.toByte
        enc_func(guess).take(bsize).toList
      }).toList
      // Encrypt the payload
      val encrypted = enc_func(payload)
      // Slice out the target block
      val sliced: List[Byte] = encrypted.slice((input_blocks - 1) * bsize, input_blocks * bsize).toList

      // Match against our guess dict
      val byte_found: Byte = guess_dict.indexOf(sliced).toByte
      found += byte_found
      // println("Found byte: " + byte_found + " (" + byte_found.toChar + ")")
    }
    found
  }

  println("[+] Decrypted output: ")
  println(new String(attack_ecb(encryption_oracle(), secret_size, input_size, bsize, input_blocks).toArray[Byte]))


  /*
   * Challenge 14th is a generalization of this challenge. The methods there work for this case as well as for cases
   * with a random secret prefix. The code below shows how to call the methods of challenge 14th to solve this
   * challenge (12).
   */
  def bo()(enc_func: (Array[Byte] => Array[Byte])): Option[(Int, Int, Int)] ={
    val (bsize, secret_size) = find_block_secret_length(enc_func)
    Some(bsize, secret_size, 0)
  }
  println(new String(challenge14.attack_ecb(encryption_oracle(), bo()).toArray[Byte]))
}
