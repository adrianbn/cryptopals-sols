package main.set_2

import java.util.Base64
import javax.crypto.{KeyGenerator, SecretKey}

import scala.annotation.tailrec
import scala.collection.mutable.ArrayBuffer

/**
  * Created by Adrian Bravo on 12/26/16.
  */
object challenge14 extends App {
  val MAX_RNG_BYTES = 60 // Upper limit to the prepended random string

  val key: SecretKey = rand_key()
  val b64_suffix = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
  //println("Debug: Suffix size = " + Base64.getDecoder.decode(b64_suffix).length)
  // The random byte array is generated only once, it doesn't change with each invocation of the oracle
  val rnd_prefix: Array[Byte] = rnd_byte_array()
  //println("Debug: Prefix size = " + rnd_prefix.length)

  /*
  * Generates a random AES SecretKey of the specified key size
  */
  def rand_key(key_size: Int = 128): SecretKey = {
    val key_gen: KeyGenerator = KeyGenerator.getInstance("AES")
    key_gen.init(key_size)
    key_gen.generateKey()
  }

  /*
    Generates a byte array of the given size with random contents
   */
  def rnd_byte_array(size: Int = MAX_RNG_BYTES): Array[Byte] = {
    val rng = new java.util.Random()
    val num_rnd_bytes = rng.nextInt(size) + 1 // we don't want to allow 0
    val rnd_bytes: Array[Byte] = Array.fill[Byte](num_rnd_bytes)(0) // Array of len num_rnd_bytes init with 0
    rng.nextBytes(rnd_bytes) // generates random bytes and places them inside rnd_bytes
    rnd_bytes
  }

  /*
   *  AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
   */
  def encryption_oracle()(prefix: Array[Byte])(plaintext: Array[Byte]): Array[Byte] = {
    val suffix: Array[Byte] = Base64.getDecoder.decode(b64_suffix)
    val pt: Array[Byte] = prefix ++ plaintext ++ suffix
    val padded_pt: Array[Byte] = challenge9.pkcs7(pt, challenge10.BLOCK_SIZE)
    challenge10.ecb_encrypt(key.getEncoded, padded_pt)
  }

  // Finds the cipher block size and the size of the secret string appended to the plaintext
  def find_block_suffix_prefix_length()(enc_func: (Array[Byte] => Array[Byte])): Option[(Int, Int, Int)] = {
    val orig_length: Int = enc_func("".getBytes("UTF-8")).length // The length of encrypting the random prefix + secret suffix only
    //println("Debug: Enc(prefix, suffix).length = " + orig_length)
    @tailrec
    def inner_fbl(input_len: Int): Option[(Int, Int, Int)] = {
      if (input_len >= 40) return None // didn't find the block length
      val pt: String = "A" * input_len
      val ct_len: Int = enc_func(pt.getBytes("UTF-8")).length
      if (ct_len > orig_length) {
        // Block size
        val bsize: Int = ct_len - orig_length
        // prefix + suffix size
        val secret_size: Int = orig_length - input_len
        val prefix_size = find_prefix_length(enc_func, bsize).getOrElse(0)
        val suffix_size = secret_size - prefix_size
        Some(bsize, suffix_size, prefix_size)
      } else inner_fbl(input_len + 1)
    }
    inner_fbl(0)
  }

  def find_prefix_length(enc_func: (Array[Byte] => Array[Byte]), bsize: Int): Option[Int] = {
    @tailrec
    def inner_fpl(filler_len: Int): Option[Int] = {
      if (filler_len > bsize) return None // didn't find the number of bytes needed. No prefix?
      // Generate two blocks of As + whatever is needed to complete current block. At some point
      // this will result in two identical ciphertext blocks
      val pad: Array[Byte] = ("A" * (3 * bsize + filler_len)).getBytes("UTF-8")
      // Get the ciphertext in chunks of bsize
      val ct_chunks: List[Array[Byte]] = enc_func(pad).sliding(bsize, bsize).toList
      // Calculate number of repeated chunks so far
      val repetitions: Map[List[Byte], Int] = ct_chunks.map(_.toList).groupBy(identity).mapValues(_.size)
      // If two equal blocks exist already
      repetitions.find(e => e._2 >= 3) match {
        case Some(reps) => {
          // How many chars we had to add to complete the existing blocks (and start a new one)
          val input_to_new_block = bsize - filler_len
          // Position of the first repeated block
          val pos_first_a_block: Int = ct_chunks.map(_.toList).indexOf(reps._1)
          val prefix_size = bsize * (pos_first_a_block - 1) + input_to_new_block
          Some(prefix_size)
        }
        case None => inner_fpl(filler_len + 1)
      }
    }
    inner_fpl(0)
  }

  def attack_ecb(enc_func: (Array[Byte] => Array[Byte]),
                 find_block_suffix_prefix_length: ((Array[Byte] => Array[Byte]) => Option[(Int, Int, Int)])): ArrayBuffer[Byte] = {

    val (bsize, suffix_size, prefix_size) = find_block_suffix_prefix_length(enc_func).getOrElse(0, 0, 0)
    //println("Debug: Block size is " + bsize)
    //println("Debug: Secret suffix size is " + suffix_size)
    //println("Debug: Prefix size is " + prefix_size)
    // The length of the plaintext to submit in order to recover the whole secret
    val input_blocks: Int = math.ceil(suffix_size.toDouble / bsize).toInt
    //println("Debug: Need to send " + input_blocks + " input blocks")
    val num_prefix_blocks: Int = Math.ceil(prefix_size.toDouble / bsize).toInt
    // Number of bytes of the prefix rounded up to the block boundary to include our padding
    val num_prefix_bytes: Int = num_prefix_blocks * bsize
    val input_size: Int = input_blocks * bsize + (bsize * num_prefix_blocks - prefix_size)
    //println("Debug: Input size is " + input_size)

    var found: ArrayBuffer[Byte] = new ArrayBuffer[Byte]()
    0 until suffix_size foreach { i =>
      val payload: Array[Byte] = ("A" * (input_size - (i + 1))).getBytes("UTF-8")
      // Generate all block guesses formed from iterating the last byte prepended by what we've found
      // so far or the initial filler
      val guess_dict: List[List[Byte]] = (0 to 255 map { e =>
        val guess = payload.take(bsize - found.length - 1) ++ found.takeRight(bsize - 1) :+ e.toByte
        enc_func(("A" * (num_prefix_bytes - prefix_size)).getBytes() ++ guess).slice(num_prefix_bytes, num_prefix_bytes + bsize).toList
      }).toList
      // Encrypt the payload
      val encrypted = enc_func(payload)
      // Slice out the target block
      val sliced: List[Byte] = encrypted.slice((input_blocks + num_prefix_blocks - 1) * bsize, (input_blocks + num_prefix_blocks) * bsize).toList

      // Match against our guess dict
      val byte_found: Byte = guess_dict.indexOf(sliced).toByte
      found += byte_found
      //println("Debug: Found byte: " + byte_found + " (" + byte_found.toChar + ")")
    }
    found
  }

  println("[+] Decrypted output: ")
  println(new String(attack_ecb(encryption_oracle()(rnd_prefix), find_block_suffix_prefix_length()).toArray[Byte]))

}
