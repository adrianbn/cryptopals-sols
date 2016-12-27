package main.set_2

import java.security.SecureRandom
import javax.crypto.{KeyGenerator, SecretKey}
import java.util.Random

/**
  * Created by Adrian Bravo on 12/24/16.
  */
object challenge11 extends App {

  /*
   * Generates a random AES SecretKey of the specified key size
   */
  def rand_key(key_size: Int = 128): SecretKey = {
    val key_gen: KeyGenerator = KeyGenerator.getInstance("AES")
    key_gen.init(key_size)
    key_gen.generateKey()
  }

  // Randomly returns true or false
  def flip_coin: Boolean = {
    // Not cryptographically secure but not necessary for this exercise
    val rng: Random = new Random()
    rng.nextBoolean()
  }

  /*
   * Generates a random number between low and high (both included)
   */
  def rnd_num_bytes(low: Int, high: Int): Int = {
    val rng: Random = new Random()
    rng.nextInt(high - low + 1) + low
  }

  def encryption_oracle()(plaintext: Array[Byte]): Array[Byte] = {
    val key: SecretKey = rand_key()
    val prefix: Array[Byte] = ("b" * rnd_num_bytes(5, 10)).getBytes("UTF-8")
    val suffix: Array[Byte] = ("a" * rnd_num_bytes(5, 10)).getBytes("UTF-8")
    val pt: Array[Byte] = prefix ++ plaintext ++ suffix

    if (flip_coin) {
      println("ECB")
      val padded_pt: Array[Byte] = challenge9.pkcs7(pt, challenge10.BLOCK_SIZE)
      challenge10.ecb_encrypt(key.getEncoded, padded_pt)
    } else {
      println("CBC")
      val iv: Array[Byte] = new Array[Byte](challenge10.BLOCK_SIZE)
      val prng: SecureRandom = new SecureRandom()
      prng.nextBytes(iv)
      challenge10.cbc_encrypt(key, pt, iv)
    }
  }

  /*
   * Receives a black box (encryption oracle) that performs encryption with either ECB or CBC and determines
   * whether it encrypted the plaintext using ECB.
   * The argument is a partial function to invoke with plaintexts
   */
  def detect_ecb(black_box: (Array[Byte]) => Array[Byte] = encryption_oracle()): Boolean = {
    val num_blocks: Int = 40
    // Select a plaintext that will generate repetition. This will generate 40 - 2 repeated blocks + 0-1 padding
    // The -2 comes from the prefix and suffix added within the encryption oracle
    val plaintext: String = "X" * (challenge10.BLOCK_SIZE * num_blocks)
    // Encrypt with our encryption oracle
    val ciphertext: Array[Byte] = black_box(plaintext.getBytes("UTF-8"))
    // Break the ciphertext in blocks of length block_size
    val chunks: List[Array[Byte]] = ciphertext.sliding(challenge10.BLOCK_SIZE, challenge10.BLOCK_SIZE).toList

    // Find if there are any repeated blocks (ECB is deterministic and same plaintext results in
    // same ciphertext). Transform the Arrays to List for identity to work as expected.
    val num_repetitions: Map[List[Byte], Int] = chunks.map(_.toList).groupBy(identity).mapValues(_.size)
    num_repetitions.exists(e => e._2 >= num_blocks - 2)
  }

  1 to 10 foreach { _ => println(detect_ecb(encryption_oracle())) }


}
