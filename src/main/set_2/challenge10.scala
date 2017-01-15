package main.set_2

import java.security.MessageDigest
import javax.crypto.{Cipher, SecretKey}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import java.util.Base64

import main.set_1.{challenge2, challenge7}

/**
  * Created by Adrian Bravo on 12/24/16.
  */
object challenge10 extends App {
  def BLOCK_SIZE = 16
  def KEY_SIZE = 16

  /*
   * Takes a key string and returns 16 bytes that can be used in AES-128. If the key string is already
   * 16 byte long, it returns it unchanged. If not, it computes SHA-1 of the key and returns the first
   * 16 bytes. (SHA-1 is 160 bits)
   */
  def stretch_key(key_str: String): Array[Byte] = {
    if (key_str.length == KEY_SIZE)
      key_str.getBytes("UTF-8")
    else {
      val digest = MessageDigest.getInstance("SHA1")
      digest.digest(key_str.getBytes("UTF-8")).take(KEY_SIZE)
    }
  }

  /*
   * Performs AES-ECB encryption/decryption of the given plaintext
   * Key is an array of bytes
   */
  def do_ecb(key: Array[Byte], bytes: Array[Byte], mode: Int): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(mode, new SecretKeySpec(key, "AES"))
    cipher.doFinal(bytes)
  }

  def ecb_encrypt(key_str: String, plaintext: Array[Byte]): Array[Byte] = {
    // stretch key if necessary
    val key: Array[Byte] = stretch_key(key_str)
    // ECB encrypt
    do_ecb(key, plaintext, Cipher.ENCRYPT_MODE)
  }

  def ecb_encrypt(key: SecretKey, plaintext: Array[Byte]): Array[Byte] = {
    do_ecb(key.getEncoded, plaintext, Cipher.ENCRYPT_MODE)
  }

  def ecb_encrypt(key: Array[Byte], plaintext: Array[Byte]): Array[Byte] = {
    do_ecb(key, plaintext, Cipher.ENCRYPT_MODE)
  }

  def ecb_decrypt(key: SecretKey, ciphertext: Array[Byte]): Array[Byte] = {
    do_ecb(key.getEncoded, ciphertext, Cipher.DECRYPT_MODE)
  }

  def ecb_decrypt(key: Array[Byte], ciphertext: Array[Byte]): Array[Byte] = {
    do_ecb(key, ciphertext, Cipher.DECRYPT_MODE)
  }

  // CBC encryption methods
  def cbc_encrypt(key: SecretKey, plaintext: Array[Byte], iv: Array[Byte]): Array[Byte] = {
    do_cbc_enc(key.getEncoded, new String(plaintext), iv)
  }

  def cbc_encrypt(key_str: String, plaintext: String, iv: Array[Byte]): Array[Byte] = {
    // stretch key if necessary
    val key: Array[Byte] = stretch_key(key_str)
    // CBC encrypt
    do_cbc_enc(key, plaintext, iv)
  }

  def do_cbc_enc(key: Array[Byte], plaintext: String, iv: Array[Byte]): Array[Byte] = {
    // Pad the plaintext with PKCS7
    val pt_ba: Array[Byte] = challenge9.pkcs7(plaintext.getBytes("UTF-8"), BLOCK_SIZE)
    // split plaintext in chunks of size block size
    val chunks: List[Array[Byte]] = pt_ba.grouped(BLOCK_SIZE).toList
    // Implement CBC encryption
    chunks.foldLeft(List(iv))((acc, c) =>
      acc ++
        List(
          ecb_encrypt(key, challenge2.xor_ba(acc.last, c)))
    ).flatten.toArray
  }

  def cbc_decrypt(key: SecretKey, ciphertext: Array[Byte]): Array[Byte] = {
    do_cbc_dec(key.getEncoded, ciphertext)
  }

  def cbc_decrypt(key_str: String, ciphertext: Array[Byte]): Array[Byte] = {
    // stretch key if necessary
    val key: Array[Byte] = stretch_key(key_str)
    do_cbc_dec(key, ciphertext)
  }

  def do_cbc_dec(key: Array[Byte], ciphertext: Array[Byte]): Array[Byte] = {
    // split ciphertext in chunks of size block size
    val ct_iv_chunks: List[Array[Byte]] = ciphertext.grouped(BLOCK_SIZE).toList
    // Retrieve the IV from the ciphertext (first 16 bytes, first element of the list)
    val (iv: List[Array[Byte]], chunks: List[Array[Byte]]) = ct_iv_chunks.splitAt(1)

    // Implement CBC decryption
    // AES decrypt all chunks
    val aes_chunks: List[Array[Byte]] = chunks.map((b: Array[Byte]) => ecb_decrypt(key, b))

    // XOR chunks with previous chunk
    val padded_pt: Array[Byte] = (for {
      index <- aes_chunks.indices
      prev_chunk = if (index == 0) iv.head else chunks(index - 1)
    } yield challenge2.xor_ba(aes_chunks(index), prev_chunk)).flatten.toArray

    // Validate and Remove PKCS7 padding from ciphertext
    challenge15.validatePKCS7(padded_pt)
  }


  // Test

  val key = "YELLOW SUBMARINE"
  val msg = "YELLOW SUBMARINE ROCKS BIG TIME I TELL YOU!"
  val iv = "0" * 16
  // Encrypt
  val ciphertext: Array[Byte] = cbc_encrypt(key, msg, iv.getBytes("UTF-8"))
  val b64_ciphertext: String = Base64.getEncoder.encodeToString(ciphertext)
  println(b64_ciphertext)

  // Decrypt with my implementation
  println(new String(cbc_decrypt(key, ciphertext)))

  // Decrypt with JCE's CBC PKCS7
  val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") // JCE does PKCS7 under the name of PKCS5Padding
  cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(stretch_key(key), "AES"), new IvParameterSpec(ciphertext.take(BLOCK_SIZE)))
  val plaintext = cipher.doFinal(ciphertext.drop(BLOCK_SIZE))
  println(new String(plaintext))

  // Decrypt target file
  val filename = System.getProperty("user.dir") + "/src/main/set_2/ch10.txt"
  val ct: Array[Byte] = challenge7.read_b64_file(filename)
  // Add the IV to the Ciphertext as their file doesn't come with it prepended
  val pt: Array[Byte] = cbc_decrypt(key, Array.fill[Byte](BLOCK_SIZE)(0) ++ ct)
  println(new String(pt))

  //
}
