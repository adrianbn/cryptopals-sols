package main.set_1


import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
  * Created by Adrian Bravo on 12/22/16.
  */
object challenge7 extends App {
  def read_b64_file(path: String): Array[Byte] = {
    val source = io.Source.fromFile(path, "UTF-8")

    val b64_ciphertext: String = try source.getLines() mkString finally source.close()
    Base64.getDecoder.decode(b64_ciphertext)
  }

  val filename = System.getProperty("user.dir") + "/src/main/set_1/ch7.txt"
  val ciphertext = read_b64_file(filename)
  // No need to stretch key as it is 16 bytes already
  val key_str = "YELLOW SUBMARINE"
  val cipher = Cipher.getInstance("AES/ECB/NoPadding")
  cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key_str.getBytes("UTF-8"), "AES"))

  println(new String(cipher.doFinal(ciphertext)))
}
