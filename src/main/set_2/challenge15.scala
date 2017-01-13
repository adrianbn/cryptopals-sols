package main.set_2

import javax.crypto.BadPaddingException

/**
  * Created by Adrian Bravo on 12/27/16.
  */
object challenge15 extends App {

  def validatePKCS7(str: Array[Byte]): Array[Byte] = {
    val num_pad: Int = str.last.toInt
    val pad_bytes: Array[Byte] = str.takeRight(num_pad)

    if (valid_padding(pad_bytes, num_pad)) {
      // println("Debug: Padded PT = " + str.toList)
      str.dropRight(num_pad)
    } else {
      throw new BadPaddingException("String has invalid PKCS7 padding")
    }
  }

  def valid_padding(pad_bytes: Array[Byte], num_pad: Int): Boolean = {
    (num_pad > 0) && (pad_bytes.length == num_pad) && pad_bytes.forall(e => e == num_pad)
  }

  //

  val test1 = "ICE ICE BABY\u0004\u0004\u0004\u0004"
  val test2 = "ICE ICE BABY\u0005\u0005\u0005\u0005"
  val test3 = "ICE ICE BABY\u0005\u0005\u0005\u0005"

  println(new String(validatePKCS7(test1.getBytes())))
  try {
    println(validatePKCS7(test2.getBytes("UTF-8")))
  } catch {
    case bp: BadPaddingException => println("Test 2 has invalid padding")
  }
  try {
    println(validatePKCS7(test3.getBytes("UTF-8")))
  } catch {
    case bp: BadPaddingException => println("Test 3 has invalid padding")
  }
}
