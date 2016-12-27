package main.set_2

/**
  * Created by Adrian Bravo on 12/23/16.
  */
object challenge9 extends App {
  /*
   * Take a string and a block size in bytes and pad the string to the nearest multiple of the
   * block size using the PKCS7 scheme (i.e. appending N bytes of value N where N is the number
   * of bytes needed to pad up to bsize)
   */
  def pkcs7(str: Array[Byte], bsize: Int): Array[Byte] = {
    def calc_pad(chunk_length: Int) = {
      val pad: Int = bsize - chunk_length
      if (pad == 0)
        bsize
      else
        pad
    }
    // divide string into chunks of size bsize
    val chunks: List[Array[Byte]] = str.sliding(bsize, bsize).toList
    // number of bytes of padding needed. Also, value of those bytes
    val pad: Int = calc_pad(chunks.last.length)
    val pad_ba: Array[Byte] = Array.fill[Byte](pad)(pad.toByte)
    str ++ pad_ba
  }

  val padded = pkcs7("YELLOW SUBMARINE".getBytes("UTF-8"), 20)
  println(new String(padded))
  println(padded.length)
  println(padded.toList)

  val padded2 = pkcs7(("X" * 70).getBytes("UTF-8"), 16)
  println(padded2.toList)
  println(padded2.length)
}
