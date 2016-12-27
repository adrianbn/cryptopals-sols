package main.set_1

import java.util.Base64

/**
  * Created by Adrian Bravo on 12/22/16.
  */
object challenge6 extends App {
  /*
   * Transform each byte inside the ByteArray to a binary String (e.g. 3 -> "11") and count the
   * '1's or '0's in it.
   * Returns the number of times 'c' appears in the bitstream representing the provided byteArray.
   * c can be either 0 or 1 (we're searching in a binary stream after all)
   */
  def count(arr: Array[Byte], c: Char) = {
    arr.map(_.toBinaryString).map((c: String) => c.count((x: Char) => x == '1')).sum
  }

  def hamming_distance(ba1: Array[Byte], ba2: Array[Byte]): Int = {
    hamming_distance(new String(ba1), new String(ba2))
  }
  /*
   * the Hamming distance between two strings of equal length is the number of positions at
   * which the corresponding symbols are different.
   */
  def hamming_distance(s1: String, s2: String): Int = {
    // XOR the bytes of both strings leaving only set to 1 those positions that are different
    val xor = challenge2.xor_ba(s1.getBytes("UTF-8"), s2.getBytes("UTF-8"))
    // Transform each byte to a binary String (e.g. 3 -> "11") and count the '1's in it
    count(xor, '1')
  }


  val test1 = "this is a test"
  val test2 = "wokka wokka!!!"
  val expected = 37
  println(hamming_distance(test1, test2))
  println(hamming_distance(test1, test2) == expected)

  val filename = System.getProperty("user.dir") + "/src/main/set_1/ch6.txt"
  val source = io.Source.fromFile(filename, "UTF-8")


  val b64_ciphertext: String = try source.getLines() mkString finally source.close()
  val ciphertext: Array[Byte] = Base64.getDecoder.decode(b64_ciphertext)

  /*
   * Guess a key size, calculate the hamming distance between every two chunks of ciphertext of that size
   * Return the average distance for each keysize guess
   */
  val distances = for {
    ksize <- 2 to 40
    chunks = ciphertext.sliding(ksize, ksize).filter(_.length == ksize).sliding(2).toList
  } yield chunks.map(c => hamming_distance(c.head, c(1)).toFloat / ksize).sum / chunks.length

  // the key size is most likely the guessed value with the minimum distance between chunks
  val keysize = distances.indexOf(distances.min) + 2 // index starts in 0 + keysize starts in 2
  println("Keysize: " + keysize)

  // break the ciphertext in blocks of ksize size
  val ct_blocks: List[Array[Byte]] = ciphertext.grouped(keysize).toList


  /*
   * Transposes a matrix in trans_size chunks of arbitrary length. If the matrix's last row is not
   * of trans_size, only the existing elements are added to the transposition.
   */
  def transpose(blocks: List[Array[Byte]], trans_size: Int) = {
    (for {
      index: Int <- 0 until trans_size
      block: Array[Byte] <- blocks
      if block.isDefinedAt(index)
    } yield block(index)).grouped(blocks.length)
  }

  val transposed = transpose(ct_blocks, keysize).toList
  val sols: List[List[(String, Double, Int)]] = for {
    t <- transposed
  } yield challenge3.solve(t.toArray[Byte], 0.83).take(2) // we keep the two best guesses

  //sols.foreach(e => println(e.foreach((x: (String, Double, Int)) => println(x._1 + ", score: " + x._2 + ", key: " + x._3.toChar))))
  //sols.foreach(e => e.foreach((x: (String, Double, Int)) => println("key: " + x._3.toChar + ", score: " + x._2)))
  print("Best guess: ")
  sols.foreach(x => print(x.head._3.toChar))
  println()
  print("Second Best guess: ")
  sols.foreach(x => if (x.isDefinedAt(1)) print(x(1)._3.toChar) else print(x.head._3.toChar))
  println()
  //
  val key = "Terminator X: Bring the noise"
  println("\nDecrypted plaintext: ")
  println(new String(challenge5.xor_repeated_key(key, ciphertext)))
}
