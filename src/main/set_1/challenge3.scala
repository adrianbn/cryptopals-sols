package main.set_1

/**
  * Created by Adrian Bravo on 12/21/16.
  */
object challenge3 extends App {

  class FreqAnalyzer {
    /*
     * Returns the frequency table for the given byte array
     */
    def freq_table(ba: Array[Byte]): Map[Byte, Double] = {
      val ba_size: Int = ba.length
      ba.groupBy(c => c).mapValues(_.length.toDouble * 100 / ba_size)
    }

    /*
     * Calculates the difference between the frequency of each character in the given frequency table
     * and the frequency of the same character in the English language. Sums up the absolute values
     * of those differences to provide a score for a given freq_table. The smaller the value, the more
     * likely the freq_table is to represent the expected plaintext.
     */
    def freq_diff(freq_tbl: Map[Byte, Double]): Double = {
      (for {
        (e: Byte, f: Double) <- freq_tbl
        freq = FreqAnalyzer.freqs.getOrElse(e.toChar.toUpper, 0.0)
      } yield math.abs(freq - f)
        ).foldLeft(0.0)((z: Double, e: Double) => z + e)
    }

    // Computes a score of a plaintext candidate
    def score(pt: Array[Byte]): Double = {
      val ft = freq_table(pt)
      freq_diff(ft) / pt.length
    }


   /*
   * Generate all plaintext candidates by xoring the ciphertext with all potential one byte keys
   */
    def all_xors(ct_ba: Array[Byte]): IndexedSeq[(Array[Byte], Int)] = {
      for {
        key <- 0 to 255
        ks = Array.fill[Byte](ct_ba.length)(key.toByte)
        // Take into account only A-Za-z and space for histogram building to avoid distorting
        // the data given that we only have freq tables for those letters
        xored = challenge2.xor_ba(ks, ct_ba).filter(b => b.toChar.isLetter || b.toChar.isWhitespace)
        if !xored.isEmpty
      } yield (xored, key)
    }

    /*
     * Calculates the scores for all the candidate plaintexts, removing all plaintexts that are not
     * ascii, contain NULL or DEL characters.
     */
    def scores(ct_ba: Array[Byte]) = {
      for {
        (xor_ba, key) <- all_xors(ct_ba)
        if xor_ba.forall((c: Byte) => c.toInt > 0 && c.toInt < 127) // filter out non-ascii and NULL and DEL
      } yield (challenge2.ba2hex(xor_ba), score(xor_ba), key)
    }
  }

  // Companion object to hold constants
  object FreqAnalyzer {

    val freqs: Map[Char, Double] = Map(
      'A' -> 6.51738, 'B' -> 1.24248, 'C' -> 2.17339,
      'D' -> 3.49835, 'E' -> 10.41442, 'F' -> 1.97881,
      'G' -> 1.58610, 'H' -> 4.92888, 'I' -> 5.58094,
      'J' -> 0.09033, 'K' -> 0.50529, 'L' -> 3.31490,
      'M' -> 2.02124, 'N' -> 5.64513, 'O' -> 5.96302,
      'P' -> 1.37645, 'Q' -> 0.08606, 'R' -> 4.97563,
      'S' -> 5.15760, 'T' -> 7.29357, 'U' -> 2.25134,
      'V' -> 0.82903, 'W' -> 1.71272, 'X' -> 0.13692,
      'Y' -> 1.45984, 'Z' -> 0.07836, ' ' -> 19.18182)

    // Transforms a hex string to Ascii
    def toAscii(hex: String) = {
      import javax.xml.bind.DatatypeConverter
      new String(DatatypeConverter.parseHexBinary(hex))
    }
  }



  def solve(ct: Array[Byte], threshold: Double = 1.4): List[(String, Double, Int)] = {
    //println("Solving for threshold " + threshold + " ... ")
    val analyzer = new FreqAnalyzer
    val sorted_scores = analyzer.scores(ct).sortWith(_._2 < _._2)
    //println("Potential results pre threshold sieve: " + sorted_scores.length)
    //println(sorted_scores)
    // get those below threshold, the answer should be there or threshold needs to be changed
    sorted_scores.takeWhile(score => score._2 < threshold).toList
  }

  val ciphertext: String = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  val ct_ba: Array[Byte] = challenge2.hex2ba(ciphertext)
  val sol = solve(ct_ba)
  sol.foreach((x: (String, Double, Int)) => println(FreqAnalyzer.toAscii(x._1) + ", score: " + x._2 + ", key: " + x._3.toChar))

}
