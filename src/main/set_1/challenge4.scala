package main.set_1

import main.set_1.challenge3.FreqAnalyzer

/**
  * Created by Adrian Bravo on 12/21/16.
  */
object challenge4 extends App {

  import scala.io.Source

  val filename = System.getProperty("user.dir") + "/src/main/set_1/ch4.txt"
  val threshold = 1.7
  val analyzer = new challenge3.FreqAnalyzer

  for (line <- Source.fromFile(filename).getLines()) {
    val ct_ba: Array[Byte] = challenge2.hex2ba(line)
    val sol = challenge3.solve(ct_ba, threshold)
    sol.foreach((x: (String, Double, Int)) => println(FreqAnalyzer.toAscii(x._1) + ", score: " + x._2 + ", key: " + x._3.toChar))
  }
}
