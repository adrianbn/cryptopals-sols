package main.set_1

import scala.io.Source

/**
  * Created by Adrian Bravo on 12/22/16.
  */
object challenge8 extends App {
  val filename = System.getProperty("user.dir") + "/src/main/set_1/ch8.txt"

  val block_size: Int = 16

  // Detect ECB due to repeated patterns in the blocks
  val repetitions = (for {
    line <- Source.fromFile(filename).getLines()
    // Break the ciphertext in blocks of length block_size
    chunks: List[String] = line.sliding(block_size, block_size).toList
    // Find if there are any repeated blocks (ECB is deterministic and same plaintext results in
    // same ciphertext)
    num_repetitions = chunks.groupBy(identity).mapValues(_.size).maxBy(_._2)
    if num_repetitions._2 > 1
  } yield (num_repetitions, line)).toList

  println(repetitions.sortBy(_._1._2))
}
