package main.set_3

import java.util.Base64
import main.set_1.challenge2
import main.set_2.challenge10

/**
  * Created by adrian.bravo on 1/13/17.
  */
object challenge18 extends App {

  trait AesCtrI {
    val nonce: Long // 64 bit "unsigned"

    def encrypt(pt: Vector[Byte]): Vector[Byte]
    def decrypt(pt: Vector[Byte]): Vector[Byte]
  }

  class AESCTR(val key: String, val nonce: Long = 0) extends AesCtrI {
    import challenge10.{BLOCK_SIZE, ecb_encrypt}

    private var ctr: Long  = 0

    def encrypt(pt: String): Vector[Byte] = do_ctr(pt.getBytes("UTF-8").toVector)
    override def encrypt(pt: Vector[Byte]): Vector[Byte] = do_ctr(pt)
    override def decrypt(ct: Vector[Byte]): Vector[Byte] = do_ctr(ct)

    /*
     * Convert an "unsigned" Long of 64 bits to a byte array of size 8.
     * This code depends on the size of Long
     */
    private def toByteArray8(l: Long): Array[Byte] = {
      // alternatively ByteBuffer.allocate(8).putLong(123456).array()
      val ba: Array[Byte] = Array.ofDim(8)
      ba.zipWithIndex.map {
        case (_, idx: Int) => (l >>> (idx * 8)).toByte
      } // reverse for big endian
    }

    private def keystream: Vector[Byte] = {
      val ctrnonce: Array[Byte] = toByteArray8(nonce) ++ toByteArray8(ctr)
      ecb_encrypt(key, ctrnonce).toVector
    }

    private def do_ctr(ct: Vector[Byte]): Vector[Byte] = {
      ctr = 0
      (for {
        block: Vector[Byte] <- ct.grouped(BLOCK_SIZE)
        ks: Vector[Byte] = keystream
        _ = ctr += 1
      } yield challenge2.xor_ba(ks.take(block.length), block)).toVector.flatten
    }
  }

  // Nifty trick to convert a JVM signed long to a type that can hold the "unsigned" version for
  // printing/displaying
  def asUnsigned(unsignedLong: Long) =
    (BigInt(unsignedLong >>> 1) << 1) + (unsignedLong & 1)

  val b64_ct: String = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
  val ct: Vector[Byte] = Base64.getDecoder.decode(b64_ct).toVector
  val key: String = "YELLOW SUBMARINE"
  val pt: Vector[Byte] = new AESCTR(key).decrypt(ct)
  println("Solution = " + new String(pt.toArray))

  // Other enc/dec
  val test1 = "All that is gold does not glitter, " +
              "Not all those who wander are lost; " +
              "The old that is strong does not wither, " +
              "Deep roots are not reached by the frost."

  val cipher = new AESCTR(key)
  val ct1 = cipher.encrypt(test1)
  println("Test1 = " + new String(cipher.decrypt(ct1).toArray))
}
