package main.set_2

import javax.crypto.SecretKey

/**
  * Created by Adrian Bravo on 12/26/16.
  */
object challenge13 extends App {

  /*
   From
    foo=bar&baz=qux&zap=zazzle
   to
    {
      foo: 'bar',
      baz: 'qux',
      zap: 'zazzle'
     }
   */

  class Parameters(uri: String) {
    val pairs: Array[String] = uri.split("&") // [foo=bar, baz=qux, zap=zazzle]
    val dict: Map[String, String] = pairs.foldLeft(Map.empty[String,String]) { (acc: Map[String, String], pair: String) =>
      acc ++ pair.split("=").grouped(2).map {
        case Array(k, v) => k -> v
        case Array(k) => k -> "" // email is empty
      }.toMap
    } // Map(foo -> bar, baz -> qux, zap -> zazzle)

    override def toString() = uri
  }

  /*
    From "foo@bar.com" to
    {
      email: 'foo@bar.com',
      uid: 10,
      role: 'user'
    }
    encoded as email=foo@bar.com&uid=10&role=user
    removing & and = in the process
   */
  def profile_for(email: String): Parameters = {
    new Parameters("email=" + email.replaceAll("[=&]", "") + "&uid=10&role=user")
  }

  def encrypted_profile_for(key: SecretKey, email: String): Array[Byte] = {
    // generate a profile for the given email
    val profile: String = profile_for(email).toString()
    // encrypt the profile under that key
    val padded_pt: Array[Byte] = challenge9.pkcs7(profile.getBytes("UTF-8"), challenge10.BLOCK_SIZE)
    challenge10.ecb_encrypt(key.getEncoded, padded_pt)
  }

  // generate a random key
  val key: SecretKey = challenge12.rand_key()
  val enc_profile = encrypted_profile_for(key, "foo@bar.com")

  // decrypt the profile and decode
  val pt_profile: Parameters = new Parameters(new String(challenge10.ecb_decrypt(key.getEncoded, enc_profile)))

  // Generate a role=admin profile using encrypted_profile_for
  // define a partially applied function to reuse our find_block_secret_length
  def enc_func(key: SecretKey)(pt: Array[Byte]) = encrypted_profile_for(key, new String(pt))
  // obtain the block size and the additional encrypted text size
  val (bsize, secret_size) = challenge12.find_block_secret_length(enc_func(key))
  // calculate the number of bytes that we need to prepend to force a new block
  val padding: Int = (Math.ceil(secret_size.toDouble / bsize) * bsize - secret_size).toInt
  // encrypt admin + PKCS7PADDING, forcing it to fall in its own block
  val admin_ct: Array[Byte] = encrypted_profile_for(key, "A" * (padding + 1) + new String(challenge9.pkcs7("admin".getBytes("UTF-8"), bsize)))
  // extract the block that contains the ct for admin
  val admin_ct_block: Array[Byte] = admin_ct.slice(bsize, 2 * bsize)
  // println(new String(challenge10.ecb_decrypt(key.getEncoded, admin_ct_block)))
  // force the ciphertext so that user (from role=user) falls in the last block
  val ct: Array[Byte] = encrypted_profile_for(key, "A" * (padding + "user".length) + new String(challenge9.pkcs7("admin".getBytes("UTF-8"), bsize)))
  // println(new String(challenge10.ecb_decrypt(key.getEncoded, ct.takeRight(bsize))))
  // replace the last block (user) with our admin ct block
  val attack_ct = ct.dropRight(bsize) ++ admin_ct_block
  println("Result: " + new String(challenge10.ecb_decrypt(key.getEncoded, attack_ct)))

}
