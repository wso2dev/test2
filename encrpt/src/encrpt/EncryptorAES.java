package encrpt;


import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class EncryptorAES {

private static final String ALGORITHM = "AES";
private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
private static final String ENCODING = "UTF-8";
private byte[] ivBytes;
private SecretKey secretKey;

public  String encrypt(String payload)
throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
NoSuchPaddingException, UnsupportedEncodingException, InvalidParameterSpecException {
generateSecretKey();
Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
AlgorithmParameters params = cipher.getParameters();
ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
byte[] encryptedTextBytes = cipher.doFinal(payload.getBytes(ENCODING));
return new String(new Base64().encode(encryptedTextBytes));
}

public String decrypt(String payload, String key, String bytes)
throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
InvalidKeyException, InvalidAlgorithmParameterException, DecoderException {
setSecretKey(key);
setIVBytes(bytes);
byte[] encryptedTextBytes = Base64.decodeBase64(payload.getBytes());
Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));
byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
return new String(decryptedTextBytes);
}

private void generateSecretKey() throws NoSuchAlgorithmException {
//KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
//generator.init(128);
//secretKey = generator.generateKey();

secretKey = new SecretKeySpec("herotttttttttttt".getBytes(), "AES");
System.out.println(secretKey);
}



private void setIVBytes(String ivBytes) throws DecoderException {
this.ivBytes = Hex.decodeHex(ivBytes.toCharArray());
}

private void setSecretKey(String secretKey) throws DecoderException {
byte[] byteArray = Hex.decodeHex(secretKey.toCharArray());
this.secretKey = new SecretKeySpec(byteArray, 0, byteArray.length, ALGORITHM);
}

public static void main(String s[]) throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, UnsupportedEncodingException, InvalidParameterSpecException
{
	System.out.println(new EncryptorAES().encrypt("i am hero"));
}
}