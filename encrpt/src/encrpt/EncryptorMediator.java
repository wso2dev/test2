package encrpt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

public class EncryptorMediator extends AbstractMediator { 

public boolean mediate(MessageContext context) { 

String payload = getPayload(context);
if(payload == null || payload.length() < 1){
System.out.println("1st condition");
return completeProcess(context, "Payload is empty.");
}else{
String key = getSecretKey(context);
String bytes = getIVByteString(context);
process(context, payload, key, bytes);
}
return true;
}

private boolean process(MessageContext ctx, String payload, String key, String bytes){
String respondPayload = "";
String encryptionKey = "";
String ivbyteString = "";
try {
EncryptorAES encryptor = new EncryptorAES();
if(bytes == "NULL"){
respondPayload = encryptor.encrypt(payload);
encryptionKey = encryptor.getSecretKey();
ivbyteString = encryptor.getIVBytes();
}else{
if(key != null && !key.equals("NULL") && bytes != null){
respondPayload = encryptor.decrypt(payload, key, bytes);
}else{
return completeProcess(ctx,"Encryption key or IVByte String is invalid.");
}
}
return completeProcess(ctx, respondPayload, encryptionKey, ivbyteString);
} catch (InvalidKeyException e) {
return completeProcess(ctx,e.getMessage());
} catch (NoSuchAlgorithmException e) {
return completeProcess(ctx,e.getMessage());
} catch (IllegalBlockSizeException e) {
return completeProcess(ctx,e.getMessage());
} catch (BadPaddingException e) {
return completeProcess(ctx,e.getMessage());
} catch (NoSuchPaddingException e) {
return completeProcess(ctx,e.getMessage());
} catch (UnsupportedEncodingException e) {
return completeProcess(ctx,e.getMessage());
} catch (InvalidParameterSpecException e) {
return completeProcess(ctx,e.getMessage());
} catch (InvalidAlgorithmParameterException e) {
return completeProcess(ctx,e.getMessage());
} catch (DecoderException e) {
return completeProcess(ctx,e.getMessage());
}
}

private String getPayload(MessageContext context){
return context.getProperty("Paylod").toString();
}

private String getSecretKey(MessageContext context){
return context.getProperty("SecretKey").toString();
}

private String getIVByteString(MessageContext context){
return context.getProperty("IVByteString").toString();
}

private boolean completeProcess(MessageContext context,String payload, String key, String bytes){
setResultPayload(context,payload);
setEncryptionKey(context,key);
setIVByteString(context,bytes);
setSuccess(context, "true");
setErrorMessage(context, "");
return true;
}

private boolean completeProcess(MessageContext context,String error){
 setSuccess(context, "false");
 setErrorMessage(context, error);
 return true;
}

private void setSuccess(MessageContext context, String success){
context.setProperty("success", success);
}

private void setResultPayload(MessageContext context, String respondPayload){
context.setProperty("resultPayload", respondPayload);
}

private void setEncryptionKey(MessageContext context, String encryptionKey){
context.setProperty("encyptionKey", encryptionKey);
}

private void setErrorMessage(MessageContext context, String errorMessage){
context.setProperty("errorMessage", errorMessage);
}

private void setIVByteString(MessageContext context, String ivbyteString){
context.setProperty("ivByteString", ivbyteString);
}
}