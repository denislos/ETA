package mipt.information.defence;

import java.util.HashSet;
import java.util.Set;

abstract public class TlsMessage {
  public static boolean isSupported(int messageType) {
    if ((MsgType.ClientHello.getCode() == messageType) ||
        (MsgType.ServerHello.getCode() == messageType) ||
        (MsgType.Certificate.getCode() == messageType) ||
        (MsgType.ServerKeyExchange.getCode() == messageType) ||
        (MsgType.ClientKeyExchange.getCode() == messageType)) {
      return true;
    }
    return false;
  }

  public static MsgType getMsgType(int code) throws UnsupportedOperationException {
    switch (code) {
      case 1:
        return MsgType.ClientHello;
      case 2:
        return MsgType.ServerHello;
      case 11:
        return MsgType.Certificate;
      case 12:
        return MsgType.ServerKeyExchange;
      case 16:
        return MsgType.ClientKeyExchange;
      default:
        throw new UnsupportedOperationException();
    }
  }

  public static TlsMessage getMessage(MsgType msg, byte[] array) throws UnsupportedOperationException {
    switch(msg)
    {
      case ClientHello:
        return new ClientHelloMessage(array);
      case ServerHello:
        return new ServerHelloMessage(array);
      case Certificate:
        return new CertificateMessage(array);
      case ServerKeyExchange:
        return new ServerKeyExchangeMessage(array);
      case ClientKeyExchange:
        return new ClientKeyExchangeMessage(array);
      default:
        throw new UnsupportedOperationException();
    }
  }

  public abstract boolean writeData(Features feature)
      throws NoSuchFieldException, IllegalAccessException;
}

class ClientHelloMessage extends TlsMessage {
  private Set<String> setKeys = new HashSet<>();
  private Set<String> setExtensions = new HashSet<>();

  private String noKey = "No such key";
  private String noExt = "No such extension";

  private String decipherKey(int firstByte, int secondByte) {
    CipherSuites[] arrayCipher = CipherSuites.values();
    for (CipherSuites cipherSuites : arrayCipher) {
      if ((cipherSuites.getFirstByte() == firstByte) &&
          (cipherSuites.getSecondByte() == secondByte)) {
        return cipherSuites.name();
      }
    }
    return noKey;
  }

  private String decipherExtension(int code) {
    Extensions[] arrayExtensions = Extensions.values();
    for (Extensions extensions : arrayExtensions) {
      if (extensions.getCode() == code) {
        return extensions.name();
      }
    }
    return noExt;
  }

  public ClientHelloMessage(byte[] array) {
    int msgPointer = 35;
    int lengthOfCipher = 0;
    int lengthOfOne;
    int firstByte;
    int secondByte;
    int codeExt;

    int lengthSessionID = (array[34] >= 0) ? array[34] : array[34] + 256;
    msgPointer += lengthSessionID;

    lengthOfCipher += (array[msgPointer + 1] >= 0) ? array[msgPointer + 1] : array[msgPointer + 1] + 256;
    lengthOfCipher += (array[msgPointer] >= 0) ? (array[msgPointer]) * 256 : (array[msgPointer] + 256) * 256;
    msgPointer += 2;

    for (int i = msgPointer; i < lengthOfCipher + msgPointer; i += 2) {
      firstByte = (array[i] >= 0) ? array[i] : array[i] + 256;
      secondByte = (array[i+1] >= 0) ? array[i+1] : array[i+1] + 256;
      String key = decipherKey(firstByte, secondByte);
      if (!key.equals(noKey)) {
        setKeys.add(key);
      }
    }

    msgPointer += lengthOfCipher;
    int lengthCompMeth = (array[msgPointer] >= 0) ? array[msgPointer] : array[msgPointer] + 256;
    msgPointer += lengthCompMeth + 1;

    msgPointer += 2;

    while (msgPointer < array.length) {
      codeExt = 0;
      codeExt += (array[msgPointer] >= 0) ? (array[msgPointer]) * 256 : (array[msgPointer] + 256) * 256;
      codeExt += (array[msgPointer + 1] >= 0) ? array[msgPointer + 1] : array[msgPointer + 1] + 256;
      String ext = decipherExtension(codeExt);
      if (!ext.equals(noExt)){
        setExtensions.add(ext);
      }

      lengthOfOne = 0;
      lengthOfOne += (array[msgPointer + 2] >= 0) ? (array[msgPointer + 2]) * 256 : (array[msgPointer + 2] + 256) * 256;
      lengthOfOne += (array[msgPointer + 3] >= 0) ? array[msgPointer + 3] : array[msgPointer + 3] + 256;
      msgPointer += 4 + lengthOfOne;
    }
  }

  @Override
  public boolean writeData(Features feature) throws NoSuchFieldException, IllegalAccessException {
    Class clazz = feature.getClass();
    for (String key: setKeys) {
      clazz.getField(key).setInt(feature, 1);
    }
    for (String extension: setExtensions) {
      clazz.getField(extension).setInt(feature, 1);
    }
    return feature.setFlag(FlagToParser.FLAGCLIENTHELLO);
  }
}

class ServerHelloMessage extends TlsMessage {

  private Set<String> chosen_ext = new HashSet<>();
  private String chosen_key = null;

  private String noKey = "No such key";
  private String noExt = "No such extension";

  private String decipherKey(int firstByte, int secondByte) {
    CipherSuites[] arrayCipher = CipherSuites.values();
    for (CipherSuites cipherSuites : arrayCipher) {
      if ((cipherSuites.getFirstByte() == firstByte) &&
          (cipherSuites.getSecondByte() == secondByte)) {
        return cipherSuites.name();
      }
    }
    return noKey;
  }

  private String decipherExtension(int code) {
    Extensions[] arrayExtensions = Extensions.values();
    for (Extensions extensions : arrayExtensions) {
      if (extensions.getCode() == code) {
        return extensions.name();
      }
    }
    return noExt;
  }

  public ServerHelloMessage(byte[] array) {
    int msgPointer = 35;
    int codeExt;
    int lengthOfOne;

    int lengthSessionID = (array[34] >= 0) ? array[34] : array[34] + 256;
    msgPointer += lengthSessionID;

    int firstByte = (array[msgPointer] >= 0) ? array[msgPointer] : array[msgPointer] + 256;
    int secondByte = (array[msgPointer+1] >= 0) ? array[msgPointer+1] : array[msgPointer+1] + 256;
    String key = decipherKey(firstByte, secondByte);
    if (!key.equals(noKey)) {
      chosen_key = key;
    }

    msgPointer += 5;

    while (msgPointer < array.length) {
      codeExt = 0;
      codeExt += (array[msgPointer] >= 0) ? (array[msgPointer]) * 256 : (array[msgPointer] + 256) * 256;
      codeExt += (array[msgPointer + 1] >= 0) ? array[msgPointer + 1] : array[msgPointer + 1] + 256;
      String ext = decipherExtension(codeExt);
      if (!ext.equals(noExt)){
        chosen_ext.add(ext);
      }

      lengthOfOne = 0;
      lengthOfOne += (array[msgPointer + 2] >= 0) ? (array[msgPointer + 2]) * 256 : (array[msgPointer + 2] + 256) * 256;
      lengthOfOne += (array[msgPointer + 3] >= 0) ? array[msgPointer + 3] : array[msgPointer + 3] + 256;
      msgPointer += 4 + lengthOfOne;
    }
  }

  @Override
  public boolean writeData(Features feature) throws NoSuchFieldException, IllegalAccessException {
    Class clazz = feature.getClass();
    feature.selected_ciphersuite = CipherSuites.valueOf(chosen_key).getFirstByte() * 256 +
        CipherSuites.valueOf(chosen_key).getSecondByte();
    if (!chosen_ext.isEmpty()) {
      for (String extension: chosen_ext) {
        clazz.getField(extension+"_selected").setInt(feature, 1);
      }
    }
    return feature.setFlag(FlagToParser.FLAGSERVERHELLO);
  }
}

class CertificateMessage extends TlsMessage {

  public CertificateMessage(byte[] array) {
    //System.out.println("Certificate");
  }

  @Override
  public boolean writeData(Features feature) {
    return feature.setFlag(FlagToParser.FLAGCERTIFICATE);
  }
}

@Deprecated
class ServerKeyExchangeMessage extends TlsMessage {

  public ServerKeyExchangeMessage(byte[] array) {
    //System.out.println("Server key exc");
  }

  @Override
  public boolean writeData(Features feature) {
    return feature.setFlag(FlagToParser.FLAGSERVERKEYEXCHANGE);
  }
}

class ClientKeyExchangeMessage extends TlsMessage {

  private int lengthOfClientKey;

  public ClientKeyExchangeMessage(byte[] array) {
    lengthOfClientKey = array[0];
  }

  @Override
  public boolean writeData(Features feature) {
    feature.pkl = lengthOfClientKey;
    return feature.setFlag(FlagToParser.FLAGCLIENTKEYEXCHANGE);
  }
}