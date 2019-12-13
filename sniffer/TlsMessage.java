package mipt.information.defence;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Formatter;
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

  public static TlsMessage getMessage(MsgType msg, byte[] array, int version) throws UnsupportedOperationException {
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
        return new ClientKeyExchangeMessage(array, version);
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

    if (array.length < 35) {
      System.out.println("Connection failed");
      return;
    }
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

    if (array.length < 35) {
      System.out.println("Connection failed");
      return;
    }
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
    if (chosen_key != null) {
      feature.selected_ciphersuite = CipherSuites.valueOf(chosen_key).getFirstByte() * 256 +
          CipherSuites.valueOf(chosen_key).getSecondByte();
    }
    if (!chosen_ext.isEmpty()) {
      for (String extension: chosen_ext) {
        clazz.getField(extension+"_selected").setInt(feature, 1);
      }
    }
    return feature.setFlag(FlagToParser.FLAGSERVERHELLO);
  }
}

class CertificateMessage extends TlsMessage {

  private static final Byte MAGIC_0 = 0x30;
  private static final Byte MAGIC_1 = 0x1e;

  private static final Byte MAGIC_DELIMETER_0 = 0x17;
  private static final Byte MAGIC_DELIMETER_1 = 0x0d;

  private static final String DATE_FORMAT = "yy:MM:dd HH:mm:ss";

  private int validity = 1; // Treat as it is always valid

  public CertificateMessage(byte[] array) {
    final int length = array.length;

    for (int i = 0; i < length; i++) {
      if (array[i] == MAGIC_0 && array[i + 1] == MAGIC_1)
      {
        if (array[i + 2] == MAGIC_DELIMETER_0 && array[i + 3] == MAGIC_DELIMETER_1 &&
            array[i + 17] == MAGIC_DELIMETER_0 && array[i + 18] == MAGIC_DELIMETER_1)
        {
          Date beforeDate = parseDate(Arrays.copyOfRange(array, i + 4, i + 16));
          Date afterDate = parseDate(Arrays.copyOfRange(array, i + 19, i + 31));

          Date currentDate = new Date();

          if ((currentDate.compareTo(beforeDate) < 0) || (currentDate.compareTo(afterDate) > 0))
          {
            validity = 0;
          }
        }
      }
    }
  }

  private static Date parseDate(byte[] array) {
    StringBuilder sbuf = new StringBuilder();
    Formatter fmt = new Formatter(sbuf);
    fmt.format("%c%c:%c%c:%c%c %c%c:%c%c:%c%c", array[0], array[1], array[2], array[3], array[4], array[5], array[6], array[7], array[8], array[9], array[10], array[11]);
    SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);

    Date date = new Date();

    try {
      date = dateFormat.parse(sbuf.toString());
    }
    catch (Exception e)
    {
      System.out.println("Ooops");
    }
    fmt.close();

    return date;
  }

  @Override
  public boolean writeData(Features feature) {
    feature.certificate_validity = validity;
    return feature.setFlag(FlagToParser.FLAGCERTIFICATE);
  }
}


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

  public ClientKeyExchangeMessage(byte[] array, int version) {
    lengthOfClientKey = array.length;
  }

  @Override
  public boolean writeData(Features feature) {
    feature.pkl = lengthOfClientKey;
    return feature.setFlag(FlagToParser.FLAGCLIENTKEYEXCHANGE);
  }
}