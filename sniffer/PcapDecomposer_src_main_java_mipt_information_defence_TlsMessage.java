package mipt.information.defence;

abstract public class TlsMessage {
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
}

class ClientHelloMessage extends TlsMessage {

  public ClientHelloMessage(byte[] array) {
  }
}
class ServerHelloMessage extends TlsMessage {

  public ServerHelloMessage(byte[] array) {
  }
}

class CertificateMessage extends TlsMessage {

  public CertificateMessage(byte[] array) {
  }
}

class ServerKeyExchangeMessage extends TlsMessage {

  public ServerKeyExchangeMessage(byte[] array) {
  }
}

class ClientKeyExchangeMessage extends TlsMessage {

  public ClientKeyExchangeMessage(byte[] array) {
  }
}