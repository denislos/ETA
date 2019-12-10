package mipt.information.defence;

public enum MsgType{
  HelloRequest(0),
	ClientHello(1),
	ServerHello(2),
	NewSessionTicket(4),
	Certificate(11),
	ServerKeyExchange(12),
	CertificateRequest(13),
	ServerHelloDone(14),
	CertificateVerify(15),
	ClientKeyExchange(16),
	Finished(20);

  public final int code;

  public final int getCode() {
    return code;
  }

  MsgType(int code) {
    this.code = code;
  }
}
