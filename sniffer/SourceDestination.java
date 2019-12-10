package mipt.information.defence;

public class SourceDestination {
  private int sourcePort;
  private String sourceIp;
  private int destinationPort;
  private String destinationIp;
  private byte[] fragmentedData;

  public SourceDestination(int sourcePort, String sourceIp, int destinationPort,
      String destinationIp, byte[] fragmentedData) {
    this.sourcePort = sourcePort;
    this.sourceIp = sourceIp;
    this.destinationPort = destinationPort;
    this.destinationIp = destinationIp;
    this.fragmentedData = fragmentedData;
  }

  public int getSourcePort() {
    return sourcePort;
  }

  public void setSourcePort(int sourcePort) {
    this.sourcePort = sourcePort;
  }

  public String getSourceIp() {
    return sourceIp;
  }

  public void setSourceIp(String sourceIp) {
    this.sourceIp = sourceIp;
  }

  public int getDestinationPort() {
    return destinationPort;
  }

  public void setDestinationPort(int destinationPort) {
    this.destinationPort = destinationPort;
  }

  public String getDestinationIp() {
    return destinationIp;
  }

  public void setDestinationIp(String destinationIp) {
    this.destinationIp = destinationIp;
  }

  public byte[] getFragmentedData() {
    return fragmentedData;
  }

  public void setFragmentedData(byte[] fragmentedData) {
    this.fragmentedData = fragmentedData;
  }
}
