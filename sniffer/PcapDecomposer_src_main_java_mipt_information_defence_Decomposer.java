package mipt.information.defence;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Decomposer {

  static List<Features> listTls = new ArrayList<>();
  static String folderpath = "C:/pcap";
  static double count = 0;
  static double countOfTls = 0;
  static double globalcount = 0;
  private static JHeaderPool headerPool = new JHeaderPool();
  private static ArrayList<SourceDestination> fragmented = new ArrayList<>();
  public static void main(String[] args) throws IOException {
    File file = new File(folderpath);
    File[] files = file.listFiles();

    for (File f : files) {
      String FILENAME = folderpath + "/" + f.getName();
      StringBuilder errorBuf = new StringBuilder();
      Pcap pcap = Pcap.openOffline(FILENAME, errorBuf);//Making Pcap object an opening pcap file in offline mode and passing pcap filename and StringBuilder object to the function
      if (pcap == null) {
        throw new IOException(errorBuf.toString());
      }
      // Here pcap object is used to start a loop
      // for capturing each  packet of an
      // each pcap file(as a pcap file can
      // have many packets) one at a time, here -1
      // indicates eof(end of file) i.e
      // until every packet is captured execute the
      // loop, we can also give some value
      // instead of -1 which will indicate the
      // number of packets to execute
      // in each pcap file
      //final TLSContext tlsContext = new TLSContext();
      try {
        pcap.loop(-1, new JPacketHandler<StringBuilder>() {
          // nextPacket is override function
          // of JPacketHandler( Handler which is
          // use to receive fully decoded packets)
          public void nextPacket(JPacket packet, StringBuilder errorBuf) {
            //THERE WILL BE SOME CODE
            // counter to count the number of packet
            // in each pcap file
            count++;
            if (!packet.hasHeader(new Tcp())){
              return;
            }
            int sourcePort = packet.getHeader(new Tcp()).source();
            int destinationPort = packet.getHeader(new Tcp()).destination();
            if ((sourcePort == 443) || (sourcePort == 9001) || (destinationPort == 443) || (destinationPort == 9001)){
              byte[] payload = packet.getHeader(new Tcp()).getPayload();
              if (payload.length == 0) {
                return;
              }
              String sIp = org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(new Ip4()).source());
              String dIp = org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(new Ip4()).destination());
              System.out.println("\nSource ip: " + sIp+ "\nDestination ip: " + dIp);
              System.out.print("Payload: ");
              if (payload[0] == 22) {
                System.out.print("Handshake version: ");
                System.out.println(payload[1] + " " + payload[2]);
                int tlsIter = 5;
                //while (tlsIter < payload.length) {

                //}
              } else if (payload[0] == 23) {
                System.out.println("Application");
              } else if (payload[0] == 24) {
                System.out.println("Heartbeat");
              } else if (payload[0] == 21) {
                System.out.println("Alert");
              } else if (payload[0] == 20) {
                System.out.println("ChangeCipherSpec");
              } else {
                System.out.println("Not TLS");
                countOfTls--;
              }
              countOfTls++;

            }

          }
        }, errorBuf);
      } catch (NullPointerException e) {
        e.printStackTrace();
      }
      System.out.println("File : " + f.getName()
          + " Number of Packets : "
          + count);

      // Global counter to count the total number
      // of packets in all pcap file
      globalcount = globalcount + count;
      count = 0;
    }
    System.out.println("Total Packets in folder : " + globalcount);
    System.out.println("Secure Packets in folder : " + countOfTls);
  }
  public static void AnalyseHeaders(JPacket packet, int i) {
    final int id = packet.getHeaderIdByIndex(i);

    final JHeader header = headerPool.getHeader(id);
    if (!header.getName().equals("Tls")) {
      return;
    }
    System.out.println("Header: " + packet.getHeaderByIndex(i, header).getName());

    for (int j = 0; j < packet.getHeaderByIndex(i, header).getFields().length; j++) {

    }

    final JHeader[] subHeaders = header.getSubHeaders();
    for (int j = 0; j < subHeaders.length; j++){
      AnalyseHeaders(packet, j);
    }
  }
}