package mipt.information.defence;

import static mipt.information.defence.Main.fileBuf;
import static mipt.information.defence.Main.fragmentedPackets;
import static mipt.information.defence.Main.isOnline;
import static mipt.information.defence.Main.listTls;
import static mipt.information.defence.Main.count;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
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

  public static final JPacketHandler<StringBuilder> myHandler = new JPacketHandler<StringBuilder>() {
    // nextPacket is override function
    // of JPacketHandler( Handler which is
    // use to receive fully decoded packets)
    public void nextPacket(JPacket packet, StringBuilder errorBuf) {
      count++;
      if (!packet.hasHeader(new Tcp())) {
        return;
      }
      int sourcePort = packet.getHeader(new Tcp()).source();
      int destinationPort = packet.getHeader(new Tcp()).destination();
      if ((sourcePort == 443) || (sourcePort == 9001) || (destinationPort == 443) || (
          destinationPort == 9001)) {
        byte[] payload = packet.getHeader(new Tcp()).getPayload();
        if (payload.length == 0) {
          return;
        }
        String sIp = org.jnetpcap.packet.format.FormatUtils
            .ip(packet.getHeader(new Ip4()).source());
        String dIp = org.jnetpcap.packet.format.FormatUtils
            .ip(packet.getHeader(new Ip4()).destination());
        //System.out.println("\nSource ip: " + sIp + "   Source port: " + sourcePort + "\nDestination ip: " + dIp + "   Destination port: " + destinationPort);
        int fragmentedIter = isFragmented(sIp, dIp, sourcePort, destinationPort);

        if (fragmentedIter != -1) {
          byte[] addArray = fragmentedPackets.get(fragmentedIter).getFragmentedData();
          byte[] temp = payload;
          payload = new byte[addArray.length + temp.length];
          System.arraycopy(addArray, 0, payload, 0,
              addArray.length);//concatenate multiple payload into one
          System.arraycopy(temp, 0, payload, addArray.length, temp.length);
          fragmentedPackets.remove(fragmentedIter);
        }

        if (payload[0] == 22) {
          int version = payload[2];
          if (payload.length < 6) {//inadequate but possible
            SourceDestination fragmentedOne = new SourceDestination(sourcePort, sIp,
                destinationPort, dIp, payload);
            fragmentedPackets.add(fragmentedOne);
            return;
          }
          //System.out.print("Handshake version: ");
          //System.out.println(payload[1] + " " + payload[2]);
          //System.out.print("Length of current part: ");
          int lengthOfPacket = 0;
          int lengthOfMsg;
          int messageType;
          int tlsIter = 5;

          lengthOfPacket += (payload[4] >= 0) ? payload[4] : payload[4] + 256;
          lengthOfPacket += (payload[3] >= 0) ? (payload[3]) * 256 : (payload[3] + 256) * 256;

          //System.out.println(lengthOfPacket);

          int sessionIter;
          for (sessionIter = 0; sessionIter < listTls.size(); sessionIter++) {
            Features current = listTls.get(sessionIter);
            if (checkSession(sIp, dIp, sourcePort, destinationPort,
                current.sourceIp, current.destinationIp, current.source_port, current.dest_port)) {
              break;
            }
          }
          Features session;
          if (sessionIter == listTls.size()) {
            session = new Features();
            session.source_port = sourcePort;
            session.dest_port = destinationPort;
            session.sourceIp = sIp;
            session.destinationIp = dIp;
            session.version = version;
            listTls.add(session);
          } else {
            session = listTls.get(sessionIter);
          }

          while (tlsIter < payload.length) {
            if ((tlsIter + 5 > payload.length) || (payload[tlsIter] == 22)) {
              byte[] remainer = new byte[payload.length - tlsIter];
              System.arraycopy(payload, tlsIter, remainer, 0, payload.length - tlsIter);
              SourceDestination fragmentedOne = new SourceDestination(sourcePort, sIp,
                  destinationPort, dIp, remainer);
              fragmentedPackets.add(fragmentedOne);
              return;
            }
            messageType = payload[tlsIter];

            if (TlsMessage.isSupported(messageType)) {
              System.out.println(TlsMessage.getMsgType(messageType));
              lengthOfMsg = getLengthOfMsg(payload, tlsIter);
              if (tlsIter + lengthOfMsg + 4 > payload.length) {
                byte[] remainer = new byte[payload.length - tlsIter + 5];
                remainer[0] = 0x16;
                remainer[1] = 0;
                remainer[2] = 0;
                remainer[3] = 0;
                remainer[4] = 0;
                System.arraycopy(payload, tlsIter, remainer, 5, payload.length - tlsIter);
                SourceDestination fragmentedOne = new SourceDestination(sourcePort, sIp,
                    destinationPort, dIp, remainer);
                fragmentedPackets.add(fragmentedOne);
                return;
              }

              byte[] msgArray = new byte[lengthOfMsg];
              System.arraycopy(payload, tlsIter + 4, msgArray, 0, lengthOfMsg);
              TlsMessage message = TlsMessage
                  .getMessage(TlsMessage.getMsgType(messageType), msgArray, version);
              try {
                if (message.writeData(session)) {
                  if (!isOnline()){
                    session.parseToJson(fileBuf);
                  } else {
                    session.parseToOneJson();
                  }
                  listTls.remove(session);
                }
              } catch (NoSuchFieldException | IllegalAccessException | IOException e) {
                e.printStackTrace();
              }
            } else {
              lengthOfMsg = 1;
              lengthOfMsg +=
                  (payload[tlsIter + 4] >= 0) ? payload[tlsIter + 4] : payload[tlsIter + 4] + 256;
              lengthOfMsg += (payload[tlsIter + 3] >= 0) ? (payload[tlsIter + 3]) * 256
                  : (payload[tlsIter + 3] + 256) * 256;
            }

            tlsIter += lengthOfMsg + 4;
          }
        } else if (payload[0] == 23) {
          //System.out.println("Application");
        } else if (payload[0] == 24) {
          //System.out.println("Heartbeat");
        } else if (payload[0] == 21) {
          //System.out.println("Alert");
        } else if (payload[0] == 20) {
          //System.out.println("ChangeCipherSpec");
        } else {
          //System.out.println("Not TLS");
          Main.countOfTls--;
        }
        Main.countOfTls++;

      }

    }
  };

  public static boolean checkSession(String sIpCurrent, String dIpCurrent, int sourcePortCurrent,
      int destinationPortCurrent,
      String sIpAnother, String dIpAnother, int sourcePortAnother, int destinationPortAnother) {
    if (sIpCurrent.equals(sIpAnother) &&
        dIpCurrent.equals(dIpAnother) &&
        (sourcePortCurrent == sourcePortAnother) &&
        (destinationPortCurrent == destinationPortAnother)) {
      return true;
    } else if (sIpCurrent.equals(dIpAnother) &&
        dIpCurrent.equals(sIpAnother) &&
        (sourcePortCurrent == destinationPortAnother) &&
        (destinationPortCurrent == sourcePortAnother)) {
      return true;
    } else {
      return false;
    }
  }

  public static int isFragmented(String sIpCurrent, String dIpCurrent, int sourcePortCurrent,
      int destinationPortCurrent) {
    for (int i = 0; i < fragmentedPackets.size(); i++) {
      if ((fragmentedPackets.get(i).getSourceIp().equals(sIpCurrent)) &&
          (fragmentedPackets.get(i).getDestinationIp().equals(dIpCurrent)) &&
          (fragmentedPackets.get(i).getSourcePort() == sourcePortCurrent) &&
          (fragmentedPackets.get(i).getDestinationPort() == destinationPortCurrent)) {
        return i;
      }
    }
    return -1;
  }

  public static int getLengthOfMsg(byte[] payload, int tlsIter) {
    int lengthOfMsg = 0;
    lengthOfMsg += (payload[tlsIter + 3] >= 0) ? payload[tlsIter + 3] : payload[tlsIter + 3] + 256;
    lengthOfMsg += (payload[tlsIter + 2] >= 0) ? (payload[tlsIter + 2]) * 256
        : (payload[tlsIter + 2] + 256) * 256;
    lengthOfMsg += (payload[tlsIter + 1] >= 0) ? (payload[tlsIter + 1]) * 256 * 256
        : (payload[tlsIter + 1] + 256) * 256 * 256;
    return lengthOfMsg;
  }
}