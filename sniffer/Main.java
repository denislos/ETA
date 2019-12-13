package mipt.information.defence;

import static mipt.information.defence.Decomposer.myHandler;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.Timer;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class Main {

  private static boolean isStarted = false;
  private static boolean online = false;
  private Pcap pcap = new Pcap();
  private StringBuilder errbuf = new StringBuilder();
  private List alldevs = new ArrayList();
  private static String folderpath = "C:/pcap";

  public static List<Features> listTls = null;
  public static ArrayList<SourceDestination> fragmentedPackets = null;
/////////////////////////////////////////////////////////////////////////////some configuration for online mode
  private int r = Pcap.findAllDevs(alldevs, errbuf);
  private int adp;
  private int snaplen = 64 * 1024;//we catch packets without truncation
  private int flags = Pcap.MODE_PROMISCUOUS;//catch all packets(Pcap.MODE_NON_PROMISCUOUS means that we catch packets only in chosen adapter)
  private int timeout = 100;
  public static int count = 0;
  public static int globalcount = 0;
  public static int countOfTls = 0;

  public static BufferedWriter fileBuf = null;

  private JButton btnStartOffline = new JButton("Start Offline");
  private JComboBox adapterList = new JComboBox();

  String [] nbAdapterStrings = {"0", "1"};
  String [] nbAdpStrings = {"0", "1"};

  public static boolean isOnline() {
    return online;
  }

  public class MyFrame extends JFrame {

    public class MyPanel extends JPanel {
      private boolean isReady = false;
      private JLabel label = new JLabel("Adapter is not chosen");
      private JButton btnStartOnline = new JButton("Start Online");
      private JButton btnExit = new JButton("Exit");
      private JButton btnStopOnline = new JButton("Stop Online");


      private ActionListener act = new ActionListener(){
        @Override
        public void actionPerformed(ActionEvent e) {
          if (!isReady) {
            return;
          }
          listTls = new ArrayList<>();
          fragmentedPackets = new ArrayList<>();
          switch (e.getActionCommand()) {
            case "beginOnline":
              online = true;
              btnStartOffline.setEnabled(false);
              btnStartOnline.setEnabled(false);
              adapterList.setEnabled(false);
              btnStopOnline.setEnabled(true);
              isStarted = true;
              break;
            case "beginOffline":
              online = false;
              btnStartOffline.setEnabled(false);
              btnStartOnline.setEnabled(false);
              adapterList.setEnabled(false);
              isStarted = true;
              break;
            case "quit":
              isStarted = false;
              closeWindow();
              break;
            case "stopOnline":
              isStarted = false;
              btnStopOnline.setEnabled(false);
              btnStartOnline.setEnabled(false);
              btnStartOffline.setEnabled(true);
              adapterList.setEnabled(true);
              System.out.println(adp + " device close");
              label.setText("Adapter is not chosen");
              pcap.close();
          }
        }
      };

      class ethListEventListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
          JComboBox cb = (JComboBox)e.getSource();//chosen string in combobox

          adp = cb.getSelectedIndex();//get adapter number

          PcapIf device = (PcapIf) alldevs.get(adp);//get device by adapter in list

          pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);//open this adapter live

          if (pcap == null) {
            System.out.println("Error while opening device for capture: " + errbuf.toString());
            return;
          }

          label.setOpaque(true);
          label.setText(nbAdapterStrings[adp]);
          btnStartOnline.setEnabled(true);
        }
      }

      private void CreateBtn(JButton btn, String command, String tip) {
        btn.setToolTipText(tip);
        btn.setVerticalTextPosition(AbstractButton.CENTER);
        btn.setHorizontalTextPosition(AbstractButton.LEADING);
        btn.setActionCommand(command);
        btn.addActionListener(this.act);
      }
      MyPanel() {
        Dimension size = new Dimension(800, 650);
        this.setPreferredSize(size);
        this.setLayout(null);

        this.label.setBounds(590, 245, 200, 30);

        adapterList.setBounds(10,25,300,20);
        adapterList.addActionListener(new ethListEventListener());
        adapterList.setEnabled(true);

        this.CreateBtn(btnStartOffline, "beginOffline", "Click this button to begin processing offline");
        this.CreateBtn(this.btnStartOnline, "beginOnline", "Click this button to begin processing online");
        this.CreateBtn(this.btnExit, "quit", "Click this button to quit processing");
        this.CreateBtn(this.btnStopOnline, "stopOnline", "Click this button to stop processing");
        btnStartOffline.setBounds(590, 285, 200, 30);
        this.btnStartOnline.setBounds(590, 325, 200, 30);
        this.btnStopOnline.setBounds(590, 365, 200, 30);
        this.btnExit.setBounds(590, 405, 200, 30);
        btnStartOnline.setEnabled(false);
        btnStopOnline.setEnabled(false);


        this.add(this.label);
        this.add(adapterList);
        this.add(btnStartOffline);
        this.add(this.btnStartOnline);
        this.add(this.btnExit);
        this.add(this.btnStopOnline);

        this.setFocusable(true);
        isReady = true;
      }

      private void closeWindow(){
        this.setVisible(false);
        System.exit(0);
      }
    }

    public MyFrame() {
      if (r != Pcap.OK) {
        System.err.printf("Can't read list of devices, error is %s", errbuf
            .toString());
        return;
      }
      System.out.println("Network devices found:");
      int i = 0;
      for (Iterator it = alldevs.iterator(); it.hasNext();) {
        PcapIf device = (PcapIf) it.next();
        String description =
            (device.getDescription() != null) ? device.getDescription()
                : "No description available";
        // записать название адаптера в строку
        nbAdapterStrings[i] = description + "\n";
        nbAdpStrings[i] = description;
        //dv = dv + nbAdapterStrings[i];
        // список адаптеров в adapterList
        adapterList.addItem(nbAdapterStrings[i]);
        i++;
      }
      // список адаптеров в input
      //input.setText(dv);
      this.setTitle("Sniffer/decomposer");
      this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);//closes window when close is clicked
      MyPanel panel = new MyPanel();
      this.setResizable(false);
      this.getContentPane().add(panel);//add content to window
      this.pack();//set window size to canvas size
      this.setLocationRelativeTo(null);//set window to center
      this.setVisible(true);
    }
  }

  public class MainThread extends Thread {

    @Override
    public void run() {
      while(true)
      {
        try{
          sleep(1);
          if(isStarted) {//
            if (online) {
              pcap.loop(1, myHandler, errbuf);
            } else {
              File file = new File(folderpath);
              File[] files = file.listFiles();
              FileWriter fileJson = new FileWriter("C:\\json\\Good_traffic.json");
              fileBuf = new BufferedWriter(fileJson);
              fileBuf.write("[\n");
              for (File f : files) {
                String FILENAME = folderpath + "/" + f.getName();
                pcap = Pcap.openOffline(FILENAME, errbuf);//Making Pcap object an opening pcap file in offline mode and passing pcap filename and StringBuilder object to the function
                if (pcap == null) {
                  throw new IOException(errbuf.toString());
                }
                pcap.loop(-1, myHandler, errbuf);
                System.out.println("File : " + f.getName()
                    + " Number of Packets : "
                    + count);
                // Global counter to count the total number
                // of packets in all pcap file
                count = 0;
              }
              System.out.println("Secure Packets in folder : " + countOfTls);
              countOfTls = 0;
              fileBuf.write("\n]");
              fileBuf.flush();
              fileBuf = null;
              isStarted = false;
              btnStartOffline.setEnabled(true);
              adapterList.setEnabled(true);
            }
          }
        }catch(InterruptedException | IOException e){
          e.printStackTrace();
        }
      }
    }
  }

  public static void main(String[] args) {
    Main main = new Main();
    Main.MyFrame window = main.new MyFrame();
    Main.MainThread thread = main.new MainThread();
    thread.run();
  }
}
