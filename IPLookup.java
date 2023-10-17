import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class IPLookup {
    public static void lookup(String ipAddress) {
        String[] links = {
                "https://www.virustotal.com/gui/ip-address/" + ipAddress,
                "https://talosintelligence.com/reputation_center/lookup?search=" + ipAddress,
                "https://otx.alienvault.com/indicator/ip/" + ipAddress,
                "https://www.shodan.io/host/" + ipAddress,
                "https://www.abuseipdb.com/check/" + ipAddress
        };

        for (String link : links) {
            try {
                Desktop.getDesktop().browse(new URI(link));
                Thread.sleep(250);
            } catch (IOException | URISyntaxException | InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        while (true) {
            System.out.print("Enter IP: ");
            String ipAddress = scanner.next();
            String exitStatement = "q";
            if (ipAddress.equals(exitStatement)) {
                System.out.println("exiting");
                break;
            }
            System.out.println("Looking up IP " + ipAddress);
            lookup(ipAddress);
        }
        scanner.close();
    }
}