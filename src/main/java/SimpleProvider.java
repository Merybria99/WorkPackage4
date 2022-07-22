import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;


public class SimpleProvider {
    public static void main(String[] args) {
        String providerName = "BC";
        Security.addProvider(new BouncyCastleProvider());

        if (Security.getProvider(providerName) == null)
            System.out.println(providerName + " provider not installed");
        else
            System.out.println(providerName + " is installed.");

    }
}
                  