package ch.schmucki;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class Main {

    public static void main(String[] args) {
	    RainbowTable table = new RainbowTable(7, 2000, 2000, true);
	    String result = table.lookupHash(Constants.hash);
        if(result == null) {
            System.out.println(String.format("No password found for hash: %s", Constants.hash));
        } else {
            System.out.println(String.format("Found password: %s, for hash: %s", result, Constants.hash));
        }
    }
}
