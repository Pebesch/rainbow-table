package ch.schmucki;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class RainbowTable {
    private int passwordLength;
    private int numberOfPasswords;
    private int chainLength;
    private boolean verbose;
    private MessageDigest md;
    private Map<String, String> plainTextToHash;
    Logger logger = Logger.getLogger("MyLog");
    FileHandler fh;

    public RainbowTable(int passwordLength, int numberOfPasswords, int chainLength, boolean verbose) {
        this.passwordLength = passwordLength;
        this.numberOfPasswords = numberOfPasswords;
        this.chainLength = chainLength;
        this.verbose = verbose;
        try {
            this.md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {

            // This block configure the logger with handler and formatter
            fh = new FileHandler("C:/tmp/RainbowTable.log");
            logger.addHandler(fh);
            SimpleFormatter formatter = new SimpleFormatter();
            fh.setFormatter(formatter);
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        plainTextToHash = generatePasswords();
    }

    // Generates all end reduced values and stores the pair <PlainText, EndReduce>
    private Map<String, String> generatePasswords() {
        Map<String, String> map = new HashMap<>();

        if(verbose) {
            logger.info(String.valueOf(Constants.countAllowedChars()));
            logger.info(String.valueOf(numberOfPasswords / Constants.countAllowedChars()));
            logger.info(String.valueOf(numberOfPasswords % Constants.countAllowedChars()));
        }

        // Creates all passwords and calculates hashes and reduces
        for(int i = 0; i < numberOfPasswords; i++) {
            String initialPassword = generatePassword(i);
            String password = initialPassword;
            for(int j = 0; j < chainLength; j++) {
                BigInteger nextHash = hashPassword(password);
                password = reducePassword(nextHash, j);
            }
            if(verbose) logger.info(String.format("Added password %s", password));
            map.put(initialPassword, password);
        }

        return map;
    }

    // Generates a password for a given index
    private String generatePassword(int index) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < passwordLength; i++) sb.append("0");

        int bitPosition = passwordLength - 1;

        while(index > 0 && bitPosition >= 0) {
            // Get character for position := position mod |chars|
            char charAtPosition = Constants.allowedChars[index % Constants.countAllowedChars()];
            // Replace at position
            sb.setCharAt(bitPosition, charAtPosition);
            // Decrease index
            index /= Constants.countAllowedChars();
            // Decrease bit position
            bitPosition--;
        }

        if(verbose) logger.info(sb.toString());
        return sb.toString();
    }

    // Hashes a password with the instanciated md
    private BigInteger hashPassword(String password) {
        md.update(password.getBytes());
        BigInteger hash = new BigInteger(1, md.digest());
        if(verbose) logger.info(bigIntToString(hash));
        return hash;
    }

    // Conversion Function
    private String bigIntToString(BigInteger hash) {
        return hash.toString(16);
    }

    // Conversion Function
    private BigInteger stringToBigInteger(String hash) {
        return new BigInteger(hash, 16);
    }

    // Reduces a hash at a given level
    private String reducePassword(BigInteger hash, int level) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < passwordLength; i++) sb.append("0");

        hash = hash.add(BigInteger.valueOf(level));
        for(int i = 1; i <= passwordLength; i++) {
            BigInteger ri = hash.mod(BigInteger.valueOf(Constants.countAllowedChars()));
            hash = hash.divide(BigInteger.valueOf(Constants.countAllowedChars()));
            sb.setCharAt(passwordLength - i, Constants.allowedChars[ri.intValue()]);
        }
        if(verbose) logger.info(sb.toString());
        return sb.toString();
    }

    public String lookupHash(String hash) {
        String password = null;

        // Loop backwards
        for(int i = chainLength - 1; i >= 0; i--) {
            password = hash;
            // Go forth
            for(int j = i; j < chainLength; j++) {
                // Generate the next reduce
                String result = reducePassword(stringToBigInteger(password), j);

                // Collision Check
                if(plainTextToHash.containsValue(result)) {
                    for(String key : plainTextToHash.keySet()) {

                        String hashAtIndex = null;
                        String roundPassword = key;
                        for(int k = 0; k < i; k++) {
                            BigInteger nextHash = hashPassword(roundPassword);
                            hashAtIndex = bigIntToString(nextHash);
                            roundPassword = reducePassword(nextHash, k);
                        }
                        if(hashAtIndex.equals(Constants.hash) && !key.equals(result)) {
                            return null;
                        }
                    }
                    // If no collision was found return the password
                    return getKeyForValue(result);

                }
                // Go further
                password = bigIntToString(hashPassword(result));
            }
        }
        // If no result was found return null
        return null;
    }

    // Helper function for the map
    private String getKeyForValue(String value) {
        if(plainTextToHash.containsValue(value)) {
            for(Map.Entry<String, String> entry : plainTextToHash.entrySet()) {
                if(entry.getValue().equals(value)) return entry.getKey();
            }
        }
        return null;
    }
}
