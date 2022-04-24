package ch.schmucki;

public class Constants {
    // Hash provided by exercise
    public static String hash = "1d56a37fb6b08aa709fe90e12ca59e12";
    // Allowed chars for the password
    public static char[] allowedChars = new char[]{
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    };

    public static int countAllowedChars() {
        return allowedChars.length;
    }
}
