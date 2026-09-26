package io.github.tylerhackett.certgen;

public class Params {

    /*
     * Passwords passed in environment variables
     */
    public static final String CA_ROOT_KEYSTORE_PASSWORD = "CA_ROOT_KEYSTORE_PASSWORD";
    public static final String CA_ROOT_KEY_PASSWORD = "CA_ROOT_KEY_PASSWORD";
    public static final String CA_ONLINE_KEYSTORE_PASSWORD = "CA_ONLINE_KEYSTORE_PASSWORD";
    public static final String CA_ONLINE_KEY_PASSWORD = "CA_ONLINE_KEY_PASSWORD";

    /*
     * Properties in distinguished names files.
     */
    public static final String CA_ROOT = "ca.root";
    public static final String CA_ONLINE = "ca.online";

    /*
     * Keystore aliases
     */
    // CA root (in the offline keystore)
    public static final String CA_ROOT_ALIAS = "ca-root";

    // Online CA for app client certs (in the online CA keystore).
    public static final String CA_ONLINE_ALIAS = "ca-online";

    /*
     * Default durations.
     */
    public static final int ONE_YEAR = 365 * 24;
    public static final long SERVER_CERT_DURATION = ONE_YEAR;
    public static final long CLIENT_CERT_DURATION = ONE_YEAR;
    public static final long CA_ONLINE_CERT_DURATION = 5 * ONE_YEAR;
    public static final long CA_ROOT_DURATION = 10 * ONE_YEAR;

    /*
     * Keystore types.
     */
    // For root CA key.
    public static final String CA_ROOT_KEYSTORE_TYPE = "PKCS12";

    // Online keystores and truststores
    public static final String CA_ONLINE_KEYSTORE_TYPE = "PKCS12";
    public static final String SERVER_KEYSTORE_TYPE = "PKCS12";
    public static final String SERVER_TRUSTSTORE_TYPE = "PKCS12";
    public static final String CLIENT_KEYSTORE_TYPE = "PKCS12";

    /**
     * Files:
     */
    public static final String CA_ROOT_KEYSTORE_FILENAME = "caroot.p12";
    public static final String CA_ONLINE_KEYSTORE_FILENAME = "ca.p12";
    public static final String NAMES_FILENAME = "names.properties";

    /*
     * Some crypto parameters.
     */
    public static final int ASYMMETRIC_KEY_LENGTH = 2048;
    // Recommended for X509 & default in BC

}
