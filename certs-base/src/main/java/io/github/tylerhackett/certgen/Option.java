package io.github.tylerhackett.certgen;

public enum Option {
    /*
     * Command-line options:
     */
    SCRIPT_FILE("scriptfile"),
    /*
     * Arguments:
     */
    CERT_FILE("cert"),
    DNS_NAME("dns"),
    DURATION("duration"),
    DIST_NAME("dn"),
    CLIENT_CSR_FILE("csr"),
    ALIAS("alias"),
    TRUSTSTORE_FILE("truststore"),
    TRUSTSTORE_PASSWORD("truststorepass"),
    KEYSTORE_FILE("keystore"),
    KEYSTORE_PASSWORD("keystorepass"),
    KEYSTORE_KEY_PASSWORD("keypass");

    private String value;
    private boolean param;

    private Option(String v) {
        value = v;
        param = true;
    }

    public String value() {
        return value;
    }

    public boolean isParam() {
        return param;
    }
}
