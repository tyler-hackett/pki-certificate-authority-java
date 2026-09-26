package io.github.tylerhackett.certgen.offline;

import io.github.tylerhackett.certgen.AppBase;
import io.github.tylerhackett.certgen.Command;
import io.github.tylerhackett.certgen.Option;
import io.github.tylerhackett.certgen.Params;
import io.github.tylerhackett.crypto.CAUtils;
import io.github.tylerhackett.crypto.PrivateCredential;
import io.github.tylerhackett.driver.Driver;
import io.github.tylerhackett.util.Reporter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;


public class App extends AppBase {

	private static final String CA_OFFLINE_PROPERTIES_FILE = "/config.properties";

	private static final Logger logger = Logger.getLogger(App.class.getCanonicalName());

	/*
	 * Passwords for keystores and truststores.
	 */
	protected char[] keystorePasswordRootCA;
	protected char[] keyPasswordRootCA;
	protected char[] keystorePasswordOnlineCA;
	protected char[] keyPasswordOnlineCA;

	/*
	 * Files for CA keystores and truststores
	 */
	protected File keystoreRootCAFile;
	protected File keystoreOnlineCAFile;

	/*
	 * Distinguished names for CA certificates.
	 */
	protected X500Name caRoot;
	protected X500Name caOnline;


	@Override
	protected void initialize() throws IOException {

		/*
		 * Passwords
		 */
		String password = System.getenv(Params.CA_ROOT_KEYSTORE_PASSWORD);
		if (password == null) {
			throw new IllegalArgumentException("Missing environment variable: " + Params.CA_ROOT_KEYSTORE_PASSWORD);
		}
		keystorePasswordRootCA = password.toCharArray();

		password = System.getenv(Params.CA_ROOT_KEY_PASSWORD);
		if (password == null) {
			throw new IllegalArgumentException("Missing environment variable: " + Params.CA_ROOT_KEY_PASSWORD);
		}
		keyPasswordRootCA = password.toCharArray();

		password = System.getenv(Params.CA_ONLINE_KEYSTORE_PASSWORD);
		if (password == null) {
			throw new IllegalArgumentException("Missing environment variable: " + Params.CA_ONLINE_KEYSTORE_PASSWORD);
		}
		keystorePasswordOnlineCA = password.toCharArray();

		password = System.getenv(Params.CA_ONLINE_KEY_PASSWORD);
		if (password == null) {
			throw new IllegalArgumentException("Missing environment variable: " + Params.CA_ONLINE_KEY_PASSWORD);
		}
		keyPasswordOnlineCA = password.toCharArray();

		/*
		 * Keystore filenames
		 */
		keystoreRootCAFile = new File(Params.CA_ROOT_KEYSTORE_FILENAME);

		keystoreOnlineCAFile = new File(Params.CA_ONLINE_KEYSTORE_FILENAME);

		/*
		 * Distinguished names
		 * https://stackoverflow.com/a/38234094
		 */
		try (InputStream inp = getClass().getResourceAsStream(CA_OFFLINE_PROPERTIES_FILE)) {
			Properties properties = new Properties();
			properties.load(inp);
			caRoot = new X500Name(RFC4519Style.INSTANCE, properties.getProperty(Params.CA_ROOT));
			caOnline = new X500Name(RFC4519Style.INSTANCE, properties.getProperty(Params.CA_ONLINE));
		}

	}

	/**
	 * Called by the REPL driver to execute a command line from the REPL.
	 */
	@Override
	public void execute(Command command, Map<Option, String> options) throws Exception {
		if (command == null) {
			displayHelp();
			return;
		}
		switch (command) {
			case HELP:
				displayHelp();
				break;
			case SHOW_CERTIFICATES:
				showCerts(options);
				break;
			case GENERATE_CA_ROOT:
				genCaRoot(options);
				break;
			case EXPORT_CA_ROOT_CERT:
				exportCaRootCert(options);
				break;
			case GENERATE_SERVER_KEYSTORE:
				genServerKeystore(options);
				break;
			case GENERATE_TRUSTSTORE:
				genTruststore(options);
				break;
			case GENERATE_CA_ONLINE_CERT:
				genOnlineCaCert(options);
				break;
			case EXPORT_CA_ONLINE_CERT:
				exportOnlineCaCert(options);
				break;
			default:
				throw new IllegalArgumentException("Unrecognized command: " + command.name());
		}
	}

	private static final String GENERATE_CA_ROOT_HELP = HelpMessage("  %s [--%s duration]",
			Command.GENERATE_CA_ROOT, Option.DURATION);

	private static final String EXPORT_CA_ROOT_CERT_HELP = HelpMessage("  %s --%s cert-file",
			Command.EXPORT_CA_ROOT_CERT, Option.CERT_FILE);

	private static final String GENERATE_SERVER_KEYSTORE_HELP =
			HelpMessage("  %s --%s server-dist-name --%s server-domain-name --%s keystore-file --%s keystore-password --%s key-password --%s key-alias [--%s duration]",
			             Command.GENERATE_SERVER_KEYSTORE, Option.DIST_NAME, Option.DNS_NAME, Option.KEYSTORE_FILE,
						 Option.KEYSTORE_PASSWORD, Option.KEYSTORE_KEY_PASSWORD, Option.ALIAS, Option.DURATION);

	private static final String GENERATE_TRUSTSTORE_HELP =
			HelpMessage("  %s --%s truststore-file --%s truststore-password",
					Command.GENERATE_TRUSTSTORE, Option.TRUSTSTORE_FILE, Option.TRUSTSTORE_PASSWORD);

	private static final String GENERATE_CA_ONLINE_CERT_HELP = HelpMessage("  %s [--%s duration]",
			Command.GENERATE_CA_ONLINE_CERT, Option.DURATION);

	private static final String EXPORT_CA_ONLINE_CERT_HELP = HelpMessage("  %s --%s cert-file",
			Command.EXPORT_CA_ONLINE_CERT, Option.CERT_FILE);

	private static final String SHOW_CERTIFICATES_HELP = HelpMessage("  %s", Command.SHOW_CERTIFICATES);

	protected void displayHelp() {
		say("");
		say("Offline commands:");
		say(GENERATE_CA_ROOT_HELP);
		say(EXPORT_CA_ROOT_CERT_HELP);
		say(GENERATE_SERVER_KEYSTORE_HELP);
		say(GENERATE_TRUSTSTORE_HELP);
		say(GENERATE_CA_ONLINE_CERT_HELP);
		say(EXPORT_CA_ONLINE_CERT_HELP);
		say(SHOW_CERTIFICATES_HELP);
		say("");
		flush();
	}
	
	/**
	 * Generate root CA for server CA for server SSL, stored in the offline keystore.
	 */
	protected void genCaRoot(Map<Option,String> options) throws Exception {
		if (keystoreRootCAFile.exists()) {
			reporter.error("Root CA keystore already exists!");
			return;
		}
		
		long duration = getDuration(options, Params.CA_ROOT_DURATION);
		
		KeyStore keystoreRoot = load(keystoreRootCAFile, keystorePasswordRootCA, Params.CA_ROOT_KEYSTORE_TYPE);
		
		KeyPair kp = generateKeyPair();
		
		long certId = getRandom().nextLong();
		
		X509Certificate cert = null;
		// Generate root CA cert (see CAUtils)
		cert = CAUtils.createCaRootCert(certId, caRoot, kp, duration);

		Certificate[] chain = new Certificate[]{cert};

		keystoreRoot.setKeyEntry(Params.CA_ROOT_ALIAS, kp.getPrivate(), keyPasswordRootCA, chain);
		
		updateKeystore(keystoreRootCAFile, keystoreRoot, keystorePasswordRootCA);

		PrivateCredential credential = getCredential(keystoreRoot, Params.CA_ROOT_ALIAS, keyPasswordRootCA);
		showCredentialInfo("Root CA credential:", credential);
	}
	

	/**
	 * Export CA root cert as a PEM file.
	 */
	protected void exportCaRootCert(Map<Option,String> options) throws Exception {
		File certFile = getCertFile(options);
		
		// Write CA root cert to a PEM file: load the root keystore, get the root CA private credential,
		// convert to string (see externCertificate), then write that to the certFile
		KeyStore keystoreRoot = load(keystoreRootCAFile, keystorePasswordRootCA, Params.CA_ROOT_KEYSTORE_TYPE);
		PrivateCredential cred = getCredential(keystoreRoot, Params.CA_ROOT_ALIAS, keyPasswordRootCA);
		writeString(certFile, externCertificate(cred.getCertificate()[0]));

	}

	/**
	 * Generate and save a server keystore.
	 */
	protected void genServerKeystore(Map<Option,String> options) throws Exception {
		String serverDNS = options.get(Option.DNS_NAME);
		if (serverDNS == null) {
			reporter.error("Missing server DNS.");
			return;
		}

		X500Name serverDistName = getDistinguishedName(options);

		long duration = getDuration(options, Params.SERVER_CERT_DURATION);

		KeyStore keystoreRoot = load(keystoreRootCAFile, keystorePasswordRootCA, Params.CA_ROOT_KEYSTORE_TYPE);

		PrivateCredential root = getCredential(keystoreRoot, Params.CA_ROOT_ALIAS, keyPasswordRootCA);

		KeyPair kp = generateKeyPair();

		long certId = getRandom().nextLong();

		X509Certificate cert = null;

		// Create server cert and cert chain
		cert = CAUtils.createServerCert(certId, root.getPrivateKey(), root.getCertificate()[0],
				serverDistName, serverDNS, kp.getPublic(), duration);

		Certificate[] chain = new Certificate[]{cert, root.getCertificate()[0]};

		File keystoreServerFile = getKeystoreFile(options);
		char[] keystorePassword = getKeystorePassword(options);
		char[] keyPassword = getKeyPassword(options);
		String keyAlias = getKeyAlias(options);
		/*
		 * Save credential in the server keystore (use load and save)
		 */
		KeyStore keystoreServer = load(keystoreServerFile, keystorePassword, Params.SERVER_KEYSTORE_TYPE);
		keystoreServer.setKeyEntry(keyAlias, kp.getPrivate(), keyPassword, chain);
		save(keystoreServerFile, keystorePassword, keystoreServer);

		/*
		 * Display the credential just created
		 */
		PrivateCredential cred = getCredential(keystoreServer, keyAlias, keyPassword);
		showCredentialInfo("Server credential:", cred);

	}

	/**
	 * Generate and save a server keystore.
	 */
	protected void genTruststore(Map<Option,String> options) throws Exception {

		File truststoreFile = getTruststoreFile(options);
		char[] truststorePassword = getTruststorePassword(options);
		KeyStore truststore = load(truststoreFile, truststorePassword, Params.SERVER_TRUSTSTORE_TYPE);

		KeyStore keystoreRoot = load(keystoreRootCAFile, keystorePasswordRootCA, Params.CA_ROOT_KEYSTORE_TYPE);
		PrivateCredential cred = getCredential(keystoreRoot, Params.CA_ROOT_ALIAS, keyPasswordRootCA);
		truststore.setCertificateEntry(Params.CA_ROOT_ALIAS, cred.getCertificate()[0]);
		showCertificateInfo("Root CA cert:", cred.getCertificate()[0]);

		KeyStore keystoreOnline = load(keystoreOnlineCAFile, keystorePasswordOnlineCA, Params.CA_ONLINE_KEYSTORE_TYPE);
		cred = getCredential(keystoreOnline, Params.CA_ONLINE_ALIAS, keyPasswordOnlineCA);
		truststore.setCertificateEntry(Params.CA_ONLINE_ALIAS, cred.getCertificate()[0]);
		showCertificateInfo("Online CA cert:", cred.getCertificate()[0]);

		save(truststoreFile, truststorePassword, truststore);
	}


	/**
	 * Generate private key for online CA for client certs, stored in the online CA keystore.
	 */
	protected void genOnlineCaCert(Map<Option,String> options) throws Exception {
		long duration = getDuration(options, Params.CA_ONLINE_CERT_DURATION);

		KeyStore keystoreOffline = load(keystoreRootCAFile, keystorePasswordRootCA, Params.CA_ROOT_KEYSTORE_TYPE);

		PrivateCredential root = getCredential(keystoreOffline, Params.CA_ROOT_ALIAS, keyPasswordRootCA);

		KeyPair kp = generateKeyPair();

		long certId = getRandom().nextLong();

		X509Certificate cert = null;
		// Create online CA cert
		cert = CAUtils.createOnlineCaCert(certId, root.getPrivateKey(), root.getCertificate()[0],
				caOnline, kp.getPublic(), duration);

		Certificate[] chain = new Certificate[]{cert, root.getCertificate()[0]};

		KeyStore keystoreOnlineCA = null;
		/*
		 * Save the credentials in the online keystore (use load and updateKeystore)
		 */
		keystoreOnlineCA = load(keystoreOnlineCAFile, keystorePasswordOnlineCA, Params.CA_ONLINE_KEYSTORE_TYPE);
		keystoreOnlineCA.setKeyEntry(Params.CA_ONLINE_ALIAS, kp.getPrivate(), keyPasswordOnlineCA, chain);
		updateKeystore(keystoreOnlineCAFile, keystoreOnlineCA, keystorePasswordOnlineCA);

		/*
		 * Display the credential just created
		 */
		PrivateCredential cred = getCredential(keystoreOnlineCA, Params.CA_ONLINE_ALIAS, keyPasswordOnlineCA);
		showCredentialInfo("Online CA credetial:", cred);
	}

	/**
	 * Export online CA cert as a PEM file.
	 */
	protected void exportOnlineCaCert(Map<Option,String> options) throws Exception {
		File certFile = getCertFile(options);
		PrivateCredential cred = null;

		// Get online CA cert from online CA keystore and extract credential
		KeyStore keystoreOnlineCA = load(keystoreOnlineCAFile, keystorePasswordOnlineCA, Params.CA_ONLINE_KEYSTORE_TYPE);
		cred = getCredential(keystoreOnlineCA, Params.CA_ONLINE_ALIAS, keyPasswordOnlineCA);

		writeString(certFile, externCertificate(cred.getCertificate()[0]));
	}



	/**
	 * Display information about all private keys.
	 */
	protected void showCerts(Map<Option, String> options) throws Exception {
		say("Showing credentials that are updated offline.");
		say("");
		if (keystoreRootCAFile.exists()) {
			KeyStore keystoreRootCA = load(keystoreRootCAFile, keystorePasswordRootCA, Params.CA_ROOT_KEYSTORE_TYPE);
			PrivateCredential root = getCredential(keystoreRootCA, Params.CA_ROOT_ALIAS, keyPasswordRootCA);
			showCredentialInfo("CA Root Credential:", root);
		}

		if (keystoreOnlineCAFile.exists()) {
			KeyStore keystoreOnlineCA = load(keystoreOnlineCAFile, keystorePasswordOnlineCA, Params.CA_ONLINE_KEYSTORE_TYPE);
			PrivateCredential onlineCa = getCredential(keystoreOnlineCA, Params.CA_ONLINE_ALIAS, keyPasswordOnlineCA);
			showCredentialInfo("CA Online Credential:", onlineCa);
		}

	}


	public static void main(String[] args) {

		Reporter reporter = Reporter.createReporter();

		App app = new App(reporter);

		Driver<Command,Option> driver = new Driver<Command,Option>(reporter, app);

		try {
			app.execute(driver, args);
		} catch (Exception e) {
			reporter.error(e.getMessage(), logger, e);
		}

	}

	public App(Reporter reporter) {
		super(reporter);
	}

}
