package io.github.tylerhackett.certgen.online;

import io.github.tylerhackett.certgen.AppBase;
import io.github.tylerhackett.certgen.Command;
import io.github.tylerhackett.certgen.Option;
import io.github.tylerhackett.certgen.Params;
import io.github.tylerhackett.crypto.CAUtils;
import io.github.tylerhackett.crypto.PrivateCredential;
import io.github.tylerhackett.driver.Driver;
import io.github.tylerhackett.util.Reporter;
import io.github.tylerhackett.util.StringUtils;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;


public class App extends AppBase {

	private static final String CA_ONLINE_PROPERTIES_FILE = "/config.properties";

	private static final Logger logger = Logger.getLogger(App.class.getCanonicalName());

	/*
	 * Passwords for CA keystore
	 */
	protected char[] keystorePasswordOnlineCA;
	protected char[] keyPasswordOnlineCA;

	/*
	 * Files for online CA keystore, initialized by the offline cert manager.
	 */

	protected File keystoreOnlineCAFile;

	/*
	 * Distinguished names for CA certificates.
	 */
	protected X500Name caOnline;

	@Override
	protected void initialize() throws IOException {
		/*
		 * Passwords
		 */
		String password = System.getenv(Params.CA_ONLINE_KEYSTORE_PASSWORD);
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
		keystoreOnlineCAFile = new File(Params.CA_ONLINE_KEYSTORE_FILENAME);

		/*
		 * Distinguished names
		 * https://stackoverflow.com/a/38234094
		 */
		try (InputStream inp = getClass().getResourceAsStream(CA_ONLINE_PROPERTIES_FILE)) {
			Properties properties = new Properties();
			properties.load(inp);
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
		case GENERATE_CLIENT_CERT:
			genClientCert(options);
			break;
		default:
			throw new IllegalArgumentException("Unrecognized command: " + command.name());
		}
	}

	private static final String GENERATE_CLIENT_CERT_HELP = HelpMessage("  %s --%s csr-file --%s cert-file \n" +
					"\t\t[--%s dns-name] [--%s duration]",
			Command.GENERATE_CLIENT_CERT, Option.CLIENT_CSR_FILE, Option.CERT_FILE, Option.DNS_NAME, Option.DURATION);

	private static final String SHOW_CERTIFICATES_HELP = HelpMessage("  %s", Command.SHOW_CERTIFICATES);

	public void displayHelp() {
		say("");
		say("Online Commands:");
		say(GENERATE_CLIENT_CERT_HELP);
		say(SHOW_CERTIFICATES_HELP);
		say("");
		flush();
	}
	
	/**
	 * Input a CSR from a client (received as a PEM file for the cert manager).
	 */
	public static PKCS10CertificationRequest internCSR(String pem) throws GeneralSecurityException {
		try {
			ByteArrayInputStream pemStream = new ByteArrayInputStream(pem.getBytes(StringUtils.CHARSET));
			Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
			PEMParser pemParser = new PEMParser(pemReader);

			Object parsedObj = pemParser.readObject();
			pemParser.close();

			if (parsedObj instanceof PKCS10CertificationRequest) {
				return (PKCS10CertificationRequest) parsedObj;
			} else {
				throw new GeneralSecurityException("Expected certification request: " + parsedObj);
			}
		} catch (IOException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	public static PKCS10CertificationRequest internCSR(File pemFile) throws GeneralSecurityException {
		try {
			return internCSR(readString(pemFile));
		} catch (IOException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Generate a client cert from a CSR
	 */
	protected void genClientCert(Map<Option,String> options) throws Exception {
		File clientCsrFile = getCsrFile(options);

		File certFile = getCertFile(options);

		String clientDns = options.get(Option.DNS_NAME);  // May be null
		
		long duration = getDuration(options, Params.CLIENT_CERT_DURATION);

		long certId = getRandom().nextLong();
		
		PKCS10CertificationRequest request = internCSR(clientCsrFile);
		
		KeyStore keystoreApp = load(keystoreOnlineCAFile, keystorePasswordOnlineCA, Params.CA_ONLINE_KEYSTORE_TYPE);

		PrivateCredential ca = getCredential(keystoreApp, Params.CA_ONLINE_ALIAS, keyPasswordOnlineCA);
	
		X509Certificate cert = null;
		
		// Generate client cert from CSR using online CA key, write to certFile
		cert = CAUtils.createClientCert(certId, ca.getPrivateKey(), ca.getCertificate()[0],
				request, clientDns, duration);

		externCertificate(cert, certFile);

		showCertificateInfo("Client cert: ", cert);
		
	}
	
	/**
	 * Display information about all credentials.
	 */
	protected void showCerts(Map<Option, String> options) throws Exception {
		say("Showing credentials that are used online.");
		say("");

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
