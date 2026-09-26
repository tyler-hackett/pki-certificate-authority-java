package io.github.tylerhackett.certgen.client;

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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;


public class App extends AppBase {

	private static final Logger logger = Logger.getLogger(App.class.getCanonicalName());

	protected void initialize() throws IOException {
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
		case GENERATE_CLIENT_ROOT:
			genClientRoot(options);
			break;
		case GENERATE_CSR:
			genClientCSR(options);
			break;
		case IMPORT_CLIENT_CERT:
			importClientCert(options);
			break;
		default:
			throw new IllegalArgumentException("Unrecognized command: " + command.name());
		}
	}

	private static final String GENERATE_CLIENT_ROOT_HELP =
			HelpMessage("  %s --%s dist-name --%s keystore \n" +
							"\t\t--%s keystore-password --%s key-password \n" +
							"\t\t--%s key-alias [--%s duration]",
					Command.GENERATE_CLIENT_ROOT, Option.DIST_NAME, Option.KEYSTORE_FILE,
					Option.KEYSTORE_PASSWORD, Option.KEYSTORE_KEY_PASSWORD, Option.ALIAS, Option.DURATION);

	private static final String GENERATE_CSR_HELP =
			HelpMessage("  %s --%s csr-file --%s keystore \n" +
							"\t\t--%s keystore-password --%s key-password \n" +
							"\t\t--%s key-alias [--%s dns-name]",
					Command.GENERATE_CSR, Option.CLIENT_CSR_FILE, Option.KEYSTORE_FILE,
					Option.KEYSTORE_PASSWORD, Option.KEYSTORE_KEY_PASSWORD, Option.ALIAS, Option.DNS_NAME);

	private static final String IMPORT_CLIENT_CERT_HELP =
			HelpMessage("  %s --%s cert-file --%s keystore \n" +
							"\t\t--%s keystore-password --%s key-password --%s key-alias",
					Command.IMPORT_CLIENT_CERT, Option.CERT_FILE, Option.KEYSTORE_FILE,
					Option.KEYSTORE_PASSWORD, Option.KEYSTORE_KEY_PASSWORD, Option.ALIAS);

	private static final String SHOW_CERTIFICATES_HELP = HelpMessage("  %s --%s keystore \n" +
							"\t\t--%s keystore-password --%s key-password --%s key-alias", Command.SHOW_CERTIFICATES,
					Option.KEYSTORE_FILE, Option.KEYSTORE_PASSWORD, Option.KEYSTORE_KEY_PASSWORD, Option.ALIAS);


	protected void displayHelp() {
		say("");
		say("Commands for client:");
		say(GENERATE_CLIENT_ROOT_HELP);
		say(GENERATE_CSR_HELP);
		say(IMPORT_CLIENT_CERT_HELP);
		say(SHOW_CERTIFICATES_HELP);
		say("");
		flush();
	}
	

	/**
	 * Generate initial v1 self-signed cert for a client.
	 */
	protected void genClientRoot(Map<Option,String> options) throws Exception {

		X500Name clientDn = getDistinguishedName(options);

		File clientKeystoreFile = getKeystoreFile(options);

		char[] clientKeystorePassword = getKeystorePassword(options);

		char[] clientKeyPassword = getKeyPassword(options);

		String clientKeyAlias = getKeyAlias(options);

		long duration = getDuration(options, Params.CLIENT_CERT_DURATION);

		long id = getRandomLong();
		KeyPair keyPair = generateKeyPair();
		
		// Create self-signed v1 cert and save in client keystore
		X509Certificate cert = CAUtils.createClientRootCert(id, clientDn, keyPair, duration);
		X509Certificate[] chain = { cert };
		KeyStore clientStore = load(clientKeystoreFile, clientKeystorePassword, Params.CLIENT_KEYSTORE_TYPE);
		clientStore.setKeyEntry(clientKeyAlias, keyPair.getPrivate(), clientKeyPassword, chain);
		save(clientKeystoreFile, clientKeystorePassword, clientStore);
	}

	/**
	 * Generate client CSR signed by their protected key
	 */
	protected void genClientCSR(Map<Option,String> options) throws Exception {

		File clientKeystoreFile = getKeystoreFile(options);

		char[] clientKeystorePassword = getKeystorePassword(options);

		char[] clientKeyPassword = getKeyPassword(options);

		File clientCsrFile = getCsrFile(options);

		String clientKeyAlias = getKeyAlias(options);

		// May be null
		String clientDns = options.get(Option.DNS_NAME);
		
		KeyStore clientStore = load(clientKeystoreFile, clientKeystorePassword, Params.CLIENT_KEYSTORE_TYPE);
		try {
			PKCS10CertificationRequest csr = null;

			// Generate a CSR signed by the client's private key
			PrivateCredential cred = getCredential(clientStore, clientKeyAlias, clientKeyPassword);
			PrivateKey privateKey = cred.getPrivateKey();
			PublicKey publicKey = fromPrivateKey(privateKey);
			KeyPair keyPair = new KeyPair(publicKey, privateKey);
			X500Name subject = CAUtils.toX500Name(cred.getCertificate()[0].getSubjectX500Principal());
			csr = CAUtils.createCSR(subject, keyPair, clientDns);

			
			extern(csr, clientCsrFile);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Import a client cert generated by a CSR
	 */
	protected void importClientCert(Map<Option,String> options) throws Exception {

		File clientKeystoreFile = getKeystoreFile(options);

		char[] clientKeystorePassword = getKeystorePassword(options);

		char[]  clientKeyPassword = getKeyPassword(options);

		File clientCertFile = getCertFile(options);

		String clientKeyAlias = getKeyAlias(options);
		
		KeyStore clientStore = load(clientKeystoreFile, clientKeystorePassword, Params.CLIENT_KEYSTORE_TYPE);
		try {
			// Import the cert from clientCertFile and store it in the clientStore
			PrivateKey privateKey = (PrivateKey) clientStore.getKey(clientKeyAlias, clientKeyPassword);
			X509Certificate clientCert = (X509Certificate) internCertificate(clientCertFile);
			X509Certificate[] chain = new X509Certificate[] { clientCert };
			clientStore.setKeyEntry(clientKeyAlias, privateKey, clientKeyPassword, chain);
			save(clientKeystoreFile, clientKeystorePassword, clientStore);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			throw new GeneralSecurityException("Security exception", e);
		}

	}
	
	/**
	 * Display information about all private keys.
	 */
	protected void showCerts(Map<Option, String> options) throws Exception {

		File clientKeystoreFile = getKeystoreFile(options);

		char[] clientKeystorePassword = getKeystorePassword(options);

		char[] clientKeyPassword = getKeyPassword(options);

		String clientKeyAlias = getKeyAlias(options);

		if (clientKeystoreFile.exists()) {
			KeyStore clientStore = load(clientKeystoreFile, clientKeystorePassword, Params.CLIENT_KEYSTORE_TYPE);
			PrivateCredential clientCert = getCredential(clientStore, clientKeyAlias, clientKeyPassword);
			showCredentialInfo("Client Credential:", clientCert);
		} else {
			reporter.error("No such client keystore: "+clientKeystoreFile.getAbsolutePath());
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
