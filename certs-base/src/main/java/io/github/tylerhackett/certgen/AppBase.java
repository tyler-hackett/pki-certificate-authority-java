package io.github.tylerhackett.certgen;

import io.github.tylerhackett.crypto.PrivateCredential;
import io.github.tylerhackett.driver.Driver;
import io.github.tylerhackett.util.DateUtils;
import io.github.tylerhackett.util.FileUtils;
import io.github.tylerhackett.util.Reporter;
import io.github.tylerhackett.util.StringUtils;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;



public abstract class AppBase implements Driver.Callback<Command, Option> {

	/**
	 * Read passwords and certificate names, and init keystore and password file names.
	 * Called by generic initialization (see below).
	 */
	protected abstract void initialize() throws IOException;

	protected Reporter reporter;

//	/**
//	 * Base directory with subdirectories for online and offline keystores and truststores.
//	 * Only relevant for offline and online CA cert managers, not for the client cert manager.
//	 */
//	protected File baseDir;
//
//
//	protected void initBasedir(File base, File namesFile) throws IOException {
//		baseDir = base;
//		FileUtils.ensureFolder(baseDir);
//	}

//	/**
//	 * Generate the name of a backup file.
//	 */
//	public static String backupFilename(String name) {
//		String[] parts = name.split("\\.");
//		String prefix = parts[0];
//		String suffix = parts[1];
//
//		Date date = new Date();
//		GregorianCalendar calendar = new GregorianCalendar();
//		calendar.setTime(date);
//
//		DecimalFormat twoDigitDecimalFormat = new DecimalFormat("00");
//		DecimalFormat fourDigitDecimalFormat = new DecimalFormat("0000");
//
//		String year = fourDigitDecimalFormat.format(calendar.get(Calendar.YEAR));
//		String month = twoDigitDecimalFormat.format(calendar.get(Calendar.MONTH) + 1);
//		String day = twoDigitDecimalFormat.format(calendar.get(Calendar.DAY_OF_MONTH));
//		String hour = twoDigitDecimalFormat.format(calendar.get(Calendar.HOUR_OF_DAY));
//		String minute = twoDigitDecimalFormat.format(calendar.get(Calendar.MINUTE));
//		String second = twoDigitDecimalFormat.format(calendar.get(Calendar.SECOND));
//
//		StringBuilder sb = new StringBuilder(prefix);
//
//		sb.append("-")
//		  .append(year)
//		  .append("-")
//		  .append(month)
//		  .append("-")
//		  .append(day)
//		  .append("-")
//		  .append(hour)
//		  .append("-")
//		  .append(minute)
//		  .append("-")
//		  .append(second)
//		  .append('.')
//		  .append(suffix);
//
//		return sb.toString();
//	}
//
//	/**
//	 * Save a backup of a file.
//	 */
//	protected void backup(Path file) throws IOException {
//		if (Files.exists(file)) {
//			String parentDir = file.getParent().getFileName().toString();
//			String backupName = backupFilename(file.getFileName().toString());
//			Files.copy(file, Paths.get(baseDir.getPath(), Params.BACKUP_DIR, parentDir, backupName));
//		}
//	}
	
	/**
	 * Save the contents of the keystores after an update.
	 */
	public static void save(File store, char[] password, KeyStore keystore) throws GeneralSecurityException {
		try {
			OutputStream out = new FileOutputStream(store);
			keystore.store(out, password);
			out.close();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}

	/**
	 * Save a keystore to disk, backing up the copy already there.
	 */
	protected void updateKeystore(File keystoreFile, KeyStore keystore, char[] password) throws GeneralSecurityException, IOException {
//		backup(keystoreFile.toPath());
		save(keystoreFile, password, keystore);
	}

	/**
	 * Load an individual keystore.
	 */
	protected KeyStore load(File store, char[] password, String keystoreType) throws GeneralSecurityException {
		try {
			KeyStore keystore = KeyStore.getInstance(keystoreType);
			if (!store.exists()) {
				reporter.info("Store does not exist, initializing " + store.getAbsolutePath());
				keystore.load(null, null);
			} else {
				InputStream in = new FileInputStream(store);
				keystore.load(in, password);
				in.close();
			}
			return keystore;
		} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}

	/**
	 * Downcast an array of certificates to X509 certificates.
	 */
	protected X509Certificate[] toX509Certificates(Certificate[] certificates) {
		if (certificates == null) {
			return null;
		}
		X509Certificate[] x509certificates = new X509Certificate[certificates.length];
		for (int i=0; i<certificates.length; i++) {
			x509certificates[i] = (X509Certificate)certificates[i];
		}
		return x509certificates;
	}
	
	/**
	 * Retrieve a credential from a keystore.
	 */
	protected PrivateCredential getCredential(KeyStore keystore, String alias, char[] password) throws GeneralSecurityException {
		try {
			PrivateKey key = null;
			X509Certificate[] chain = null;
			
			// Get key and cert chain from the keystore
			key = (PrivateKey) keystore.getKey(alias, password);
			chain = toX509Certificates(keystore.getCertificateChain(alias));
			
			return new PrivateCredential(chain, key, alias);
		} catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
			throw new GeneralSecurityException("Security exception", e);

		}
	}

	private static final RSAKeyGenParameterSpec RSA_KEY_SPECS =
			new RSAKeyGenParameterSpec(Params.ASYMMETRIC_KEY_LENGTH, RSAKeyGenParameterSpec.F4);

	/**
	 * Create a random RSA key pair.
	 */
	public static KeyPair generateKeyPair() throws GeneralSecurityException {
		try {
			// Generate a new RSA key pair (using BC as provider)
			// RSA_KEY_SPECS specifies the specs for the key....
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(RSA_KEY_SPECS, new SecureRandom());
			return generator.generateKeyPair();
			
		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}

	/**
	 * Regenerate an RSA public key from the private key.
	 */
	public static PublicKey fromPrivateKey(PrivateKey privateKey) throws GeneralSecurityException {
		BigInteger exponent;
		BigInteger modulus;
		if (privateKey instanceof RSAPrivateKey) {
			// Generate the public key from the RSA private key
			RSAPrivateKey rsaPrivate = (RSAPrivateKey) privateKey;
			modulus = rsaPrivate.getModulus();
			if (rsaPrivate instanceof RSAPrivateCrtKey) {
				exponent = ((RSAPrivateCrtKey) rsaPrivate).getPublicExponent();
			} else {
				exponent = RSAKeyGenParameterSpec.F4;
			}
			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
			return keyFactory.generatePublic(publicKeySpec);
		}
		throw new GeneralSecurityException("Trying to get the public key from a non-RSA private key.");
	}

	protected SecureRandom random;

	protected void initRandom() {
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Unable to find random algorithm SHA1PRNG.", e);
		}
	}

	public SecureRandom getRandom() throws GeneralSecurityException {
		if (random == null) {
			throw new GeneralSecurityException("Unable to find random algorithm SHA1PRNG.");
		}
		return random;
	}

	protected long getRandomLong() throws GeneralSecurityException {
		return getRandom().nextLong();
	}

	/**
	 * Output is sent to the reporter.
	 */
	public static String HelpMessage(String msg, Command cmd, Option... options) {
		String[] args = new String[options.length+1];
		args[0] = cmd.value();
		for (int ix=0; ix<options.length; ix++) {
			args[ix+1] = options[ix].value();
		}
		return String.format(msg, args);
	}

	protected void say(String msg) {
		reporter.say(msg);
	}

	protected void flush() {
		reporter.flush();
	}

	
	protected static void writeString(File f, String s) throws IOException {
		Writer wr = new BufferedWriter(FileUtils.openOutputCharFile(f));
		wr.append(s);
		wr.close();
	}
	
	protected static String readString(File f) throws IOException {
		BufferedReader rd = new BufferedReader(FileUtils.openInputCharFile(f));
		StringBuilder sb = new StringBuilder();
		String line = rd.readLine();
		while (line != null) {
			sb.append(line);
			sb.append('\n');
			line = rd.readLine();
		}
		rd.close();
		return sb.toString();
	}

	/**
	 * Get the duration for a certificate as a command option.
	 */
	protected long getDuration(Map<Option, String> options, long defaultDuration) {
		String duration = options.get(Option.DURATION);
		if (duration == null) {
			return defaultDuration;
		}
		return Long.parseLong(duration);
	}

	protected X500Name getDistinguishedName(Map<Option, String> options) throws IOException {
		String distName = options.get(Option.DIST_NAME);
		if (distName == null) {
			throw new IOException("Required: distinguished name.");
		}
		return new X500Name(BCStyle.INSTANCE, distName);	}

	/**
	 * Get the file for a certificate as a command option.
	 */
	protected File getCertFile(Map<Option,String> options) throws IOException {
		String f = options.get(Option.CERT_FILE);
		if (f == null) {
			throw new IOException("Required: name of certificate file.");
		}
		return new File(f);
	}

	/**
	 * Get the file for a certificate as a command option.
	 */
	protected File getCsrFile(Map<Option,String> options) throws IOException {
		String f = options.get(Option.CLIENT_CSR_FILE);
		if (f == null) {
			throw new IOException("Required: name of CSR file.");
		}
		return new File(f);
	}

	/**
	 * Get the file for a keystore as a command option.
	 */
	protected File getKeystoreFile(Map<Option,String> options) throws IOException {
		String f = options.get(Option.KEYSTORE_FILE);
		if (f == null) {
			throw new IOException("Required: name of keystore file.");
		}
		return new File(f);
	}

	/**
	 * Get the password for a keystore as a command option.
	 */
	protected char[] getKeystorePassword(Map<Option,String> options) throws IOException {
		String pwd = options.get(Option.KEYSTORE_PASSWORD);
		if (pwd == null) {
			throw new IOException("Required: password for keystore file.");
		}
		return pwd.toCharArray();
	}

	/**
	 * Get the password for a keystore as a command option.
	 */
	protected char[] getKeyPassword(Map<Option,String> options) throws IOException {
		String pwd = options.get(Option.KEYSTORE_KEY_PASSWORD);
		if (pwd == null) {
			throw new IOException("Required: password for key in keystore file.");
		}
		return pwd.toCharArray();
	}

	/**
	 * Get the alias for a key in a keystore as a command option.
	 */
	protected String getKeyAlias(Map<Option,String> options) throws IOException {
		String alias = options.get(Option.ALIAS);
		if (alias == null) {
			throw new IOException("Required: alias for key in keystore.");
		}
		return alias;
	}

	/**
	 * Get the file for a truststore as a command option.
	 */
	protected File getTruststoreFile(Map<Option,String> options) throws IOException {
		String f = options.get(Option.TRUSTSTORE_FILE);
		if (f == null) {
			throw new IOException("Required: name of truststore file.");
		}
		return new File(f);
	}

	/**
	 * Get the password for a truststore as a command option.
	 */
	protected char[] getTruststorePassword(Map<Option,String> options) throws IOException {
		String pwd = options.get(Option.TRUSTSTORE_PASSWORD);
		if (pwd == null) {
			throw new IOException("Required: password for truststore file.");
		}
		return pwd.toCharArray();
	}


	/**
	 * Persist certificates and CSRs in PEM format to a string.
	 */
	protected static String extern(Object cert) throws GeneralSecurityException {
		try {
			StringWriter sbuf = new StringWriter();
			JcaPEMWriter wr = new JcaPEMWriter(sbuf);
			wr.writeObject(cert);
			wr.flush();
			wr.close();
			String externCert = sbuf.toString();
			sbuf.close();
			return externCert;
		} catch (IOException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Persist certificates and CSRs in PEM format to a file.
	 */
	protected static void extern(Object cert, File file) throws GeneralSecurityException {
		try {
			writeString(file, extern(cert));
		} catch (IOException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Write and read a certificate stored in external (PEM) format.
	 */
	public static String externCertificate(Certificate cert) throws GeneralSecurityException {
		return extern(cert);
	}
	
	public static void externCertificate(Certificate cert, File file) throws GeneralSecurityException {
		extern(cert, file);
	}

	public static Certificate internCertificate(InputStream in) throws GeneralSecurityException {
		try {
			CertificateFactory certFactory;
			certFactory = CertificateFactory.getInstance("X.509","BC");
			return certFactory.generateCertificate(in);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}

	public static Certificate internCertificate(File file) throws GeneralSecurityException {
		try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
			return internCertificate(in);
		} catch (IOException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Get the fingerprint of a cryptographic value (cert, public key, etc).
	 */
	public static byte[] getFingerprint(byte[] cert) throws GeneralSecurityException {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
            return md.digest(cert);
		} catch (NoSuchAlgorithmException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}

	public static byte[] getCertFingerprint(X509Certificate cert) throws GeneralSecurityException {
		return getFingerprint(cert.getEncoded());
	}
	
	protected static String digits = "0123456789abcdef";

	/**
	 * Return length many bytes of the passed in byte array as a hex string.
	 */
	public static String toHex(byte[] data, int length) {
		if (data == null) {
			return null;
		}
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i != length; i++) {
			int v = data[i] & 0xff;
			buf.append(digits.charAt(v >> 4));
			buf.append(digits.charAt(v & 0xf));
		}
		return buf.toString();
	}
	
	/**
	 * Return the passed in byte array as a hex string.
	 */
	public static String toHex(byte[] data) {
		return toHex(data, data.length);
	}
	
	/**
	 * Display hex string as sequence of pairs of hex digits.
	 */
	public static String displayHex(byte[] b) {
		if (b == null) {
			return null;
		}
		String s = toHex(b);
		int len = s.length();
		if (s.length() <= 2 || s.length() % 2 != 0) {
			throw new IllegalArgumentException("Trivial edge case in displayHex.");
		}
		StringBuilder sb = new StringBuilder();
		sb.append(s.charAt(0));
		sb.append(s.charAt(1));
		for (int i = 2; i < len-1; i+=2) {
			sb.append(':');
			sb.append(s.charAt(i));
			sb.append(s.charAt(i+1));
		}
		return sb.toString();
	}	

	protected void showCredentialInfo(String certName, PrivateCredential credential) throws GeneralSecurityException {
		say("================================================================================");
		say(certName);
		byte[] fp = getFingerprint(fromPrivateKey(credential.getPrivateKey()).getEncoded());
		say("SHA1: " + displayHex(fp));
		for (X509Certificate certificate : credential.getCertificate()) {
			say("--------------------------------------------------------------------------------");
			showCertificateInfo(certificate);
		}
		say("");
	}
	
	@SuppressWarnings("unused")
	protected void showCertificateInfo(String certName, X509Certificate certificate) throws GeneralSecurityException {
		say("================================================================================");
		say(certName);
		byte[] fp = getFingerprint(certificate.getPublicKey().getEncoded());
		say("SHA1: " + displayHex(fp));
		say("--------------------------------------------------------------------------------");
		showCertificateInfo(certificate);
		say("");
	}
	
	protected void showCertificateInfo(X509Certificate certificate) throws GeneralSecurityException {
		say(String.format("Issuer: %s", certificate.getIssuerX500Principal().getName()));
		say(String.format("Subject: %s", certificate.getSubjectX500Principal().getName()));
		say("Serial number: "+certificate.getSerialNumber().toString(16));
		say("SHA1: " + displayHex(getCertFingerprint(certificate)));
		Date before = certificate.getNotBefore();
		Date after = certificate.getNotAfter();
		say(String.format("Valid from %s to %s", DateUtils.dateTimeFormat(before), DateUtils.dateTimeFormat(after)));
	}
	

	protected Map<String,Command> commands;

	protected Map<String,Option> options;

	/**
	 * Super constructor for all cert managers.  Set the JCE provider.
	 */
	public AppBase(Reporter reporter) {

		Security.addProvider(new BouncyCastleProvider());

		initRandom();

		this.reporter = reporter;

		commands = new HashMap<String, Command>();
		for (Command command : Command.values()) {
			commands.put(command.value(), command);
		}
				
		options = new HashMap<String, Option>();
		for (Option option : Option.values()) {
			options.put(option.value(), option);
		}

	}

	/*
	 * Callbacks for the REPL driver.
	 */
	@Override
	public Command lookupCommand(String arg) {
		return commands.get(arg);
	}

	@Override
	public Option lookupOption(String arg) {
		return options.get(arg);
	}

	@Override
	public boolean isParameterized(Option option) {
		return option.isParam();
	}

	/**
	 * Called by main program in each of the cert managers, to initialize and start the REPL driver.
	 */
	protected void execute(Driver<Command,Option> driver, String[] args) throws Exception {
		Map<Option,String> options = new HashMap<Option,String>();
		driver.parseOptions(args, options);

		initialize();

		if (options.containsKey(Option.SCRIPT_FILE)) {
			String scriptName = options.get(Option.SCRIPT_FILE);
			BufferedReader rd = new BufferedReader(new InputStreamReader(new FileInputStream(scriptName), StringUtils.CHARSET));
			driver.batch(rd);
		} else {
			driver.interactive();
		}
	}

//	/**
//	 * Initialize taking into account any command line arguments to override defaults.
//	 */
//	private void initialize(Map<Option,String> options) throws IOException {
//		File passwordsFile;
//		File namesFile;
//
//		String baseDir = options.get(Option.BASE_DIR);
//		if (baseDir == null) {
//			baseDir = Paths.get("").toAbsolutePath().toString();
//		}
//		File baseDirFile = new File(baseDir);
//
//		String passwords = options.get(Option.PASSWORD_FILE);
//		if (passwords != null) {
//			passwordsFile = new File(passwords);
//		} else {
//			passwordsFile = null;
//		}
//
//		String names = options.get(Option.NAMES_FILE);
//		if (names != null) {
//			namesFile = new File(names);
//		} else {
//			namesFile = null;
//		}
//
//		initCA(baseDirFile, passwordsFile, namesFile);
//
//	}

}
