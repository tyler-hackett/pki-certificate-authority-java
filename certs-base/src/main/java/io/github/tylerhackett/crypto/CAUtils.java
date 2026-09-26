package io.github.tylerhackett.crypto;

import io.github.tylerhackett.util.DateUtils;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class CAUtils {
	
	/**
	 * For use by the server-side CA.
	 */
	
	public final static KeyUsage CA_USAGE;

	public final static KeyUsage END_USAGE;
	
	public final static KeyUsage CODE_SIGN_USAGE;
	
	public final static KeyUsage ENCRYPT_USAGE;
	
	public final static ExtendedKeyUsage CLIENT_USAGE_EXT;

	public final static ExtendedKeyUsage SERVER_USAGE_EXT;

	public final static ExtendedKeyUsage CODE_SIGN_USAGE_EXT;

	static {
		CA_USAGE = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign);
		END_USAGE = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.keyEncipherment);
		CODE_SIGN_USAGE = new KeyUsage(KeyUsage.digitalSignature);
		ENCRYPT_USAGE = new KeyUsage(KeyUsage.keyEncipherment);
		CLIENT_USAGE_EXT = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
		SERVER_USAGE_EXT = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
		CODE_SIGN_USAGE_EXT = new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning);
	}
	
	public static X500Name toX500Name(X500Principal principal) {
		// return X500Name.getInstance(principal.getEncoded());
		return new X500Name(RFC4519Style.INSTANCE, principal.getName());
	}

	/**
	 * Certificate signer.
	 */
	public static ContentSigner getContentSigner(PrivateKey privateKey) throws OperatorCreationException{
		return new JcaContentSignerBuilder("SHA512withRSA")
				.setProvider("BC")
				.build(privateKey);
	}

	/**
	 * Certificate verifier.
	 */
	public static ContentVerifierProvider getContentVerifier(PublicKey publicKey) throws OperatorCreationException {
		return new JcaContentVerifierProviderBuilder()
				.setProvider("BC")
				.build(publicKey);
	}
	
	/**
	 * Build a self-signed v1 certificate to bootstrap a client.
	 */
	public static X509Certificate createClientRootCert(long id, X500Name clientDn, KeyPair keyPair,
			long durationHours) throws GeneralSecurityException {
		try {
			// Generate self-signed v1 certificate
			Date notBefore = new Date();
			Date notAfter = new Date(notBefore.getTime() + durationHours * 60L * 60L * 1000L);
			X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(
					clientDn,
					BigInteger.valueOf(id),
					notBefore,
					notAfter,
					clientDn,
					keyPair.getPublic());
			ContentSigner signer = getContentSigner(keyPair.getPrivate());
			return new JcaX509CertificateConverter()
					.setProvider("BC")
					.getCertificate(certBuilder.build(signer));
		} catch (OperatorCreationException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Build a self-signed v3 certificate for the root CA.
	 */
	public static X509Certificate createCaRootCert(long id, X500Name caName, KeyPair keyPair,
			long durationHours) throws GeneralSecurityException {
		try {
			// Generate root CA self-signed v3 cert
			Date notBefore = new Date();
			Date notAfter = new Date(notBefore.getTime() + durationHours * 60L * 60L * 1000L);

			X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
					caName,
					BigInteger.valueOf(id),
					notBefore,
					notAfter,
					caName,
					keyPair.getPublic());

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			certBuilder.addExtension(Extension.keyUsage, true, CA_USAGE);
			certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
					extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
			certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));

			ContentSigner signer = getContentSigner(keyPair.getPrivate());
			return new JcaX509CertificateConverter()
					.setProvider("BC")
					.getCertificate(certBuilder.build(signer));
		} catch (NoSuchAlgorithmException | CertIOException | OperatorCreationException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Create an intermediate or end-entity certificate.
	 */
	private static X509Certificate createCert(long id, PrivateKey issuerKey, X509Certificate issuerCert,
			X500Name subjectName, PublicKey subjectKey, BasicConstraints basicConstraints, KeyUsage usage,
			ExtendedKeyUsage extendedUsage, GeneralNames sans, long durationHours) throws GeneralSecurityException {
		try {
			X509v3CertificateBuilder certBuilder = null;
			// Create the X509v3CertificateBuilder and add the extensions
			Date notBefore = new Date();
			Date notAfter = new Date(notBefore.getTime() + durationHours * 60L * 60L * 1000L);

			X500Name issuerName = toX500Name(issuerCert.getSubjectX500Principal());

			certBuilder = new JcaX509v3CertificateBuilder(
					issuerName,
					BigInteger.valueOf(id),
					notBefore,
					notAfter,
					subjectName,
					subjectKey);

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			if (basicConstraints != null) {
				certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
			}
			if (usage != null) {
				certBuilder.addExtension(Extension.keyUsage, true, usage);
			}
			if (extendedUsage != null) {
				certBuilder.addExtension(Extension.extendedKeyUsage, false, extendedUsage);
			}
			if (sans != null) {
				certBuilder.addExtension(Extension.subjectAlternativeName, false, sans);
			}
			certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
					extUtils.createSubjectKeyIdentifier(subjectKey));
			certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(issuerCert.getPublicKey()));
			
			ContentSigner signer = getContentSigner(issuerKey);
			return new JcaX509CertificateConverter()
				.setProvider("BC")
				.getCertificate(certBuilder.build(signer));
 		} catch (NoSuchAlgorithmException | CertIOException | OperatorCreationException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Create an intermediate certificate for online CA.
	 */
	public static X509Certificate createOnlineCaCert(long id, PrivateKey issuerKey, X509Certificate issuerCert,
			X500Name subjectName, PublicKey subjectKey, long durationHours) throws GeneralSecurityException {
		BasicConstraints basicConstraints = new BasicConstraints(0);
		return createCert(id, issuerKey, issuerCert, subjectName, subjectKey, basicConstraints, CA_USAGE, null, null, durationHours);
	}
	
	/**
	 * Create an end-user certificate for a server.
	 */
	public static X509Certificate createServerCert(long id, PrivateKey issuerKey, X509Certificate issuerCert,
			X500Name subjectName, String serverDNS, PublicKey subjectKey, long durationHours) throws GeneralSecurityException {
		GeneralName san = new GeneralName(GeneralName.dNSName, serverDNS);
		GeneralNames sans = new GeneralNames(new GeneralName[]{ san });
		BasicConstraints basicConstraints = new BasicConstraints(false);
		return createCert(id, issuerKey, issuerCert, subjectName, subjectKey, basicConstraints, END_USAGE,
				SERVER_USAGE_EXT, sans, durationHours);
	}
	
	/**
	 * Request a certificate from the CA certifying our signature.
	 */
	public static PKCS10CertificationRequest createCSR(X500Name subject, KeyPair keyPair, 
			String dnsAddress) throws GeneralSecurityException {
		try {
			PKCS10CertificationRequest request = null;
			// Generate CSR
			PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(
					subject, keyPair.getPublic());

			if (dnsAddress != null) {
				ExtensionsGenerator extGen = new ExtensionsGenerator();
				GeneralName san = new GeneralName(GeneralName.dNSName, dnsAddress);
				GeneralNames sans = new GeneralNames(new GeneralName[]{ san });
				extGen.addExtension(Extension.subjectAlternativeName, false, sans);
				requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
			}

			ContentSigner signer = getContentSigner(keyPair.getPrivate());
			request = requestBuilder.build(signer);
			if (!request.isSignatureValid(getContentVerifier(keyPair.getPublic()))) {
				throw new IllegalStateException("Certificate signing request failed to verify!");
			}
			return request;

		} catch (IOException | OperatorCreationException | PKCSException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
	/**
	 * Generate a client certificate from a CSR.
	 */
	public static X509Certificate createClientCert(long id, PrivateKey issuerKey, X509Certificate issuerCert,
			PKCS10CertificationRequest csr,  String dnsAddress, long durationHours)
			throws GeneralSecurityException {
		try {
			BasicConstraints basicConstraints = new BasicConstraints(false);
			PublicKey subjectKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();

			ContentVerifierProvider contentVerifier = getContentVerifier(subjectKey);
			if (!csr.isSignatureValid(contentVerifier)) {
				throw new GeneralSecurityException("Bad signature on certificate signing request: " + csr.getSubject());
			}

			X509v3CertificateBuilder certBuilder = null;
			// Generate client cert from the CSR (add DNS SAN if dnsAddress is provided)
			Date notBefore = new Date();
			Date notAfter = new Date(notBefore.getTime() + durationHours * 60L * 60L * 1000L);

			X500Name issuerName = toX500Name(issuerCert.getSubjectX500Principal());

			certBuilder = new JcaX509v3CertificateBuilder(
					issuerName,
					BigInteger.valueOf(id),
					notBefore,
					notAfter,
					csr.getSubject(),
					subjectKey);

			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
			certBuilder.addExtension(Extension.keyUsage, true, END_USAGE);
			certBuilder.addExtension(Extension.extendedKeyUsage, false, CLIENT_USAGE_EXT);
			certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
					extUtils.createSubjectKeyIdentifier(subjectKey));
			certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(issuerCert.getPublicKey()));

			if (dnsAddress != null) {
				GeneralName san = new GeneralName(GeneralName.dNSName, dnsAddress);
				GeneralNames sans = new GeneralNames(new GeneralName[]{ san });
				certBuilder.addExtension(Extension.subjectAlternativeName, false, sans);
			} else {
				Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
				if (attrs != null && attrs.length > 0) {
					Extensions csrExtensions = Extensions.getInstance(attrs[0].getAttrValues().getObjectAt(0));
					Extension sanExt = csrExtensions.getExtension(Extension.subjectAlternativeName);
					if (sanExt != null) {
						certBuilder.addExtension(sanExt);
					}
				}
			}
			ContentSigner signer = getContentSigner(issuerKey);
			
			return new JcaX509CertificateConverter()
							.setProvider("BC")
							.getCertificate(certBuilder.build(signer));

		} catch (NoSuchAlgorithmException | CertIOException | OperatorCreationException | PKCSException e) {
			throw new GeneralSecurityException("Security exception", e);
		}
	}
	
}
