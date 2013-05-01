package net.fatfredyy.wss4j.benchmarker.rsa;

import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class RSACertificatesPresenceTest {
	
	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA512");
	static List<String> keySizes = Arrays.asList("1024", "3072", "7680", "15360");

	@BeforeClass
	public static void beforeClass() {
		WSSConfig.init();
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new XMLDSigRI());
	}
	
	@Test
	public void rsaCertificatesForAllKeySizesShouldBePresent() throws Exception {
		for (String keySize : keySizes) {
			for (String certDigestAlg : digestAlgorithms) {
				checkPresence(keySize, certDigestAlg);
			}
		}
	}
	
	private void checkPresence(String size, String certDigestAlg) throws Exception {
		Properties rsaMerlinProperties = createRSAMerlinProperties(size, certDigestAlg);
		CryptoFactory.getInstance(rsaMerlinProperties);
	}

	private static Properties createRSAMerlinProperties(String size, String certDigestAlg) {
		Properties cryptoProps = new Properties();
		cryptoProps.put("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.type", "pkcs12");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.provider", "BC");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.password", "132456");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.alias", "certificate");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.file",
				"keys/ks_rsa_" + size + "_" + certDigestAlg + ".p12");

		return cryptoProps;
	}
}
