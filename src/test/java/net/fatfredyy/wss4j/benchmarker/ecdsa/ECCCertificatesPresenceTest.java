package net.fatfredyy.wss4j.benchmarker.ecdsa;

import java.security.Security;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class ECCCertificatesPresenceTest {

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA512");

	@BeforeClass
	public static void beforeClass() {
		WSSConfig.init();
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new XMLDSigRI());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void eccCertificatesForAllNamedCurvesShouldBePresent() throws Exception {
		Enumeration<String> namedCurves = ECNamedCurveTable.getNames();

		while (namedCurves.hasMoreElements()) {
			String curveName = namedCurves.nextElement();
			for (String certDigestAlg : digestAlgorithms) {
				checkPresence(curveName, certDigestAlg);
			}
		}
	}

	private void checkPresence(String curveName, String certDigestAlg) throws Exception {
		Properties ecdsaMerlinProperties = createECDSAMerlinProperties(curveName, certDigestAlg);
		CryptoFactory.getInstance(ecdsaMerlinProperties);
	}

	private static Properties createECDSAMerlinProperties(String curveName, String certDigestAlg) {
		Properties cryptoProps = new Properties();
		cryptoProps.put("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.type", "pkcs12");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.provider", "BC");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.password", "132456");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.alias", "certificate");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.file", "keys/ks_ec_" + curveName + "_" + certDigestAlg + ".p12");
		return cryptoProps;
	}

}
