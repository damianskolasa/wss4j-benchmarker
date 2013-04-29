package net.fatfredyy.wss4j.benchmarker.dsa;

import java.io.FileWriter;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import net.fatfredyy.wss4j.benchmarker.SOAPUtil;
import net.fatfredyy.wss4j.benchmarker.String2WSConstantsMapper;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class DSABenchmarker {
	
	private FileWriter fs;
	private FileWriter fv;

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA512");
	
	static List<String> keySizes = Arrays.asList("1024-160", "2048-224", "2048-256", "3072-256");
	
	private static final String SEP = ";";

	public DSABenchmarker() throws Exception {
		fs = new FileWriter("dsa_benchmark_sign.csv");
		fv = new FileWriter("dsa_benchmark_verify.csv");
	}

	@SuppressWarnings("unchecked")
	public void benchmark() throws Exception {
		fs.write("size;cert_digest;digest;time\n");
		fv.write("size;cert_digest;digest;time\n");
		for (String keySize : keySizes) {
			for (String certDigestAlg : digestAlgorithms) {
				for (String digestAlg : digestAlgorithms) {
					benchmarkLoop(keySize, certDigestAlg, String2WSConstantsMapper.string2WSconstantMap.get("DSA_" + digestAlg),
							String2WSConstantsMapper.string2WSconstantMap.get(digestAlg));
				}

			}

		}
	}

	private void benchmarkLoop(String size, String certDigest, String algSuit, String digest) throws Exception {
		System.out.println("Trying: " + size + ", " + certDigest + ", " + algSuit + ", " + digest);
		for (int i = 0; i < 10; i++) {
			banchmarkSignle(size, certDigest, algSuit, digest);
		}
		fs.flush();
		fv.flush();
	}

	public void banchmarkSignle(String size, String certDigest, String algSuit, String digest) throws Exception {
		Properties dsaMerlinProperties = createDSAMerlinProperties(size, certDigest);
		Crypto dsaCrypto = CryptoFactory.getInstance(dsaMerlinProperties);

		long start = System.currentTimeMillis();
		Document signedDoc = signSOAPMessage(dsaCrypto, algSuit, digest);
		long mid = System.currentTimeMillis();
		verifySOAPMessageSignature(dsaCrypto, signedDoc);
		long end = System.currentTimeMillis();

		fs.write(size + SEP + certDigest + SEP + digest + SEP + (mid - start));
		fv.write(size + SEP + certDigest + SEP + digest + SEP + (end - mid));
		
		System.gc();

	}

	private void verifySOAPMessageSignature(Crypto dsaCrypto, Document signedDoc) throws WSSecurityException, Exception {
		Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);

		AlgorithmSuite algorithmSuite = createDSAAlgorithmSuite();
		verify(securityHeader, algorithmSuite, dsaCrypto);
	}

	private Document signSOAPMessage(Crypto dsaCrypto, String signatureAlg, String digestAlg) throws Exception, WSSecurityException {
		WSSecSignature builder = new WSSecSignature();
		builder.setUserInfo("privateKey", "123456");
		builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
		builder.setSignatureAlgorithm(signatureAlg);
		builder.setDigestAlgo(digestAlg);

		Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
		WSSecHeader secHeader = new WSSecHeader();
		secHeader.insertSecurityHeader(doc);
		Document signedDoc = builder.build(doc, dsaCrypto, secHeader);
		return signedDoc;
	}

	private static AlgorithmSuite createDSAAlgorithmSuite() {
		AlgorithmSuite algorithmSuite = new AlgorithmSuite();
		algorithmSuite.addSignatureMethod(WSConstants.DSA_SHA1);
		algorithmSuite.addSignatureMethod(WSConstants.DSA_SHA256);
		algorithmSuite.addSignatureMethod(WSConstants.DSA_SHA384);
		algorithmSuite.addSignatureMethod(WSConstants.DSA_SHA512);
		algorithmSuite.setMinimumAsymmetricKeyLength(128);
		algorithmSuite.addC14nAlgorithm(WSConstants.C14N_EXCL_OMIT_COMMENTS);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA1);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA256);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA384);
		algorithmSuite.addDigestAlgorithm(WSConstants.SHA512);
		return algorithmSuite;
	}

	private List<WSSecurityEngineResult> verify(Element securityHeader, AlgorithmSuite algorithmSuite, Crypto sigVerCrypto)
			throws Exception {
		WSSecurityEngine secEngine = new WSSecurityEngine();
		RequestData data = new RequestData();
		data.setSigCrypto(sigVerCrypto);

		data.setAlgorithmSuite(algorithmSuite);

		WSSConfig wssConfig = WSSConfig.getNewInstance();
		wssConfig.setWsiBSPCompliant(false);
		data.setWssConfig(wssConfig);

		return secEngine.processSecurityHeader(securityHeader, data);
	}

	private static Properties createDSAMerlinProperties(String size, String certDigestAlg) {
		Properties cryptoProps = new Properties();
		cryptoProps.put("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.type", "pkcs12");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.provider", "BC");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.password", "132456");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.alias", "certificate");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.file",
				"/home/none/mgr_workspace/certgenerator/src/test/resources/ks_dsa_" + size + "_" + certDigestAlg + ".p12");

		return cryptoProps;
	}

}
