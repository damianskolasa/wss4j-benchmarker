package net.fatfredyy.wss4j.benchmarker.ecdsa;

import java.util.List;
import java.util.Properties;

import net.fatfredyy.wss4j.benchmarker.main.SOAPUtil;

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

public class ECDSABenchmarker {
	
	

	public String banchmarkSignle() throws Exception {

		Properties ecdsaMerlinProperties = createECDSAMerlinProperties("prime193v1", "SHA256");
		Crypto ecdsaCrypto = CryptoFactory.getInstance(ecdsaMerlinProperties);

		long start = System.currentTimeMillis();
		Document signedDoc = signSOAPMessage(ecdsaCrypto, WSConstants.ECDSA_SHA1, WSConstants.SHA1);
		long mid = System.currentTimeMillis();
		verifySOAPMessageSignature(ecdsaCrypto, signedDoc);
		long end = System.currentTimeMillis();

		return "B-163;SHA1;" + (end - mid) + ";" + (mid - start);

	}

	private void verifySOAPMessageSignature(Crypto ecdsaCrypto, Document signedDoc) throws WSSecurityException, Exception {
		Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);

		AlgorithmSuite algorithmSuite = createECDSAAlgorithmSuite();
		verify(securityHeader, algorithmSuite, ecdsaCrypto);
	}

	private Document signSOAPMessage(Crypto ecdsaCrypto, String signatureAlg, String digestAlg) throws Exception, WSSecurityException {
		WSSecSignature builder = new WSSecSignature();
		builder.setUserInfo("privateKey", "123456");
		builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
		builder.setSignatureAlgorithm(signatureAlg);
		builder.setDigestAlgo(digestAlg);

		Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
		WSSecHeader secHeader = new WSSecHeader();
		secHeader.insertSecurityHeader(doc);
		Document signedDoc = builder.build(doc, ecdsaCrypto, secHeader);
		return signedDoc;
	}

	public static AlgorithmSuite createECDSAAlgorithmSuite() {
		AlgorithmSuite algorithmSuite = new AlgorithmSuite();
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA1);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA256);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA384);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA512);
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

	public Properties createECDSAMerlinProperties(String curveName, String certDigestAlg) {
		Properties cryptoProps = new Properties();
		cryptoProps.put("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.type", "pkcs12");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.provider", "BC");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.password", "132456");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.alias", "certificate");
		cryptoProps.put("org.apache.ws.security.crypto.merlin.keystore.file",
				"/home/none/mgr_workspace/certgenerator/src/test/resources/ks_ec_" + curveName + "_" + certDigestAlg + ".p12");

		return cryptoProps;
	}

}
