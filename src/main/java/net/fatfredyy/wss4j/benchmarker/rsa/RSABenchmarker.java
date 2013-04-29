package net.fatfredyy.wss4j.benchmarker.rsa;

import java.io.FileWriter;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import net.fatfredyy.wss4j.benchmarker.SOAPUtil;
import net.fatfredyy.wss4j.benchmarker.String2WSConstantsMapper;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
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

public class RSABenchmarker {

	private FileWriter fs;
	private FileWriter fv;
	private FileWriter tabSign;
	private FileWriter tabVrf;
	private boolean first = true;

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA512");

	static List<String> keySizes = Arrays.asList("1024", "3072", "7680", "15360");

	private static final String SEP = ";";

	private SummaryStatistics signStat = new SummaryStatistics();
	private SummaryStatistics vrfStat = new SummaryStatistics();

	private DecimalFormat dc = new DecimalFormat("####0.00");

	public RSABenchmarker() throws Exception {
		fs = new FileWriter("rsa_benchmark_sign1.csv");
		fv = new FileWriter("rsa_benchmark_verify1.csv");
		tabSign = new FileWriter("rsa_benchmark_tab_sign.tex");
		tabVrf = new FileWriter("rsa_benchmark_tab_vrf.tex");
	}

	public void benchmark() throws Exception {
		fs.write("size;cert_digest;digest;time\n");
		fv.write("size;cert_digest;digest;time\n");
		tabSign.write("\\begin{longtable}{| l | l | l | l | l |l |l |l |l |}\n");
		tabSign.write("\\hline\n");
		tabSign.write("\\parbox[t]{15mm}{\\centering Rozmiar\\\\ klucza} & \\parbox[t]{15mm}{\\centering Skrót\\\\ wiadomości} & \\parbox[t]{2cm}{\\centering Skrót\\\\ certyfikatu} &  \\parbox[t]{10mm}{\\centering Czas\\\\  min. [ms]} & \\parbox[t]{10mm}{\\centering Czas\\\\ max. [ms]}  & \\parbox[t]{2cm}{\\centering Mediana} & \\parbox[t]{2cm}{\\centering Wariancja} & \\parbox[t]{30mm}{\\centering Odchylenie\\\\ standardowe} \\\\ \\hline \n");
		tabSign.write("\\endhead\n");
		
		tabVrf.write("\\begin{longtable}{| l | l | l | l | l |l |l |l |l |}\n");
		tabVrf.write("\\hline\n");
		tabVrf.write("\\parbox[t]{15mm}{\\centering Rozmiar\\\\ klucza} & \\parbox[t]{15mm}{\\centering Skrót\\\\ wiadomości} & \\parbox[t]{2cm}{\\centering Skrót\\\\ certyfikatu} &  \\parbox[t]{10mm}{\\centering Czas\\\\  min. [ms]} & \\parbox[t]{10mm}{\\centering Czas\\\\ max. [ms]}  & \\parbox[t]{2cm}{\\centering Mediana} & \\parbox[t]{2cm}{\\centering Wariancja} & \\parbox[t]{30mm}{\\centering Odchylenie\\\\ standardowe} \\\\ \\hline \n");
		tabVrf.write("\\endhead\n");
		
		for (String keySize : keySizes) {
			for (String certDigestAlg : digestAlgorithms) {
				for (String digestAlg : digestAlgorithms) {
					benchmarkLoop(keySize, certDigestAlg, digestAlg);
				}
			}
		}
		tabSign.write("\\caption{longtable}\n");
		tabSign.write("\\end{longtable}");
		tabSign.flush();

		tabVrf.write("\\caption{aa}\n");
		tabVrf.write("\\end{longtable}");
		tabVrf.flush();
	}

	private void benchmarkLoop(String size, String certDigest, String digest) throws Exception {
		System.out.println("Trying: " + size + ", " + certDigest + ", " + digest);
		if (first) {
			banchmarkSignle(size, certDigest, digest);
			first = false;
		}

		for (int i = 0; i < 10; i++) {
			banchmarkSignle(size, certDigest, digest);
		}
		fs.flush();
		fv.flush();
		tabSign.write(size + " & " + digest + " & " + certDigest + " & " + dc.format(signStat.getMin()) + " & "
				+ dc.format(signStat.getMax()) + " & " + dc.format(signStat.getMean()) + " & " + dc.format(signStat.getVariance()) + " & "
				+ dc.format(signStat.getStandardDeviation()) + " \\\\ \\hline \n");
		tabSign.flush();
		tabVrf.write(size + " & " + digest + " & " + certDigest + " & " + dc.format(vrfStat.getMin()) + " & " + dc.format(vrfStat.getMax())
				+ " & " + dc.format(vrfStat.getMean()) + " & " + dc.format(vrfStat.getVariance()) + " & "
				+ dc.format(vrfStat.getStandardDeviation()) + " \\\\ \\hline \n");
		tabVrf.flush();
		signStat = new SummaryStatistics();
		vrfStat = new SummaryStatistics();
		System.gc();
	}

	public void banchmarkSignle(String size, String certDigest, String digest) throws Exception {
		Properties dsaMerlinProperties = createDSAMerlinProperties(size, certDigest);
		Crypto dsaCrypto = CryptoFactory.getInstance(dsaMerlinProperties);

		long start = System.currentTimeMillis();
		Document signedDoc = signSOAPMessage(dsaCrypto, String2WSConstantsMapper.string2WSconstantMap.get("RSA_" + digest),
				String2WSConstantsMapper.string2WSconstantMap.get(digest));
		long mid = System.currentTimeMillis();
		verifySOAPMessageSignature(dsaCrypto, signedDoc);
		long end = System.currentTimeMillis();

		if (!first) {
			signStat.addValue(new Double(mid - start));
			vrfStat.addValue(new Double(end - mid));
		}

		fs.write(size + SEP + certDigest + SEP + digest + SEP + (mid - start) + "\n");
		fv.write(size + SEP + certDigest + SEP + digest + SEP + (end - mid) + "\n");

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
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA1);
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA256);
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA384);
		algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA512);
		algorithmSuite.setMinimumAsymmetricKeyLength(128);
		algorithmSuite.setMaximumAsymmetricKeyLength(8192);
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
				"/home/none/mgr_workspace/certgenerator/src/test/resources/ks_rsa_" + size + "_" + certDigestAlg + ".p12");

		return cryptoProps;
	}

}
