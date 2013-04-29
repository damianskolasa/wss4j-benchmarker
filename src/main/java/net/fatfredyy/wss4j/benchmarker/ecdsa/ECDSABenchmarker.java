package net.fatfredyy.wss4j.benchmarker.ecdsa;

import java.io.FileWriter;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import net.fatfredyy.wss4j.benchmarker.SOAPUtil;
import net.fatfredyy.wss4j.benchmarker.String2WSConstantsMapper;
import net.fatfredyy.wss4j.benchmarker.main.SortJavaCurves;

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

public class ECDSABenchmarker {

	private FileWriter fs;
	private FileWriter fv;
	private FileWriter tabSign;
	private FileWriter tabVrf;
	private boolean first = true;

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA512");

	private static final String SEP = ";";

	private SummaryStatistics signStat = new SummaryStatistics();
	private SummaryStatistics vrfStat = new SummaryStatistics();

	private DecimalFormat dc = new DecimalFormat("####0.00");

	public ECDSABenchmarker() throws Exception {
		fs = new FileWriter("ecdsa_benchmark_sign.csv");
		fv = new FileWriter("ecdsa_benchmark_verify.csv");
		tabSign = new FileWriter("ecdsa_benchmark_tab_sign.tex");
		tabVrf = new FileWriter("ecdsa_benchmark_tab_vrf.tex");
	}

	public void benchmark() throws Exception {

		SortJavaCurves.initialize();

		// Enumeration<String> namedCurves = ECNamedCurveTable.getNames();
		fs.write("curve_name;size;cert_digest;digest;min;max;mean;variance;standard_deviation\n");
		fv.write("curve_name;size;cert_digest;digest;min;max;mean;variance;standard_deviation\n");

		tabSign.write("\\begin{longtable}{| l | l | l | l | l |l |l |l |l |}\n");
		tabSign.write("\\hline\n");
		tabSign.write("\\parbox[t]{25mm}{\\centering Nazwa\\ krzywej} & \\parbox[t]{10mm}{\\centering Rozmiar} & \\parbox[t]{15mm}{\\centering Skrót\\\\ wiadomości} & \\parbox[t]{2cm}{\\centering Skrót\\\\ certyfikatu} &  \\parbox[t]{10mm}{\\centering Czas\\\\  min. [ms]} & \\parbox[t]{10mm}{\\centering Czas\\\\ max. [ms]}  & \\parbox[t]{2cm}{\\centering Mediana} & \\parbox[t]{2cm}{\\centering Wariancja} & \\parbox[t]{30mm}{\\centering Odchylenie\\\\ standardowe} \\\\ \\hline \n");
		tabSign.write("\\endhead\n");

		tabVrf.write("\\begin{longtable}{| l | l | l | l | l |l |l |l |l |}\n");
		tabVrf.write("\\hline\n");
		tabVrf.write("\\parbox[t]{25mm}{\\centering Nazwa\\\\ krzywej} & \\parbox[t]{10mm}{\\centering Rozmiar} & \\parbox[t]{15mm}{\\centering Skrót\\\\ wiadomości} & \\parbox[t]{2cm}{\\centering Skrót\\\\ certyfikatu} &  \\parbox[t]{10mm}{\\centering Czas\\\\  min. [ms]} & \\parbox[t]{10mm}{\\centering Czas\\\\ max. [ms]}  & \\parbox[t]{2cm}{\\centering Mediana} & \\parbox[t]{2cm}{\\centering Wariancja} & \\parbox[t]{30mm}{\\centering Odchylenie\\\\ standardowe} \\\\ \\hline \n");
		tabVrf.write("\\endhead\n");

		for (Integer size : SortJavaCurves.keySizes) {
			List<String> curveNames = SortJavaCurves.size2NameListMap.get(size);
			for (String curveName : curveNames) {
				for (String certDigestAlg : digestAlgorithms) {
					for (String digestAlg : digestAlgorithms) {
						if (first) {
							benchmarkLoop(curveName, certDigestAlg,
									String2WSConstantsMapper.string2WSconstantMap.get("ECDSA_" + digestAlg),
									String2WSConstantsMapper.string2WSconstantMap.get(digestAlg), digestAlg, size);
							first = false;
						}
						benchmarkLoop(curveName, certDigestAlg, String2WSConstantsMapper.string2WSconstantMap.get("ECDSA_" + digestAlg),
								String2WSConstantsMapper.string2WSconstantMap.get(digestAlg), digestAlg, size);
					}

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

	private void benchmarkLoop(String curveName, String certDigest, String algSuit, String digest, String digestName, Integer size)
			throws Exception {
		System.out.println("Trying: " + curveName + ", " + certDigest + ", " + algSuit + ", " + digestName);
		for (int i = 0; i < 10; i++) {
			banchmarkSignle(curveName, certDigest, algSuit, digest);
		}
		if (first) {
			return;
		}
		fs.write(curveName + SEP + size + SEP + digestName + SEP + certDigest + SEP + dc.format(signStat.getMin()) + SEP
				+ dc.format(signStat.getMax()) + SEP + dc.format(signStat.getMean()) + SEP + dc.format(signStat.getVariance()) + SEP
				+ dc.format(signStat.getStandardDeviation()) + "\n");
		fv.write(curveName + SEP + size + SEP + digestName + SEP + certDigest + SEP + dc.format(vrfStat.getMin()) + SEP
				+ dc.format(vrfStat.getMax()) + SEP + dc.format(vrfStat.getMean()) + SEP + dc.format(vrfStat.getVariance()) + SEP
				+ dc.format(vrfStat.getStandardDeviation()) + "\n");

		fs.flush();
		fv.flush();
		tabSign.write(curveName + " & " + size + " & " + digestName + " & " + certDigest + " & " + dc.format(signStat.getMin()) + " & "
				+ dc.format(signStat.getMax()) + " & " + dc.format(signStat.getMean()) + " & " + dc.format(signStat.getVariance()) + " & "
				+ dc.format(signStat.getStandardDeviation()) + " \\\\ \\hline \n");
		tabSign.flush();

		tabVrf.write(curveName + " & " + size + " & " + digestName + " & " + certDigest + " & " + dc.format(vrfStat.getMin()) + " & "
				+ dc.format(vrfStat.getMax()) + " & " + dc.format(vrfStat.getMean()) + " & " + dc.format(vrfStat.getVariance()) + " & "
				+ dc.format(vrfStat.getStandardDeviation()) + " \\\\ \\hline \n");
		tabVrf.flush();
		signStat = new SummaryStatistics();
		vrfStat = new SummaryStatistics();
		System.gc();
	}

	private void banchmarkSignle(String curveName, String certDigest, String algSuit, String digest) throws Exception {
		Properties ecdsaMerlinProperties = createECDSAMerlinProperties(curveName, certDigest);
		Crypto ecdsaCrypto = CryptoFactory.getInstance(ecdsaMerlinProperties);

		long start = System.currentTimeMillis();
		Document signedDoc = signSOAPMessage(ecdsaCrypto, algSuit, digest);
		long mid = System.currentTimeMillis();
		verifySOAPMessageSignature(ecdsaCrypto, signedDoc);
		long end = System.currentTimeMillis();

		if (!first) {
			signStat.addValue(new Double(mid - start));
			vrfStat.addValue(new Double(end - mid));
		}

		System.gc();

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

	private static AlgorithmSuite createECDSAAlgorithmSuite() {
		AlgorithmSuite algorithmSuite = new AlgorithmSuite();
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA1);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA256);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA384);
		algorithmSuite.addSignatureMethod(WSConstants.ECDSA_SHA512);
		algorithmSuite.setMinimumAsymmetricKeyLength(100);
		algorithmSuite.setMaximumAsymmetricKeyLength(600);
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

	private static Properties createECDSAMerlinProperties(String curveName, String certDigestAlg) {
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
