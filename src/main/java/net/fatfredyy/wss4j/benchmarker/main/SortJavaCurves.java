package net.fatfredyy.wss4j.benchmarker.main;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jce.ECNamedCurveTable;

public class SortJavaCurves {
	
	private static HashMap<Integer, List<String>> size2NameListMap = new LinkedHashMap<Integer, List<String>>();
	private static HashMap<Integer, List<String>> group2NameListMap = new LinkedHashMap<Integer, List<String>>();

	public static void main(String[] args) {
		Enumeration<String> namedCurves = ECNamedCurveTable.getNames();
		int namedCurvesCnt = 0;
		
		Pattern p = Pattern.compile("\\d{3}");
		
		while (namedCurves.hasMoreElements()) {
			String curveName = namedCurves.nextElement();
			Matcher m = p.matcher(curveName);
			m.find();
			Integer keySize = Integer.valueOf(m.group());
			addToMap(keySize, curveName);
			addToGroupMap(getGroupForKeySize(keySize), curveName);
			namedCurvesCnt++;
		}
		
		
		List<Integer> keySizes = new ArrayList<Integer>(size2NameListMap.keySet());
		
		Collections.sort(keySizes);
		
		for (Integer integer : keySizes) {
			System.out.println(integer);
		}
		
		System.out.println("We have " + namedCurvesCnt + " named curves defined.");
	}
	
	private static void addToGroupMap(Integer keySize, String curveName) {
		List<String> curvesList = group2NameListMap.get(keySize);
		if (curvesList == null) {
			curvesList = new LinkedList<String>();
		}
		curvesList.add(curveName);
	}
	
	private static Integer getGroupForKeySize(Integer keySize) {
		int keyBits = keySize;
		if (keyBits >= 160 && keyBits <= 193) {
			return 1;
		} else  if (keyBits >= 208 && keyBits <= 304) {
			return 2;
		} else if (keyBits >= 320 && keyBits <= 431) {
			return 3;
		} else {
			return 4;
		}
	}

	private static void addToMap(Integer keySize, String curveName) {
		List<String> curvesList = size2NameListMap.get(keySize);
		if (curvesList == null) {
			curvesList = new LinkedList<String>();
		}
		curvesList.add(curveName);
	}

}
