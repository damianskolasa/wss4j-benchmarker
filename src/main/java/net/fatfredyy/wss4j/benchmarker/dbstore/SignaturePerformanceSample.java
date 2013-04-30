package net.fatfredyy.wss4j.benchmarker.dbstore;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "sign_perf_sample")
public class SignaturePerformanceSample {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	private String curveName;

	private Integer keySize;

	private String digestName;

	private String certDigestName;

	private Double min;

	private Double max;

	private Double mean;

	private Double variance;

	private Double stdDeviation;

	private String scheme;

	private String type;

	private boolean sign;

	public SignaturePerformanceSample() {
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getCurveName() {
		return curveName;
	}

	public void setCurveName(String curveName) {
		this.curveName = curveName;
	}

	public Integer getKeySize() {
		return keySize;
	}

	public void setKeySize(Integer keySize) {
		this.keySize = keySize;
	}

	public String getDigestName() {
		return digestName;
	}

	public void setDigestName(String digestName) {
		this.digestName = digestName;
	}

	public String getCertDigestName() {
		return certDigestName;
	}

	public void setCertDigestName(String certDigestName) {
		this.certDigestName = certDigestName;
	}

	public Double getMin() {
		return min;
	}

	public void setMin(Double min) {
		this.min = min;
	}

	public Double getMax() {
		return max;
	}

	public void setMax(Double max) {
		this.max = max;
	}

	public Double getMean() {
		return mean;
	}

	public void setMean(Double mean) {
		this.mean = mean;
	}

	public Double getVariance() {
		return variance;
	}

	public void setVariance(Double variance) {
		this.variance = variance;
	}

	public Double getStdDeviation() {
		return stdDeviation;
	}

	public void setStdDeviation(Double stdDeviation) {
		this.stdDeviation = stdDeviation;
	}

	public String getScheme() {
		return scheme;
	}

	public void setScheme(String scheme) {
		this.scheme = scheme;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public boolean isSign() {
		return sign;
	}

	public void setSign(boolean sign) {
		this.sign = sign;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((certDigestName == null) ? 0 : certDigestName.hashCode());
		result = prime * result + ((curveName == null) ? 0 : curveName.hashCode());
		result = prime * result + ((digestName == null) ? 0 : digestName.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((keySize == null) ? 0 : keySize.hashCode());
		result = prime * result + ((max == null) ? 0 : max.hashCode());
		result = prime * result + ((mean == null) ? 0 : mean.hashCode());
		result = prime * result + ((min == null) ? 0 : min.hashCode());
		result = prime * result + ((scheme == null) ? 0 : scheme.hashCode());
		result = prime * result + (sign ? 1231 : 1237);
		result = prime * result + ((stdDeviation == null) ? 0 : stdDeviation.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		result = prime * result + ((variance == null) ? 0 : variance.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SignaturePerformanceSample other = (SignaturePerformanceSample) obj;
		if (certDigestName == null) {
			if (other.certDigestName != null)
				return false;
		} else if (!certDigestName.equals(other.certDigestName))
			return false;
		if (curveName == null) {
			if (other.curveName != null)
				return false;
		} else if (!curveName.equals(other.curveName))
			return false;
		if (digestName == null) {
			if (other.digestName != null)
				return false;
		} else if (!digestName.equals(other.digestName))
			return false;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		if (keySize == null) {
			if (other.keySize != null)
				return false;
		} else if (!keySize.equals(other.keySize))
			return false;
		if (max == null) {
			if (other.max != null)
				return false;
		} else if (!max.equals(other.max))
			return false;
		if (mean == null) {
			if (other.mean != null)
				return false;
		} else if (!mean.equals(other.mean))
			return false;
		if (min == null) {
			if (other.min != null)
				return false;
		} else if (!min.equals(other.min))
			return false;
		if (scheme == null) {
			if (other.scheme != null)
				return false;
		} else if (!scheme.equals(other.scheme))
			return false;
		if (sign != other.sign)
			return false;
		if (stdDeviation == null) {
			if (other.stdDeviation != null)
				return false;
		} else if (!stdDeviation.equals(other.stdDeviation))
			return false;
		if (type == null) {
			if (other.type != null)
				return false;
		} else if (!type.equals(other.type))
			return false;
		if (variance == null) {
			if (other.variance != null)
				return false;
		} else if (!variance.equals(other.variance))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SignaturePerformanceSample [id=" + id + ", curveName=" + curveName + ", keySize=" + keySize + ", digestName=" + digestName
				+ ", certDigestName=" + certDigestName + ", min=" + min + ", max=" + max + ", mean=" + mean + ", variance=" + variance
				+ ", stdDeviation=" + stdDeviation + ", scheme=" + scheme + ", type=" + type + ", sign=" + sign + "]";
	}

}
