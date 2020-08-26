package org.gluu.casa.plugins.bioid.model;

import org.gluu.casa.core.model.BasePerson;
import org.gluu.casa.misc.Utils;
import org.gluu.persist.annotation.AttributeName;
import org.gluu.persist.annotation.DataEntry;
import org.gluu.persist.annotation.ObjectClass;

import java.util.List;

@DataEntry
@ObjectClass("gluuPerson")
public class PersonBiometric extends BasePerson {

    @AttributeName(name = "oxBiometricDevices")
    private String bioMetricDevices;

    @AttributeName
    private List<String> biometric;

	public String getBioMetricDevices() {
		return bioMetricDevices;
	}

	public void setBioMetricDevices(String bioMetricDevices) {
		this.bioMetricDevices = bioMetricDevices;
	}

	public List<String> getBiometric() {
		return biometric;
	}

	public void setBiometric(List<String> biometric) {
		this.biometric = biometric;
	}

    

}
