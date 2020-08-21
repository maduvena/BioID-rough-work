package org.gluu.casa.plugins.bioid;

import org.gluu.casa.credential.BasicCredential;

public class BioIDCredential extends BasicCredential {

	private String trait;

	public String getTrait() {
		return trait;
	}

	public void setTrait(String trait) {
		this.trait = trait;
	}

	public BioIDCredential(String trait, String nickName, long addedOn) {
		super(nickName, addedOn);
		this.trait = trait;

	}

}
