package org.gluu.casa.plugins.bioid.vm;

import java.util.List;

import org.gluu.casa.credential.BasicCredential;
import org.gluu.casa.misc.Utils;
import org.gluu.casa.plugins.bioid.BioIDService;
import org.gluu.casa.service.ISessionContext;
import org.gluu.casa.ui.UIUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zkoss.bind.annotation.Command;
import org.zkoss.bind.annotation.Init;
import org.zkoss.bind.annotation.NotifyChange;
import org.zkoss.zk.au.out.AuInvoke;
import org.zkoss.zk.ui.select.annotation.WireVariable;
import org.zkoss.zk.ui.util.Clients;

public class BioidViewModel {
	private Logger logger = LoggerFactory.getLogger(getClass());
	@WireVariable
	private ISessionContext sessionContext;
	private List<BasicCredential> devices;
	private BasicCredential newDevice;
	private String accessToken;
	private String apiUrl;
	private String task;
	private String trait;

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getApiUrl() {
		return apiUrl;
	}

	public void setApiUrl(String apiUrl) {
		this.apiUrl = apiUrl;
	}

	public String getTask() {
		return task;
	}

	public void setTask(String task) {
		this.task = task;
	}

	public String getTrait() {
		return trait;
	}

	public void setTrait(String trait) {
		this.trait = trait;
	}

	public BasicCredential getNewDevice() {
		return newDevice;
	}

	public void setNewDevice(BasicCredential newDevice) {
		this.newDevice = newDevice;
	}

	public List<BasicCredential> getDevices() {
		return devices;
	}

	/**
	 * Initialization method for this ViewModel.
	 */
	@Init
	public void init() {
		logger.debug("init invoked");
		sessionContext = Utils.managedBean(ISessionContext.class);
	}

	@NotifyChange("*")
	@Command
	public void show() {
		logger.debug("showBioID");
		try {
			sessionContext = Utils.managedBean(ISessionContext.class);
			apiUrl = BioIDService.getInstance().getScriptPropertyValue("ENDPOINT");
			trait = BioIDService.TRAIT_FACE_PERIOCULAR;
			devices = BioIDService.getInstance().getDevices(sessionContext.getLoggedUser().getUserName());
			String bcid = BioIDService.getInstance().getScriptPropertyValue("STORAGE") + "."
					+ BioIDService.getInstance().getScriptPropertyValue("PARTITION") + "."
					+ sessionContext.getLoggedUser().getUserName().hashCode();
			try {
				if (BioIDService.getInstance().isEnrolled(bcid, BioIDService.TRAIT_FACE)
						&& BioIDService.getInstance().isEnrolled(bcid, BioIDService.TRAIT_PERIOCULAR)) {
					accessToken = BioIDService.getInstance().getAccessToken(bcid, BioIDService.TASK_VERIFY);

					task = BioIDService.TASK_VERIFY;
				} else {
					accessToken = BioIDService.getInstance().getAccessToken(bcid, BioIDService.TASK_ENROLL);
					task = BioIDService.TASK_ENROLL;
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			Clients.response(new AuInvoke("initPage", accessToken, trait, task, apiUrl));
			Clients.scrollBy(0, 10);

		} catch (Exception e) {
			UIUtils.showMessageUI(false);
			logger.error(e.getMessage(), e);
		}

	}

	
}
