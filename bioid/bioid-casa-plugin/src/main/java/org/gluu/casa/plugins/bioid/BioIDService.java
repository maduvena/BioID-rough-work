package org.gluu.casa.plugins.bioid;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;
import org.gluu.casa.credential.BasicCredential;
import org.gluu.casa.misc.Utils;
import org.gluu.casa.service.IPersistenceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Class that holds the logic to list and enroll bioid creds
 * 
 * @author madhumita
 *
 */

public class BioIDService {

	private static BioIDService SINGLE_INSTANCE = null;
	public static Map<String, String> properties;
	private Logger logger = LoggerFactory.getLogger(getClass());
	public static String ACR = "bioid";
	private int TIMEOUT = 5000; // 5 seconds
	public static final String TRAIT_FACE = "Face";
	public static final String TRAIT_PERIOCULAR = "Periocular";
	public static final String TRAIT_FACE_PERIOCULAR = "Face,Periocular";
	public static final String TRAIT_VOICE = "voice";
	public static final String TASK_ENROLL = "enroll";
	public static final String TASK_VERIFY = "verify";

	private IPersistenceService persistenceService;

	private BioIDService() {
		persistenceService = Utils.managedBean(IPersistenceService.class);
		reloadConfiguration();

	}

	public static BioIDService getInstance() {
		if (SINGLE_INSTANCE == null) {
			synchronized (BioIDService.class) {
				SINGLE_INSTANCE = new BioIDService();
			}
		}
		return SINGLE_INSTANCE;
	}

	public void reloadConfiguration() {
		ObjectMapper mapper = new ObjectMapper();
		properties = persistenceService.getCustScriptConfigProperties(ACR);
		if (properties == null) {
			logger.warn(
					"Config. properties for custom script '{}' could not be read. Features related to {} will not be accessible",
					ACR, ACR.toUpperCase());
		} else {
			try {
				logger.info("BioID settings found were: {}", mapper.writeValueAsString(properties));
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

	public String getScriptPropertyValue(String value) {
		return properties.get(value);
	}

	public List<BasicCredential> getDevices(String uniqueIdOfTheUser) {
		String bcid = properties.get("STORAGE") + "." + properties.get("PARTITION") + "."
				+ uniqueIdOfTheUser.hashCode();
		try {
			List<BasicCredential> list = new ArrayList<BasicCredential>();
			if (isEnrolled(bcid, TRAIT_FACE)) {

				list.add(new BasicCredential(TRAIT_FACE, System.currentTimeMillis()));
			}
			if (isEnrolled(bcid, TRAIT_PERIOCULAR)) {

				list.add(new BasicCredential(TRAIT_PERIOCULAR, System.currentTimeMillis()));
			}
			return list;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public int getDeviceTotal(String uniqueIdOfTheUser) {
		String bcid = properties.get("STORAGE") + "." + properties.get("PARTITION") + "."
				+ uniqueIdOfTheUser.hashCode();
		try {
			if (isEnrolled(bcid, TRAIT_FACE)) {
				if (isEnrolled(bcid, TRAIT_PERIOCULAR)) {
					return 2;
				} else
					return 1;
			} else {
				return 0;
			}
		} catch (Exception e) {
			e.printStackTrace();
			return 0;
		}
	}

	public boolean deleteBioIDDevice(String userName, String deviceId) {
		// write the logic for deleting the device
		return true;
	}

	public boolean updateBioIDDevice(String userName) {
		return true;
	}

	public boolean isEnrolled(String bcid, String trait) throws Exception {

		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair("bcid", bcid));
		params.add(new BasicNameValuePair("trait", trait));
		params.add(new BasicNameValuePair("livedetection", "true"));
		String asB64 = Base64.getEncoder().encodeToString(
				(properties.get("APP_IDENTIFIER") + ":" + properties.get("APP_SECRET")).getBytes("utf-8"));

		String url = properties.get("ENDPOINT") + "isenrolled";
		String result = getUrlContents(url, params, new BasicNameValuePair("Authorization", "Basic " + asB64), TIMEOUT);
		logger.info(result);
		if (result == null)
			return false;
		else
			return true;
	}

	public boolean performBiometricOperation(String task, String token) throws Exception {

		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair("livedetection", "true"));

		String url = properties.get("ENDPOINT") + task;
		String result = getUrlContents(url, params, new BasicNameValuePair("Authorization", "Bearer " + token),
				TIMEOUT);
		logger.info(result);
		return true;
	}

	public String getAccessToken(String bcid, String task) throws Exception {
		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair("id", properties.get("APP_IDENTIFIER")));
		params.add(new BasicNameValuePair("bcid", bcid));
		params.add(new BasicNameValuePair("task", task));
		String asB64 = Base64.getEncoder().encodeToString(
				(properties.get("APP_IDENTIFIER") + ":" + properties.get("APP_SECRET")).getBytes("utf-8"));
		String url = properties.get("ENDPOINT") + "token";
		String result = getUrlContents(url, params, new BasicNameValuePair("Authorization", "Basic " + asB64), TIMEOUT);
		logger.info(result);
		return result;
	}

	private String getUrlContents(String url, List<NameValuePair> nvPairList, NameValuePair header, int timeout)
			throws Exception {

		String contents = null;

		DefaultHttpClient client = new DefaultHttpClient();
		HttpParams params = client.getParams();
		HttpConnectionParams.setConnectionTimeout(params, timeout);
		HttpConnectionParams.setSoTimeout(params, timeout);

		HttpGet httpGet = new HttpGet(url);
		URIBuilder uribe = new URIBuilder(httpGet.getURI());
		nvPairList.forEach(pair -> uribe.addParameter(pair.getName(), pair.getValue()));

		httpGet.setURI(uribe.build());
		httpGet.setHeader(header.getName(), header.getValue());
		HttpResponse response = client.execute(httpGet);
		HttpEntity entity = response.getEntity();

		logger.debug("GET request is {}",
				httpGet.getURI() + " response status is:" + response.getStatusLine().getStatusCode());
		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
			contents = EntityUtils.toString(entity);
		}
		EntityUtils.consume(entity);

		return contents;

	}

}
