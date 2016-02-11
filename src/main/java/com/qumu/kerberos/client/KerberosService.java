package com.qumu.kerberos.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.qumu.kerberos.client.httpclient.KerberosHttpClient;
import com.qumu.kerberos.client.httpclient.ServiceNameType;


public class KerberosService {

	private static final Log LOG = LogFactory.getLog(KerberosService.class);

	private String userPrincipal;

	private String servicePrincipal;

	private KerberosHttpClient kerberosHttpClient;

	private ServiceNameType serviceNameType;

	public void setup(String keytab, String userPrincipal, String servicePrincipal, ServiceNameType serviceNameType) {
		this.userPrincipal = userPrincipal;
		this.servicePrincipal = servicePrincipal;
		this.serviceNameType = serviceNameType;
		this.kerberosHttpClient = new KerberosHttpClient(keytab, userPrincipal, servicePrincipal, serviceNameType);
	}

	/**
	 * Communicate with a Kerberos Authenticator Service
	 * presenting a Kerberos service ticket on behalf of userPrincipal in order to initiate further communication with the
	 * underlying component.
	 *
	 * @param componentHostUrl Url without port of the host where the target component/authenticator service is deployed to
	 */
	public void executeKerberosValidation(String serverUrl) {
		String authenticatorServiceUrl = serverUrl;

		if (LOG.isDebugEnabled()) {
			LOG.debug("Initiating validation for Kerberos, authenticator service url is: " + authenticatorServiceUrl +
					" user principal is: " + userPrincipal +
					", serviceNameType is: " + serviceNameType +
					", servicePrincipal: " + servicePrincipal);
		}

		try  {

			String response = kerberosHttpClient.executeGet(authenticatorServiceUrl);

			if (LOG.isDebugEnabled()) {
				LOG.debug("Successful response from Kerberos Authenticator service at " + authenticatorServiceUrl + ", response is: " + response);
			}

		} catch (Exception e) {
			String msg = "Kerberos authentication call failed when communicating with authenticator service at " + authenticatorServiceUrl;
			LOG.error(msg, e);
			throw new RuntimeException(msg);
		}
	}
}