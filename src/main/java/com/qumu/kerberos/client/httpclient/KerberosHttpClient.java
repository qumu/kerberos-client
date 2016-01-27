package com.qumu.kerberos.client.httpclient;

import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.util.StringUtils;

/**
 * 
 * Based on Spring's implementation of KerberosRestTemplate, simplified version 
 * that only allows making a GET request using a HttpClient that uses SPNEGO to communicate
 * with a kerberized server and the response is read as a String.
 * 
 * If a keytab file is provided it will be used to log into the Auth Server, otherwise a ticket cache
 * will be used.
 * 
 * Ensure the hostname/domain of the server (url passed in) is part of the Kerberos realm / Domain controller 
 * 
 * @author davidfernandez
 *
 */
public class KerberosHttpClient {
	
	private static final Log LOG = LogFactory.getLog(KerberosHttpClient.class);
	
	private static final Credentials credentials = new NullCredentials();
	private String keyTabLocation;
	private String userPrincipal;
	private HttpClient httpClient;
	private Map<String, Object> loginOptions;
	private ServiceNameSource serviceNameSource;
	
	public KerberosHttpClient(String keytabLocation, String userPrincipal, ServiceNameSource serviceNameSource) {
			this.keyTabLocation = keytabLocation;
			this.userPrincipal = userPrincipal;
			this.serviceNameSource = serviceNameSource;
			this.httpClient = buildHttpClient();
			
	}
	
	/**
	 * Builds the default instance of {@link HttpClient} having kerberos
	 * support. 
	 * 
	 * It puts the flag useCanonicalHostname to false in the SpnegoSchemeFactory 
	 * to make the login to auth server work by doing a 'shallow' inspect of the server hostname 
	 * (without lookups) so this can be used with hosts that use aliases of localhost and still be 
	 * recognized as part of the Kerberos realm
	 *
	 * @return the http client with spnego auth scheme
	 */
	private HttpClient buildHttpClient() {
		HttpClientBuilder builder = HttpClientBuilder.create();
		Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider> create()
				.register(AuthSchemes.SPNEGO, new CustomSPNegoSchemeFactory(serviceNameSource, userPrincipal, true, false)).build();
		builder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
		BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		credentialsProvider.setCredentials(new AuthScope(null, -1, null), credentials);
		builder.setDefaultCredentialsProvider(credentialsProvider);
		CloseableHttpClient httpClient = builder.build();
		return httpClient;
	}
	
	public String execute(final String url) {
		
		try {
			ClientLoginConfig loginConfig = new ClientLoginConfig(keyTabLocation, userPrincipal, loginOptions);
			Set<Principal> princ = new HashSet<Principal>(1);
			princ.add(new KerberosPrincipal(userPrincipal));
			Subject sub = new Subject(false, princ, new HashSet<Object>(), new HashSet<Object>());
			LoginContext lc = new LoginContext("", sub, null, loginConfig);
			lc.login();
			Subject serviceSubject = lc.getSubject();
			return Subject.doAs(serviceSubject, new PrivilegedAction<String>() {
				@Override
				public String run() {
					return executeRequest(url);
				}
			});
		} catch (Exception e) {
			throw new RuntimeException("Error running call", e);
		}
	}
	
	private String executeRequest(String url) {
		
		HttpGet httpGet = new HttpGet(url); 
	
		try {
			
			HttpResponse response = httpClient.execute(httpGet);
			
			if (response.getStatusLine().getStatusCode() != 200) {
				String msg = "Error in request to " + url + ", status is " + response.getStatusLine().getStatusCode() + ", reason " + response.getStatusLine().getReasonPhrase();
				LOG.error(msg);
				throw new RuntimeException(msg);
			}

			return IOUtils.toString(response.getEntity().getContent());
		} catch (Throwable t) {
			LOG.error("Error executing call to " + url, t);
			throw new RuntimeException(t);
		}
	}
	
	private static class NullCredentials implements Credentials {

		@Override
		public Principal getUserPrincipal() {
			return null;
		}

		@Override
		public String getPassword() {
			return null;
		}

	}
	
	private static class ClientLoginConfig extends Configuration {

		private final String keyTabLocation;
		private final String userPrincipal;
		private final Map<String, Object> loginOptions;

		public ClientLoginConfig(String keyTabLocation, String userPrincipal, Map<String, Object> loginOptions) {
			super();
			this.keyTabLocation = keyTabLocation;
			this.userPrincipal = userPrincipal;
			this.loginOptions = loginOptions;
		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {

			Map<String, Object> options = new HashMap<String, Object>();

			// if we don't have keytab or principal only option is to rely on
			// credentials cache.
			if (!StringUtils.hasText(keyTabLocation) || !StringUtils.hasText(userPrincipal)) {
				// cache
				options.put("useTicketCache", "true");
			} else {
				// keytab
				options.put("useKeyTab", "true");
				options.put("keyTab", this.keyTabLocation);
				options.put("principal", this.userPrincipal);
				options.put("storeKey", "true");
			}
			options.put("doNotPrompt", "true");
			options.put("isInitiator", "true");

			if (loginOptions != null) {
				options.putAll(loginOptions);
			}

			return new AppConfigurationEntry[] { new AppConfigurationEntry(
					"com.sun.security.auth.module.Krb5LoginModule",
					AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
		}
	}	
}

//Pure Java 8
//------------
//public String executeJ8(final String url, PrivilegedAction<String> httpRequestAction) {
//	
//	try {
//		
//		ClientLoginConfig loginConfig = new ClientLoginConfig(keyTabLocation, userPrincipal, loginOptions);
//		Set<Principal> princ = new HashSet<Principal>(1);
//		princ.add(new KerberosPrincipal(userPrincipal));
//		Subject sub = new Subject(false, princ, new HashSet<Object>(), new HashSet<Object>());
//		LoginContext lc = new LoginContext("", sub, null, loginConfig);
//		lc.login();
//		Subject serviceSubject = lc.getSubject();
//		return Subject.doAs(serviceSubject, httpRequestAction);
//		
//	} catch (Exception e) {
//		throw new RuntimeException("Error running call", e);
//	}
//}
//
//private void callerJ8(String url) {
//	this.executeJ8(url, () -> { return executeRequest(url); });
//}	
//	public interface StateChangeListener<T> {
//	    public T onStateChange();
//	}
//	
//	private void addState(StateChangeListener<String> lst) {
//		System.out.println("yes");
//	}
//	
//	private void test() {
//		this.addState(() -> { return "Yes"; });
//	}
