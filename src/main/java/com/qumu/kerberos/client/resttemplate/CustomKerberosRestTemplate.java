package com.qumu.kerberos.client.resttemplate;

import java.security.Principal;

import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.security.kerberos.client.KerberosRestTemplate;

import com.qumu.kerberos.client.httpclient.CustomSPNegoSchemeFactory;

public class CustomKerberosRestTemplate extends KerberosRestTemplate {
	
	private static final Credentials credentials = new NullCredentials();
	
	public CustomKerberosRestTemplate(String keyTabLocation, String userPrincipal) {
		super(keyTabLocation, userPrincipal, buildMyHttpClient());
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
	 * @return the http client with spneno auth scheme
	 */
	private static HttpClient buildMyHttpClient() {
		HttpClientBuilder builder = HttpClientBuilder.create();
		Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider> create()
				.register(AuthSchemes.SPNEGO, new CustomSPNegoSchemeFactory(null, null, true, false)).build();
		builder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
		BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		credentialsProvider.setCredentials(new AuthScope(null, -1, null), credentials);
		builder.setDefaultCredentialsProvider(credentialsProvider);
		CloseableHttpClient httpClient = builder.build();
		return httpClient;
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
}
