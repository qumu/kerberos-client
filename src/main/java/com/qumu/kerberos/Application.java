package com.qumu.kerberos;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.kerberos.client.KerberosRestTemplate;

import com.qumu.kerberos.client.httpclient.KerberosHttpClient;
import com.qumu.kerberos.client.httpclient.ServiceNameSource;
import com.qumu.kerberos.client.resttemplate.CustomKerberosRestTemplate;

@SpringBootApplication
@EnableAutoConfiguration(exclude = SecurityAutoConfiguration.class)
public class Application implements CommandLineRunner {

	@Value("${app.user-principal}")
	private String userPrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

	@Value("${app.access-url}")
	private String accessUrl;
	
	@Value("${app.use-http-client}")
	private String useHttpClient;

	@Override
	public void run(String... args) throws Exception {
		System.out.println("Running Kerberos call to url: " + accessUrl + ", user principal: " + userPrincipal + ", keytab: " + keytabLocation);
		boolean useHttpClientBoolean = Boolean.parseBoolean(useHttpClient);
		String response = useHttpClientBoolean ? useSimpleHttpClient() : useRestTemplate();
		System.out.println("The response obtained is " + response);
	}

	private String useSimpleHttpClient() {
		KerberosHttpClient kerberosHttpClient = new KerberosHttpClient(keytabLocation, userPrincipal, ServiceNameSource.HOST_BASED);
		String response = kerberosHttpClient.execute(accessUrl);
		return response;
	}
	
	private String useRestTemplate() {
		KerberosRestTemplate restTemplate = new CustomKerberosRestTemplate(keytabLocation, userPrincipal);
		String response = restTemplate.getForObject(accessUrl, String.class);
		return response;
	}
	
    public static void main(String[] args) throws Throwable {
    	new SpringApplicationBuilder(Application.class).web(false).run(args);
    }

}
