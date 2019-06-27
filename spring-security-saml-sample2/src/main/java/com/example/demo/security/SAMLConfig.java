package com.example.demo.security;

import com.google.common.collect.ImmutableMap;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/**
 *
 */
@AutoConfigureBefore(WebSecurityConfig.class)
@Configuration
@Slf4j
public class SAMLConfig {

  @Autowired
  private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

  @Bean
  public SAMLAuthenticationProvider samlAuthenticationProvider() {
    SAMLAuthenticationProvider provider = new SAMLAuthenticationProvider();
    provider.setUserDetails(samlUserDetailsServiceImpl);
    provider.setForcePrincipalAsString(false);
    return provider;
  }

  @Bean
  public AuthenticationManager authenticationManager() {
    return new ProviderManager(Collections.singletonList(samlAuthenticationProvider()));
  }

  @Bean(initMethod = "initialize")
  public StaticBasicParserPool parserPool() {
    return new StaticBasicParserPool();
  }

  @Bean
  public SAMLProcessorImpl processor() {
    HttpClient httpClient = new HttpClient(new MultiThreadedHttpConnectionManager());
    ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient);
    HTTPSOAP11Binding soapBinding = new HTTPSOAP11Binding(parserPool());
    artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding));

    VelocityEngine velocityEngine = VelocityFactory.getEngine();
    Collection<SAMLBinding> bindings = new ArrayList<>();
    bindings.add(new HTTPRedirectDeflateBinding(parserPool()));
    bindings.add(new HTTPPostBinding(parserPool(), velocityEngine));
    bindings.add(new HTTPArtifactBinding(parserPool(), velocityEngine, artifactResolutionProfile));
    bindings.add(new HTTPSOAP11Binding(parserPool()));
    bindings.add(new HTTPPAOS11Binding(parserPool()));
    return new SAMLProcessorImpl(bindings);
  }

  @Bean
  public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
    SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler();
    handler.setDefaultTargetUrl("/");
    return handler;
  }

  @Bean
  public SecurityContextLogoutHandler logoutHandler() {
    SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
    //handler.setInvalidateHttpSession(true);
    handler.setClearAuthentication(true);
    return handler;
  }

  @Bean
  public SAMLLogoutFilter samlLogoutFilter() {
    SAMLLogoutFilter filter = new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[]{logoutHandler()}, new LogoutHandler[]{logoutHandler()});
    filter.setFilterProcessesUrl("/saml/logout");
    return filter;
  }

  @Bean
  public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
    SAMLLogoutProcessingFilter filter = new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
    filter.setFilterProcessesUrl("/saml/SingleLogout");
    return filter;
  }

  @Bean
  public MetadataGeneratorFilter metadataGeneratorFilter(MetadataGenerator metadataGenerator) {
    return new MetadataGeneratorFilter(metadataGenerator);
  }

  @Bean
  public MetadataDisplayFilter metadataDisplayFilter() {
    MetadataDisplayFilter filter = new MetadataDisplayFilter();
    filter.setFilterProcessesUrl("/saml/metadata");
    return filter;
  }


  @Bean
  public ExtendedMetadata extendedMetadata() {
    ExtendedMetadata metadata = new ExtendedMetadata();
    //set flag to true to present user with IDP Selection screen
    metadata.setIdpDiscoveryEnabled(true);
    metadata.setRequireLogoutRequestSigned(true);
    //metadata.setRequireLogoutResponseSigned(true);
    metadata.setSignMetadata(false);
    return metadata;
  }

  @Bean
  public MetadataGenerator metadataGenerator(KeyManager keyManager) {
    MetadataGenerator generator = new MetadataGenerator();
//    generator.setEntityId("localhost-demo2");
    generator.setExtendedMetadata(extendedMetadata());
    generator.setIncludeDiscoveryExtension(false);
    generator.setKeyManager(keyManager);
    return generator;
  }

  @Bean(name = "samlWebSSOProcessingFilter")
  public SAMLProcessingFilter samlWebSSOProcessingFilter() {
    SAMLProcessingFilter filter = new SAMLProcessingFilter();
    filter.setAuthenticationManager(authenticationManager());
    filter.setAuthenticationSuccessHandler(successRedirectHandler());
    filter.setAuthenticationFailureHandler(authenticationFailureHandler());
    filter.setFilterProcessesUrl("/saml/SSO");
    return filter;
  }

  @Bean
  public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() {
    SAMLWebSSOHoKProcessingFilter filter = new SAMLWebSSOHoKProcessingFilter();
    filter.setAuthenticationSuccessHandler(successRedirectHandler());
    filter.setAuthenticationManager(authenticationManager());
    filter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return filter;
  }

  @Bean
  public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
    SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
    handler.setDefaultTargetUrl("/home");
    return handler;
  }

  @Bean
  public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
    SimpleUrlAuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler();
    handler.setUseForward(false);
    //handler.setDefaultFailureUrl("/error");
    return handler;
  }

  @Bean
  public SAMLDiscovery samlIDPDiscovery() {
    SAMLDiscovery filter = new SAMLDiscovery();
    filter.setFilterProcessesUrl("/saml/discovery");
    filter.setIdpSelectionPath("/idpselection");
    return filter;
  }

  @Bean
  public SAMLEntryPoint samlEntryPoint() {
    WebSSOProfileOptions options = new WebSSOProfileOptions();
    options.setIncludeScoping(false);
    SAMLEntryPoint entryPoint = new SAMLEntryPoint();
    entryPoint.setDefaultProfileOptions(options);
    entryPoint.setFilterProcessesUrl("/saml/login");
    return entryPoint;
  }

  @Bean
  public KeystoreFactory keystoreFactory(ResourceLoader resourceLoader) {
    return new KeystoreFactory(resourceLoader);
  }

  @Bean
  public KeyManager keyManager(KeystoreFactory keystoreFactory) {
//        KeyStore keystore = keystoreFactory.loadKeystore("classpath:/localhost.cert", "classpath:/localhost.key.der", "localhost", "");
    KeyStore keystore = keystoreFactory.loadKeystore("classpath:/local.cert", "classpath:/local.key.der", "localhost", "");
    return new JKSKeyManager(keystore, ImmutableMap.of("localhost", ""), "localhost");
  }

//  @Bean //Caused by: javax.net.ssl.SSLPeerUnverifiedException: SSL peer failed hostname validation for name: null
  public TLSProtocolConfigurer tlsProtocolConfigurer(KeyManager keyManager) {
    TLSProtocolConfigurer configurer = new TLSProtocolConfigurer();
    configurer.setKeyManager(keyManager);
    return configurer;
  }

}
