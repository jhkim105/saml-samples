package com.example.demo.security;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
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
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
public class SamlSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.exceptionHandling().authenticationEntryPoint(samlEntryPoint());
    // @formatter:off
    http.csrf().disable();
    http.addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
    http
        .authorizeRequests()
          .antMatchers("/error").permitAll()
          .antMatchers("/saml/**").permitAll()
          .anyRequest().authenticated();
    // @formatter:on
  }

  @Bean
  public SAMLEntryPoint samlEntryPoint() {
    SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
    WebSSOProfileOptions defaultOptions = new WebSSOProfileOptions();
    defaultOptions.setIncludeScoping(false);
    defaultOptions.setForceAuthN(true);
    samlEntryPoint.setDefaultProfileOptions(defaultOptions);
    return samlEntryPoint;
  }


  @Bean
  public FilterChainProxy samlFilter() throws Exception {
    List<SecurityFilterChain> chains = new ArrayList<>();
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"), new MetadataDisplayFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"), samlProcessingFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));
    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/sls/**"), samlLogoutProcessingFilter()));
    return new FilterChainProxy(chains);
  }

  @Bean
  public SAMLProcessingFilter samlProcessingFilter() throws Exception {
    SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
    samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
    return samlWebSSOProcessingFilter;
  }

  /**
   * logout
   */
  @Bean
  public SAMLLogoutFilter samlLogoutFilter() {
    LogoutHandler[] logoutHandlers = new LogoutHandler[]{logoutHandler()};
    return new SAMLLogoutFilter("/", logoutHandlers, logoutHandlers);
  }

  /**
   * sls
   * Global logout
   */
  @Bean
  public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
    return new SAMLLogoutProcessingFilter(logoutSuccessHandler(), logoutHandler());
  }

  @Bean
  public SecurityContextLogoutHandler logoutHandler() {
    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    return logoutHandler;
  }

  @Bean
  public SimpleUrlLogoutSuccessHandler logoutSuccessHandler() {
    SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
    logoutSuccessHandler.setDefaultTargetUrl("/");
    return logoutSuccessHandler;
  }


  @Bean
  @Qualifier("metadata")
  public CachingMetadataManager metadata() throws MetadataProviderException, IOException {
    List<MetadataProvider> providers = new ArrayList<>();
    providers.add(idpMetadata());
    return new CachingMetadataManager(providers);
  }



  //
//  private ExtendedMetadataDelegate idpMetadata()
//      throws MetadataProviderException {
//    String idpMetadataUrl = "https://app.onelogin.com/saml/metadata/e91cd789-2b00-45d0-9a0f-46363bbb97da";
//    Timer backgroundTaskTimer = new Timer(true);
//    HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(
//        backgroundTaskTimer, new HttpClient(), idpMetadataUrl);
//    httpMetadataProvider.setParserPool(parserPool());
//    ExtendedMetadataDelegate extendedMetadataDelegate =
//        new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadataMap());
//    extendedMetadataDelegate.setMetadataTrustCheck(true);
//    extendedMetadataDelegate.setMetadataRequireSignature(false);
//    backgroundTaskTimer.purge();
//    return extendedMetadataDelegate;
//  }





  // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
  // is here
  // Do no forget to call iniitalize method on providers
//  @Bean
//  @Qualifier("metadata")
//  public CachingMetadataManager metadata() throws MetadataProviderException, IOException {
//    List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
//    providers.add(ssoCircleExtendedMetadataProvider());
//    return new CachingMetadataManager(providers);
//  }


//  private Map<String, ExtendedMetadata> extendedMetadataMap() {
//    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
//    extendedMetadata.setIdpDiscoveryEnabled(false);
//    extendedMetadata.setSignMetadata(false);
//    Map<String, ExtendedMetadata> map = new HashMap<>();
//    map.put("idpMetadata", extendedMetadata);
//    return map;
//  }



  @Bean
  @Qualifier("idp-onelogin")
  public ExtendedMetadataDelegate idpMetadata() throws MetadataProviderException, IOException {
    final FilesystemMetadataProvider httpMetadataProvider
        = new FilesystemMetadataProvider(metadataFile());
    httpMetadataProvider.setParserPool(parserPool());
    ExtendedMetadataDelegate extendedMetadataDelegate =
        new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata());
    extendedMetadataDelegate.setMetadataTrustCheck(false);
    extendedMetadataDelegate.setMetadataRequireSignature(false);
    return extendedMetadataDelegate;
  }

  @Bean(name = "metadataFile")
  public File metadataFile() throws IOException {
//    String metadataFilePath = "classpath:/onelogin_metadata_942190.xml";
    String metadataFilePath = "classpath:/onelogin_metadata_936070.xml";
    Resource resource;
    if (metadataFilePath.startsWith("classpath:")) {
      resource = new ClassPathResource(metadataFilePath.substring("classpath:".length()));
    } else {
      resource = new FileSystemResource(metadataFilePath);
    }
    return resource.getFile();
  }


  @Bean(initMethod = "initialize")
  public StaticBasicParserPool parserPool() {
    return new StaticBasicParserPool();
  }

  @Bean
  public SAMLAuthenticationProvider samlAuthenticationProvider() {
    SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
    samlAuthenticationProvider.setForcePrincipalAsString(false);
    return samlAuthenticationProvider;
  }

  @Bean
  public KeyManager keyManager() {
//    String storePass = "dev#4430";
//    String alias = "onelogin";
//    Map<String, String> passwords = new HashMap<>();
//    passwords.put(alias, storePass);
//
//    DefaultResourceLoader loader = new DefaultResourceLoader();
//    Resource keyStore = loader.getResource("classpath:/local.jks");
//
//    return new JKSKeyManager(keyStore, storePass, passwords, alias);
    return new EmptyKeyManager();
  }

  @Bean
  public SAMLDefaultLogger samlLogger() {
    return new SAMLDefaultLogger();
  }

  @Bean
  public SAMLContextProviderImpl contextProvider() {
    return new SAMLContextProviderImpl();
  }


  @Bean
  public MetadataGeneratorFilter metadataGeneratorFilter() throws MetadataProviderException, IOException {
    final MetadataDisplayFilter filter = new MetadataDisplayFilter();
    filter.setManager(metadata());
    return new MetadataGeneratorFilter(metadataGenerator());
  }

  @Bean
  public MetadataGenerator metadataGenerator() {
    MetadataGenerator metadataGenerator = new MetadataGenerator();
//    metadataGenerator.setEntityId("http://localhost:8080/saml/metadata");
    metadataGenerator.setEntityId("local-idp-test");
    metadataGenerator.setExtendedMetadata(extendedMetadata());
    metadataGenerator.setIncludeDiscoveryExtension(false);
    metadataGenerator.setKeyManager(keyManager());
    return metadataGenerator;
  }

  @Bean
  public ExtendedMetadata extendedMetadata() {
    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    extendedMetadata.setIdpDiscoveryEnabled(true);
    extendedMetadata.setSignMetadata(true);
    return extendedMetadata;
  }


  @Bean
  public SAMLDiscovery samlIDPDiscovery() {
    SAMLDiscovery idpDiscovery = new SAMLDiscovery();
    idpDiscovery.setIdpSelectionPath("/saml/discovery");
    return idpDiscovery;
  }

  // Bindings
  private ArtifactResolutionProfile artifactResolutionProfile() {
    final ArtifactResolutionProfileImpl artifactResolutionProfile =
        new ArtifactResolutionProfileImpl(httpClient());
    artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
    return artifactResolutionProfile;
  }

  @Bean
  public HttpClient httpClient() {
    return new HttpClient(new MultiThreadedHttpConnectionManager());
  }



  @Bean
  public HTTPArtifactBinding artifactBinding(ParserPool parserPool) {
    return new HTTPArtifactBinding(parserPool, velocityEngine(), artifactResolutionProfile());
  }

  @Bean
  public HTTPSOAP11Binding soapBinding() {
    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  public HTTPPostBinding httpPostBinding() {
    return new HTTPPostBinding(parserPool(), velocityEngine());
  }

  @Bean
  public VelocityEngine velocityEngine() {
    return VelocityFactory.getEngine();
  }

  @Bean
  public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
    return new HTTPRedirectDeflateBinding(parserPool());
  }

  @Bean
  public HTTPSOAP11Binding httpSOAP11Binding() {
    return new HTTPSOAP11Binding(parserPool());
  }

  @Bean
  public HTTPPAOS11Binding httpPAOS11Binding() {
    return new HTTPPAOS11Binding(parserPool());
  }

  // Processor
  @Bean
  public SAMLProcessorImpl processor() {
    Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
    bindings.add(httpRedirectDeflateBinding());
    bindings.add(httpPostBinding());
    bindings.add(artifactBinding(parserPool()));
    bindings.add(httpSOAP11Binding());
    bindings.add(httpPAOS11Binding());
    return new SAMLProcessorImpl(bindings);
  }

  // SAML 2.0 WebSSO Assertion Consumer
  @Bean
  public WebSSOProfileConsumer webSSOprofileConsumer() {
    return new WebSSOProfileConsumerImpl();
  }

  // SAML 2.0 Web SSO profile
  @Bean
  public WebSSOProfile webSSOprofile() {
    return new WebSSOProfileImpl();
  }

  @Bean
  public SingleLogoutProfile logoutprofile() {
    return new SingleLogoutProfileImpl();
  }

  @Bean
  public TLSProtocolConfigurer tlsProtocolConfigurer() {
    final TLSProtocolConfigurer configurer = new TLSProtocolConfigurer();
    configurer.setKeyManager(keyManager());
    configurer.setSslHostnameVerification("allowAll");
    return configurer;
  }

  @Bean
  public ProtocolSocketFactory socketFactory() {
    final TLSProtocolSocketFactory factory = new TLSProtocolSocketFactory(keyManager(), null, "allowAll");
    return factory;
  }

  @Bean
  public Protocol socketFactoryProtocol() {
    return new Protocol("https", socketFactory(), 443);
  }

  @Bean
  public MethodInvokingFactoryBean socketFactoryInitialization() {
    MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
    methodInvokingFactoryBean.setTargetClass(Protocol.class);
    methodInvokingFactoryBean.setTargetMethod("registerProtocol");
    Object[] args = {"https", socketFactoryProtocol()};
    methodInvokingFactoryBean.setArguments(args);
    return methodInvokingFactoryBean;
  }


}
