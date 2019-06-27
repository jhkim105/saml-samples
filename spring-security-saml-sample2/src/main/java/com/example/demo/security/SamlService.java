package com.example.demo.security;

import com.example.demo.user.Idp;
import com.example.demo.user.User;
import com.example.demo.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.commons.httpclient.HttpClient;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.Timer;

@Service
@RequiredArgsConstructor
public class SamlService {

  private final MetadataManager metadataManager;

  private final ParserPool parserPool;

  private final UserRepository userRepository;

  public String loadIdpMetadata(String username) {
    User user = userRepository.findByUsername(username);
    String companyDomainName = user.getCompanyDomainName();
    String idpMetadataUrl = getMetadataUrl(user);
    Timer backgroundTaskTimer = new Timer(true);
    HTTPMetadataProvider httpMetadataProvider;
    try {
      httpMetadataProvider = new HTTPMetadataProvider(backgroundTaskTimer, new HttpClient(), idpMetadataUrl);
      httpMetadataProvider.setParserPool(parserPool);
      ExtendedMetadata metadata = new ExtendedMetadata();
      metadata.setLocal(true);
      metadata.setAlias(companyDomainName);

      ExtendedMetadataDelegate provider = new ExtendedMetadataDelegate(httpMetadataProvider, metadata);
      try {
        provider.initialize();
      } catch (MetadataProviderException e) {
        throw new RuntimeException();
      }
      provider.setMetadataTrustCheck(false);
      provider.setMetadataRequireSignature(false);
      backgroundTaskTimer.purge();

      Set<String> newEntityIds = parseProvider(provider);
      Set<String> existingEntityIds = metadataManager.getIDPEntityNames();
      if (!existingEntityIds.containsAll(newEntityIds)) {
        metadataManager.addMetadataProvider(provider);
        metadataManager.refreshMetadata();
      }

      String entityId = metadataManager.getEntityIdForAlias(companyDomainName);
      return entityId;
    } catch (MetadataProviderException e) {
      throw new RuntimeException(e);
    }
  }

  private String getMetadataUrl(User user) {
    return user.getSamlSetting(Idp.ONELOGIN).get().getEntityId();
  }


  private Set<String> parseProvider(MetadataProvider provider) {
    Set<String> result = new HashSet<>();

    XMLObject object;
    try {
      object = provider.getMetadata();

      if (object instanceof EntityDescriptor) {
        addDescriptor(result, (EntityDescriptor) object);
      } else if (object instanceof EntitiesDescriptor) {
        addDescriptors(result, (EntitiesDescriptor) object);
      }
      return result;
    } catch (MetadataProviderException e) {
      throw new RuntimeException(e);
    }
  }


  private void addDescriptors(Set<String> result, EntitiesDescriptor descriptors) {
    if (descriptors.getEntitiesDescriptors() != null) {
      for (EntitiesDescriptor descriptor : descriptors.getEntitiesDescriptors()) {
        addDescriptors(result, descriptor);
      }
    }

    if (descriptors.getEntityDescriptors() != null) {
      for (EntityDescriptor descriptor : descriptors.getEntityDescriptors()) {
        addDescriptor(result, descriptor);
      }
    }
  }

  private void addDescriptor(Set<String> result, EntityDescriptor descriptor) {
    String entityID = descriptor.getEntityID();
    result.add(entityID);
  }


}
