package com.example.demo.security;


import com.example.demo.user.Idp;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

@Controller
@RequiredArgsConstructor
@RequestMapping("/saml2")
public class SAMLController {

  private final SamlService samlService;

  @RequestMapping(value = "/{idp}")
  public String login(HttpServletRequest request, HttpServletResponse response, @PathVariable Idp idp, String username) {
    if (idp == Idp.LINEWORKS) {
      throw new NotImplementedException(); //IdpMetadata URL을 제공하지 않음.
    }

    String metadataUrl = samlService.loadIdpMetadata(idp, username);
    String result = "redirect:/saml/login?idp=" + urlEncode(metadataUrl);
    return result;
  }





  private String urlEncode(String entityId) {
    try {
      return URLEncoder.encode(entityId, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }


}
