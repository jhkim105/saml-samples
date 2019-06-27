package com.example.demo.security;


import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

@Controller
@RequiredArgsConstructor
@RequestMapping("/saml2")
public class SAMLController {

  private final SamlService samlService;

  @RequestMapping(value = "/login")
  public String login(HttpServletRequest request, HttpServletResponse response, String username) {
    String metadataUrl = samlService.loadIdpMetadata(username);
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
