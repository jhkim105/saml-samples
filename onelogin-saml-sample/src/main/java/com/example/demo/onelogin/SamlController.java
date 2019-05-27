package com.example.demo.onelogin;

import com.example.demo.user.Idp;
import com.example.demo.user.SamlSetting;
import com.example.demo.user.User;
import com.example.demo.user.UserRepository;
import com.onelogin.saml2.Auth;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * https://developers.onelogin.com/saml/java
 *
 */


@RequestMapping("/saml")
@Controller
@Slf4j
@RequiredArgsConstructor
public class SamlController {

  private final UserRepository userRepository;

  @RequestMapping("/{idp}/metadata")
  @ResponseBody
  public String metadata(@PathVariable Idp idp, @RequestParam String username, HttpServletRequest request, HttpServletResponse response) {
    try {
      Saml2Settings saml2Settings = loadSaml2Settings(idp, username);
      Auth auth = new Auth(saml2Settings, request, response);
      Saml2Settings settings = auth.getSettings();
      settings.setSPValidationOnly(true);
      String metadata = settings.getSPMetadata();
      List<String> errors = Saml2Settings.validateMetadata(metadata);
      if (errors.isEmpty()) {
        return metadata;
      } else {
        return StringUtils.join(errors, System.lineSeparator()); // TODO
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }


  @RequestMapping("/{idp}/login")
  @ResponseBody
  public ResponseEntity login(@PathVariable Idp idp, @RequestParam String username,  HttpServletRequest request, HttpServletResponse response) {
    try {
      Saml2Settings saml2Settings = loadSaml2Settings(idp, username);
      Auth auth = new Auth(saml2Settings, request, response);
      auth.login();
      return new ResponseEntity(HttpStatus.OK);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private Saml2Settings loadSaml2Settings(Idp idp, String username) {
    User user = userRepository.findByUsername(username);
    Properties prop = new Properties();
    loadSp(prop, idp, username);
    loadIdp(prop, idp, user);
    return new SettingsBuilder().fromProperties(prop).build();
  }

  private void loadSp(Properties prop, Idp idp, String username) {
    String idpl = idp.toString().toLowerCase();
    prop.setProperty(SettingsBuilder.SP_ENTITYID_PROPERTY_KEY, String.format("http://localhost:8080/saml/%s/metadata?username=%s", idpl, username));
    prop.setProperty(SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, String.format("https://localhost:8443/saml/%s/acs?username=%s", idpl, username));
    prop.setProperty(SettingsBuilder.SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, String.format("http://localhost:8080/saml/%s/sls?username=%s", idpl, username));
  }

  private void loadIdp(Properties prop, Idp idp, User user) {
    SamlSetting samlSetting = user.getSamlSetting(idp).get();
    prop.setProperty(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY, samlSetting.getEntityId());
    prop.setProperty(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY, samlSetting.getSsoUrl());
    prop.setProperty(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, samlSetting.getSloUrl());
    prop.setProperty(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY, samlSetting.getCert());
  }


  @RequestMapping("/{idp}/logout")
  public ResponseEntity logout(@PathVariable Idp idp, @RequestParam String username,HttpServletRequest request, HttpServletResponse response, HttpSession session) {
    try {
      Saml2Settings saml2Settings = loadSaml2Settings(idp, username);
      Auth auth = new Auth(saml2Settings, request, response);

      String nameId = null;
      if (session.getAttribute("nameId") != null) {
        nameId = session.getAttribute("nameId").toString();
      }
      String nameIdFormat = null;
      if (session.getAttribute("nameIdFormat") != null) {
        nameIdFormat = session.getAttribute("nameIdFormat").toString();
      }
      String nameidNameQualifier = null;
      if (session.getAttribute("nameidNameQualifier") != null) {
        nameIdFormat = session.getAttribute("nameidNameQualifier").toString();
      }
      String nameidSPNameQualifier = null;
      if (session.getAttribute("nameidSPNameQualifier") != null) {
        nameidSPNameQualifier = session.getAttribute("nameidSPNameQualifier").toString();
      }
      String sessionIndex = null;
      if (session.getAttribute("sessionIndex") != null) {
        sessionIndex = session.getAttribute("sessionIndex").toString();
      }
      auth.logout(null, nameId, sessionIndex, nameIdFormat, nameidNameQualifier, nameidSPNameQualifier);
      return new ResponseEntity(HttpStatus.OK);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @RequestMapping("/{idp}/sls")
  public void sls(@PathVariable Idp idp, @RequestParam String username, HttpServletRequest request, HttpServletResponse response) {
    try {
      Saml2Settings saml2Settings = loadSaml2Settings(idp, username);
      Auth auth = new Auth(saml2Settings, request, response);
      auth.processSLO();

      PrintWriter out = response.getWriter();
      List<String> errors = auth.getErrors();
      if (errors.isEmpty()) {
        out.println("<p>Sucessfully logged out</p>");
        out.println(String.format("<a href=\"/saml/%s/login\" class=\"btn btn-primary\">Login</a>", idp.toString().toLowerCase()));
      } else {
        out.println("<p>");
        for (String error : errors) {
          out.println(" " + error + ".");
        }
        out.println("</p>");
      }
    } catch(Exception e) {
      throw new RuntimeException(e);
    }
  }

  @RequestMapping("/{idp}/acs")
  public String acs(@PathVariable Idp idp, @RequestParam String username,HttpServletRequest request, HttpServletResponse response, Model model) {
    try {
      Saml2Settings saml2Settings = loadSaml2Settings(idp, username);
      Auth auth = new Auth(saml2Settings, request, response);
      auth.processResponse();
      if (!auth.isAuthenticated()) {
        throw new RuntimeException("Not Authenticated");
      }
      List<String> errors = auth.getErrors();
      if (errors.isEmpty()) {
        String relayState = request.getParameter("RelayState");
        if (relayState != null && !relayState.isEmpty() && !relayState.equals(ServletUtils.getSelfRoutedURLNoQuery(request)) &&
            !relayState.contains(String.format("/%s/login", idp.toString().toLowerCase()))) { // We don't want to be redirected to login neither
          log.debug("redirect to login, relayState:{}", relayState);
          response.sendRedirect(request.getParameter("RelayState"));
        } else {
          Map<String, List<String>> attributes = auth.getAttributes();
          model.addAttribute("attributes", attributes);
          model.addAttribute("idp", idp.getValue());
          log.debug("attributes -> {}", attributes);
          printAttribute(attributes);
        }

      } else {
        model.addAttribute("errors", errors);
        log.debug("errors -> {}", errors);
      }
      return "onelogin/acs";
    } catch(Exception e) {
      throw new RuntimeException(e);
    }

  }

  private void printAttribute(Map<String, List<String>> attributes) {
    Collection<String> names = attributes.keySet();
    if (names.isEmpty())
      return;
    for(String name : attributes.keySet()) {
      log.debug("name: {}", name);
      if(attributes.get(name).isEmpty())
        return;
      for(String value : attributes.get(name)) {
        log.debug("\tvalue:{}", value);
      }
    }
  }
}
