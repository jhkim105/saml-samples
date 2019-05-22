package com.example.demo.onelogin;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * https://developers.onelogin.com/saml/java
 *
 */


@RequestMapping("/onelogin")
@Controller
@Slf4j
public class OneloginController {


  @RequestMapping("/metadata")
  @ResponseBody
  public String metadata() {
    try {
      Auth auth = new Auth();
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


  @RequestMapping("/login")
  @ResponseBody
  public ResponseEntity login(HttpServletRequest request, HttpServletResponse response) {
    try {
      Auth auth = new Auth(request, response);
      auth.login();
      return new ResponseEntity(HttpStatus.OK);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @RequestMapping("/logout")
  @ResponseBody
  public ResponseEntity logout(HttpServletRequest request, HttpServletResponse response, HttpSession session) {
    try {
      Auth auth = new Auth(request, response);

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

  @RequestMapping("/sls")
  public void sls(HttpServletRequest request, HttpServletResponse response) {
    try {
      Auth auth = new Auth(request, response);
      auth.processSLO();

      PrintWriter out = response.getWriter();
      List<String> errors = auth.getErrors();
      if (errors.isEmpty()) {
        out.println("<p>Sucessfully logged out</p>");
        out.println("<a href=\"dologin.jsp\" class=\"btn btn-primary\">Login</a>");
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

  @RequestMapping("/acs")
  public String acs(HttpServletRequest request, HttpServletResponse response, Model model) {
    try {
      Auth auth = new Auth(request, response);
      auth.processResponse();
      if (!auth.isAuthenticated()) {
        throw new RuntimeException("Not Authenticated");
      }
      List<String> errors = auth.getErrors();
      if (errors.isEmpty()) {
        String relayState = request.getParameter("RelayState");
        if (relayState != null && !relayState.isEmpty() && !relayState.equals(ServletUtils.getSelfRoutedURLNoQuery(request)) &&
            !relayState.contains("/onelogin/login")) { // We don't want to be redirected to login neither
          log.debug("redirect to login, relayState:{}", relayState);
          response.sendRedirect(request.getParameter("RelayState"));
        } else {
          Map<String, List<String>> attributes = auth.getAttributes();
          model.addAttribute("attributes", attributes);
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
