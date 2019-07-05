package com.example.demo.user;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/signup")
@RequiredArgsConstructor
@Slf4j
public class SignupController {

  private final UserService userService;

  @GetMapping
  public String signupForm() {
    log.debug("/signup");
    return "signup";
  }

  @PostMapping
  @ResponseBody
  public ResponseEntity signup(SignupForm signupForm) {
    userService.signup(signupForm);
    return ResponseEntity.ok().build();
  }

}
