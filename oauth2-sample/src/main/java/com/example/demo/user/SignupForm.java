package com.example.demo.user;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class SignupForm {
  private String email;

  private String fullName;

  private String password;

  private String confirmPassword;

  public User toUser() {
    // @formatter:off
    User user = User.builder()
        .email(this.email)
        .password(this.password)
        .authorities(Authority.getDefaultAuthorites())
        .build();

    return user;
    // @formatter:on
  }

}
