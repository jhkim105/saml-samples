package com.example.demo.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

  private final UserRepository userRepository;

  public User signup(SignupForm signupForm) {
    User user = signupForm.toUser();
    userRepository.save(user);
    return user;
  }
}
