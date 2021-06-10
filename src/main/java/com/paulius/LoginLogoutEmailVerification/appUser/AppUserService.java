package com.paulius.LoginLogoutEmailVerification.appUser;

import com.paulius.LoginLogoutEmailVerification.registration.token.ConfirmationToken;
import com.paulius.LoginLogoutEmailVerification.registration.token.ConfirmationTokenService;
import com.paulius.LoginLogoutEmailVerification.security.PasswordEncoder;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;
//this class will implement UserDetails service interface specificly for security
//how we find users when we log in

@AllArgsConstructor
@Service
public class AppUserService implements UserDetailsService {
   private final static String NOT_FOUND_MSG= "User with email %s not found";


    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return appUserRepository.findByEmail(email)
                .orElseThrow(
                        ()-> new UsernameNotFoundException(String.format(NOT_FOUND_MSG, email)));
    }

    public String signUpUser(AppUser appUser) {
        boolean userExists = appUserRepository.findByEmail(appUser.getEmail())
                .isPresent();
        if (userExists) {
            throw new IllegalStateException("email already taken");
        }

       String encodedPassword =
               bCryptPasswordEncoder.encode(appUser.getPassword());

        appUser.setPassword(encodedPassword);

        appUserRepository.save(appUser);

        String token = UUID.randomUUID().toString();
        //TODO: send confirmation token - done.
        ConfirmationToken confirmationToken = new ConfirmationToken(
            token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                appUser
        );
        confirmationTokenService.saveConfirmationToken(confirmationToken);

        return token;
    }
    public int enableAppUser(String email) {
        return appUserRepository.enableAppUser(email);
    }
}
