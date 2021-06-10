package com.paulius.LoginLogoutEmailVerification.email;

public interface EmailSender {

    void send(String to, String email);
}
