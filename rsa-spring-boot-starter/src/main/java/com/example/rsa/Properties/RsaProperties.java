package com.example.rsa.Properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "spring.rsa")
public class RsaProperties {
    private final static String DEFAULT_PUBLICKEY = "";
    private final static String DEFAULT_PRIVATEKEY  = "";

    private String publicKey = DEFAULT_PUBLICKEY;
    private String privateKey = DEFAULT_PRIVATEKEY;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}
