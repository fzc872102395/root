package com.example.rsa.Rsa;

import com.example.rsa.Annotation.Encrypt;
import com.example.rsa.Model.RespBean;
import com.example.rsa.Properties.RsaProperties;
import com.example.rsa.Utils.RSAUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.security.PublicKey;

@EnableConfigurationProperties(RsaProperties.class)
@ControllerAdvice
public class EncryptResponse implements ResponseBodyAdvice<RespBean> {
    private ObjectMapper om = new ObjectMapper();
    @Autowired
    RsaProperties rsaProperties;
    PublicKey publicKey = RSAUtils.getPublicKey(rsaProperties.getPublicKey());
    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType){
        return returnType.hasMethodAnnotation(Encrypt.class);
    }
    @Override
    public RespBean beforeBodyWrite(RespBean body, MethodParameter returnType, MediaType selectedContentType, Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request, ServerHttpResponse response){
        try {
            if(body.getMsg() != null){
                body.setMsg((RSAUtils.encrypt(body.getMsg(),publicKey)));
            }
            if(body.getObj() != null){
                body.setObj(RSAUtils.encrypt(om.writeValueAsString(body.getObj()),publicKey));
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return body;
    }
}