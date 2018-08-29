package com.zjb.security.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class UserInfo {

    private int id;

    private String username;

    private String password;

    private String role;
}
