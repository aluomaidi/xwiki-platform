package com.xpn.xwiki.user.impl.xwiki;

import java.io.Serializable;

public class SSOUser implements Serializable
{
    private static final long serialVersionUID = 2498245261087924075L;
    private String userId;
    private String accountName;
    private String name;
    private Integer userSource;
    private Long timestamp;

    public SSOUser() {
    }

    public SSOUser(com.ifly.qxb.uap.client.entity.SSOUser ssoUser) {
        this.userId = ssoUser.getUserId();
        this.accountName = ssoUser.getAccountName();
        this.name = ssoUser.getName();
        this.userSource = ssoUser.getUserSource();
        this.timestamp = ssoUser.getTimestamp();
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String userId) {
        this.userId = userId == null ? null : userId.trim();
    }

    public String getAccountName() {
        return this.accountName;
    }

    public void setAccountName(String accountName) {
        this.accountName = accountName == null ? null : accountName.trim();
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name == null ? null : name.trim();
    }

    public Integer getUserSource() {
        return this.userSource;
    }

    public void setUserSource(Integer userSource) {
        this.userSource = userSource;
    }

    public Long getTimestamp() {
        return this.timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }
}
