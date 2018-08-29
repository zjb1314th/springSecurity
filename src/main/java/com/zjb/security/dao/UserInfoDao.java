package com.zjb.security.dao;

import com.zjb.security.model.UserInfo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserInfoDao {

    UserInfo findByUsername(String username);
}
