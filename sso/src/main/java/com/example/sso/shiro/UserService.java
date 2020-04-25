package com.example.sso.shiro;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class UserService {
    private StringRedisTemplate stringRedisTemplate;
    public UserService(){

    }

    @Autowired
    public UserService(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
    }

    public String generateJwtToken(String username){
        //加密JWT的盐
        //String salt = "9723612f53";
        String salt = JwtUtils.generateSalt();

        //redis缓存salt
        stringRedisTemplate.opsForValue().set("token:"+username, salt, 3600, TimeUnit.SECONDS);
        return JwtUtils.sign(username,salt,5*60);//生成jwt token，设置过期时间为1小时
    }

    /*
     * 获取上次token生成时的salt值和登录用户信息*/
    public UserDto getJwtToken(String username) {
        //String salt = "9723612f53";
        //从数据库或者缓存中取出jwt token生成时用的salt
        String salt = stringRedisTemplate.opsForValue().get("token:"+username);
        UserDto userDto = this.getUserInfo(username);
        userDto.setSalt(salt);
        return userDto;
    }

    /**
     * 获取数据库中保存的用户信息，主要是加密后的密码.这里省去了DB操作，直接生成了用户信息
     * @param username
     * @return
     */
    public UserDto getUserInfo(String username){
        UserDto user =  new UserDto();
        user.setUserId(1L);
        user.setUsername("admin");
        //模拟对密码加密
        user.setEncryptPwd(new Sha256Hash("admin123",JwtUtils.PASSWORD_ENCRYPTED).toHex());
        log.debug("UserService: [{}]",user.toString());
        return user;
    }

    /**清除token信息*/
    public void deleteLogInfo(String username){
        // 删除数据库或者缓存中保存的salt
        stringRedisTemplate.delete("token:"+username);
    }

    /**获取用户角色列表，强烈建议从缓存中获取*/
    public List<String> getUserRoles(Long userId){
        //模拟admin角色
        return Arrays.asList("admin");
    }
}
