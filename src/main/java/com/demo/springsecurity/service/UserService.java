package com.demo.springsecurity.service;

import com.demo.springsecurity.dao.UserDao;
import com.demo.springsecurity.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class UserService {

    @Autowired
    private UserDao userDao;
    private PasswordEncoder passwordEncoder;

    public void initRoleAndUser() {
        User adminUser = new User();
        adminUser.setUserName("admin123");
        adminUser.setUserPassword(getEncodedPassword("admin@pass"));
        userDao.save(adminUser);
    }

    public User registerNewUser(User user) {
        user.setUserPassword(getEncodedPassword(user.getUserPassword()));

        return userDao.save(user);
    }

    public String getEncodedPassword(String password) {
        return passwordEncoder.encode(password);
    }
}