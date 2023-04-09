package com.vladimirpandurov.supportportalB.service.impl;

import com.vladimirpandurov.supportportalB.domain.User;
import com.vladimirpandurov.supportportalB.domain.UserPrincipal;
import com.vladimirpandurov.supportportalB.repository.UserRepository;
import com.vladimirpandurov.supportportalB.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Date;

@Service
@Transactional
@Qualifier("userDetailsService")
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = this.userRepository.findUserByUsername(username);
        if(user == null){
            log.error("User not found by username: " + username);
            throw new UsernameNotFoundException("User not found by username: " + username);
        }else{
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            user.setLastLoginDate(new Date());
            this.userRepository.save(user);
            UserPrincipal userPrincipal = new UserPrincipal(user);
            log.info("Returning found user  byy username: " + username);
            return userPrincipal;
        }
    }

}
