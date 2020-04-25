package ua.kiev.prog;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String login)
            throws UsernameNotFoundException {
        CustomUser customUser = Objects.requireNonNull(Jaxb.fromXML()).findByLogin(login);
        if (customUser == null)
            throw new UsernameNotFoundException(login + " not found");

        List<GrantedAuthority> roles =
                Collections.singletonList(
                        new SimpleGrantedAuthority(customUser.getRole().toString()));

        return new User(customUser.getLogin(),
                customUser.getPassword(), roles);
    }
}