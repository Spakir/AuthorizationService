package org.example.authorizationservice.service;

import jakarta.persistence.EntityExistsException;
import lombok.RequiredArgsConstructor;
import org.example.authorizationservice.dto.UserDto;
import org.example.authorizationservice.mapper.UserMapper;
import org.example.authorizationservice.model.CustomUserDetails;
import org.example.authorizationservice.model.User;
import org.example.authorizationservice.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDto user = userRepository.findByUsername(username)
                .map(userMapper::toDto)
                .orElseThrow();
        return new CustomUserDetails(user);
    }

    public UserDto saveUser(UserDto userDto) {

        if (!userRepository.existsByUsername(userDto.getUsername())) {
            String rawPassword = userDto.getPassword();
            userDto.setRoles(Set.of("ROLE_USER"));
            userDto.setPassword(passwordEncoder.encode(rawPassword));

            var savedUser = userRepository.save(userMapper.toUser(userDto));

            return userMapper.toDto(savedUser);
        }else{
            throw new EntityExistsException();
        }
    }
}
