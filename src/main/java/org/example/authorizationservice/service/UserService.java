package org.example.authorizationservice.service;

import lombok.RequiredArgsConstructor;
import org.example.authorizationservice.mapper.UserMapper;
import org.example.authorizationservice.repository.UserRepository;
import org.example.dto.UserDto;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    public UserDto getUserById(Long id) {
        return userRepository.findById(id)
                .map(userMapper::toDto)
                .orElseThrow();
    }
}
