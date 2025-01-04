package org.example.authorizationservice.dto;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@ToString(exclude = "id")
@EqualsAndHashCode
public class UserDto {
    private Long id;

    private String username;

    private String password;

    private Set<String> roles = new HashSet<>();
}
