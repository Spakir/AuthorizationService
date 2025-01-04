package org.example.authorizationservice.mapper;

import org.example.authorizationservice.dto.UserDto;
import org.example.authorizationservice.model.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserDto toDto(User user);

    User toUser(UserDto userDto);
}
