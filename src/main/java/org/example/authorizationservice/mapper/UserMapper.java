package org.example.authorizationservice.mapper;


import org.example.authorizationservice.model.User;
import org.example.dto.UserDto;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserDto toDto(User user);

    User toUser(UserDto userDto);
}
