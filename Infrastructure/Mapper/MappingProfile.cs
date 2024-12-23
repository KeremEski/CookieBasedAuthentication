using CookieBasedAuthentication.Models;
using CookieBasedAuthentication.Models.Dtos;
using AutoMapper;

namespace CookieBasedAuthentication.Infrastructure.Mapper;

// Created Mapper profile. You dont need to use mapper. It's optional.
public class MappingProfile : Profile
{
    public MappingProfile()
    {
        CreateMap<RegisterDto,User>();
        CreateMap<User,RegisterDto>();
        CreateMap<User,LoginDto>();
        CreateMap<LoginDto,User>();
    }
}