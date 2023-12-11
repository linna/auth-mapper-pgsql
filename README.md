<div align="center">
    <a href="#"><img src="logo-linna-128.png" alt="Linna Logo"></a>
</div>

<br/>

<div align="center">
    <a href="#"><img src="logo-auth-pgsql.png" alt="Linna Auth Mapper Pgsql Logo"></a>
</div>

<br/>

<div align="center">

[![Tests](https://github.com/linna/auth-mapper-pgsql/actions/workflows/tests.yml/badge.svg)](https://github.com/linna/auth-mapper-pgsql/actions/workflows/tests.yml)
[![PDS Skeleton](https://img.shields.io/badge/pds-skeleton-blue.svg?style=flat)](https://github.com/php-pds/skeleton)
[![PHP 8.1](https://img.shields.io/badge/PHP-8.1-8892BF.svg)](http://php.net)

</div>

> **_NOTE:_**  Code porting to PHP 8.1 ongoing.

# About
This package provide a concrete implementation for the authentication interfaces and 
for the authorization interfaces of the framework.

Mappers use as persistent storage postgresql through php pdo.

# Requirements
   
   * PHP >= 8.1
   * PDO extension
   * Postgresql extension
   * linna/framework v0.28.0|next

# Installation
With composer:
```
composer require linna/auth-mapper-pgsql
```

# Package Content

### Interfaces from Framework
* `Linna\Authentication\EnhancedAuthenticationMapperInterface`
* `Linna\Authorization\PermissionExtendedMapperInterface`
* `Linna\Authorization\PermissionMapperInterface`
* `Linna\Authorization\RoleExtendedMapperInterface`
* `Linna\Authorization\RoleMapperInterface`
* `Linna\Authorization\UserExtendedMapperInterface`
* `Linna\Authorization\UserMapperInterface`

### Implementation
* `Linna\Authentication\EnhancedAuthenticationMapper`
    - deleteOldLoginAttempts()
    - fetchAll()
    - fetchAttemptsWithSameIp()
    - fetchAttemptsWithSameSession()
    - fetchAttemptsWithSameUser()
    - fetchById()
    - fetchLimit()
* `Linna\Authorization\PermissionExtendedMapper`
* `Linna\Authorization\PermissionMapper`
    - fetchAll()
    - fetchById()
    - fetchByName()
    - fetchByRole()
    - fetchByRoleId()
    - fetchByRoleName()
    - fetchByUser()
    - fetchByUserId()
    - fetchByUserName()
    - fetchLimit()
    - fetchUserPermissionHashTable()
    - permissionExistById()
    - permissionExistByName()
* `Linna\Authorization\RoleExtendedMapper`
    - addUser()
    - addUserById()
    - addUserByName()
    - grantPermission()
    - grantPermissionById()
    - grantPermissionByName()
    - removeUser()
    - removeUserById()
    - removeUserByName()
    - revokePermission()
    - revokePermissionById()
    - revokePermissionByName()
* `Linna\Authorization\RoleMapper`
    - fetchAll()
    - fetchById()
    - fetchByName()
    - fetchByPermission()
    - fetchByPermissionId()
    - fetchByPermissionName()
    - fetchByUser()
    - fetchByUserId()
    - fetchByUserName()
    - fetchLimit()
* `Linna\Authorization\UserExtendedMapper`
    - addRole()
    - addRoleById()
    - addRoleByName()
    - grantPermission()
    - grantPermissionById()
    - grantPermissionByName()
    - removeRole()
    - removeRoleById()
    - removeRoleByName()
    - revokePermission()
    - revokePermissionById()
    - revokePermissionByName()
* `Linna\Authorization\UserMapper`
    - fetchAll()
    - fetchById()
    - fetchByName()
    - fetchByPermission()
    - fetchByPermissionId()
    - fetchByPermissionName()
    - fetchByRole()
    - fetchByRoleId()
    - fetchByRoleName()
    - fetchLimit()