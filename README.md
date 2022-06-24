<div align="center">
    <a href="#"><img src="logo-linna-96.png" alt="Linna Logo"></a>
</div>

<br/>

<div align="center">
    <a href="#"><img src="logo-auth-pgsql.png" alt="Linna Auth Mapper Pgsql Logo"></a>
</div>

<br/>

<div align="center">

[![StyleCI](https://github.styleci.io/repos/209962835/shield?branch=master&style=flat)](https://github.styleci.io/repos/209962835)
[![PDS Skeleton](https://img.shields.io/badge/pds-skeleton-blue.svg?style=flat)](https://github.com/php-pds/skeleton)
[![PHP 8.1](https://img.shields.io/badge/PHP-8.1-8892BF.svg)](http://php.net)

</div>

> **_NOTE:_**  Code porting to PHP 8.1 ongoing.

# About
This package provide a concrete implementation for authentication interfaces and 
for the authorization interfaces of the framework.

Mappers use as persistent storage postgresql through php pdo.

# Requirements
   
   * PHP >= 8.1
   * PDO extension
   * Postgresql extension
   * linna/framework v0.27.0

# Installation
With composer:
```
composer require linna/auth-mapper-pgsql
```

# Package Content
Implementation of framework interfaces:
* `Linna\Authentication\EnhancedAuthenticationMapperInterface`
* `Linna\Authentication\UserMapperInterface`
* `Linna\Authorization\EnhancedUserMapperInterface`
* `Linna\Authorization\PermissionMapperInterface`
* `Linna\Authorization\RoleMapperInterface`
* `Linna\Authorization\RoleToUserMapperInterface`

As:
* `Linna\Authentication\EnhancedAuthenticationMapper`
* `Linna\Authentication\UserMapper`
* `Linna\Authorization\EnhancedUserMapper`
* `Linna\Authorization\PermissionMapper`
* `Linna\Authorization\RoleMapper`
* `Linna\Authorization\RoleToUserMapper`