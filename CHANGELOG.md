
# Linna Auth Mapper Postgresql Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [v0.2.1](https://github.com/linna/auth-mapper-pgsql/compare/v0.2.0...v0.2.1) - 2022-10-24

### Changed
* `auth-mapper-test-trait` version fixed to `^0.2` from `dev-master` as development aid

## [v0.2.0](https://github.com/linna/auth-mapper-pgsql/compare/v0.2.0...master) - 2022-10-03

* Start with v0.2.0 for match `auth-mapper-mysql` version

### Changed
* PHP 8.1 required
* strict typing updated to provide compatibility with the next version of the framework
* `composer.json` `require` and `require-dev` sections updated
* tests updated

### Added
* `Linna\Authentication\EnhancedAuthenticationMapper` class
* `Linna\Authentication\UserMapper` class
* `Linna\Authorization\EnhancedUserMapper` class
* `Linna\Authorization\PermissionMapper` class
* `Linna\Authorization\RoleMapper` class
* `Linna\Authorization\RoleToUserMapper` class
