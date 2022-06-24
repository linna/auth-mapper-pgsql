<?php

/**
 * Linna Framework.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\Tests;

use Linna\Authentication\Password;
use Linna\Authorization\EnhancedUserMapper;
use Linna\Authorization\PermissionMapper;
use Linna\Authorization\RoleMapper;
use Linna\Authorization\RoleToUserMapper;
use Linna\Authentication\UserMapper;
use Linna\Storage\StorageFactory;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Enhanced User Mapper Test.
 */
class EnhancedUserMapperTest extends TestCase
{
    use EnhancedUserMapperTrait;

    /**
     * Setup.
     *
     * @return void
     */
    public static function setUpBeforeClass(): void
    {
        $options = [
            'dsn'      => $GLOBALS['pdo_pgsql_dsn'],
            'user'     => $GLOBALS['pdo_pgsql_user'],
            'password' => $GLOBALS['pdo_pgsql_password'],
            'options'  => [
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_OBJ,
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_PERSISTENT         => false,
            ],
        ];

        $pdo = (new StorageFactory('pdo', $options))->get();
        $password = new Password();

        $permissionMapper = new PermissionMapper($pdo);
        $role2userMapper = new RoleToUserMapper($pdo, $password);
        $userMapper = new UserMapper($pdo, $password);

        self::$pdo = $pdo;
        self::$permissionMapper = $permissionMapper;
        self::$roleMapper = new RoleMapper($pdo, $permissionMapper, $userMapper, $role2userMapper);
        self::$enhancedUserMapper = new EnhancedUserMapper($pdo, $password, $permissionMapper, $role2userMapper);
    }
}
