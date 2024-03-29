<?php

/**
 * Linna Framework.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\Authorization;

use Linna\Authentication\Password;
//use Linna\Authentication\UserMapper;
use Linna\Storage\StorageFactory;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Role Mapper Test.
 */
class RoleExtendedMapperTest extends TestCase
{
    use RoleExtendedMapperTrait;

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
                PDO::ATTR_PERSISTENT         => false
            ],
        ];

        $pdo = (new StorageFactory('pdo', $options))->get();
        $password = new Password();

        $permissionMapper = new PermissionMapper($pdo);
        $userMapper = new UserMapper($pdo, $password);

        $roleExtendedMapper = new RoleExtendedMapper($pdo, $permissionMapper, $userMapper);

        //declared in trait
        self::$pdo = $pdo;
        self::$permissionMapper = $permissionMapper;
        self::$userMapper = $userMapper;
        self::$roleExtendedMapper = $roleExtendedMapper;
    }
}
