<?php

/**
 * Linna Framework.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@alice.it>
 * @copyright (c) 2018, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\Tests;

use Linna\Authentication\Password;
use Linna\Authentication\UserMapper;
use Linna\Authorization\PermissionMapper;
use Linna\Authorization\RoleMapper;
use Linna\Authorization\RoleToUserMapper;
use Linna\Storage\StorageFactory;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Role Mapper Test.
 */
class RoleMapperTest extends TestCase
{
    /**
     * @var RoleMapper
     */
    protected $roleMapper;

    /**
     * Setup.
     */
    public function setUp(): void
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
        $role2userMapper = new RoleToUserMapper($pdo, $password);
        //$roleMapper = new RoleMapper($pdo, $permissionMapper, $userMapper, $role2userMapper);
        //$enhancedUserMapper = new EnhancedUserMapper($pdo, $password, $permissionMapper, $role2userMapper);

        $this->roleMapper = new RoleMapper($pdo, $permissionMapper, $userMapper, $role2userMapper);
    }

    /**
     * Test new instance.
     */
    public function testNewInstance()
    {
        $this->assertInstanceOf(RoleMapper::class, $this->roleMapper);
    }
}
