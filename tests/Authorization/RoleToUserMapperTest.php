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
//use Linna\Authentication\UserMapper;
//use Linna\Authorization\EnhancedUserMapper;
//use Linna\Authorization\PermissionMapper;
//use Linna\Authorization\RoleMapper;
use Linna\Authorization\RoleToUserMapper;
use Linna\Storage\StorageFactory;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Role To User Mapper Test.
 */
class RoleToUserMapperTest extends TestCase
{
    /**
     * @var RoleToUserMapper
     */
    protected $roleToUserMapper;

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

        $this->roleToUserMapper = new RoleToUserMapper((new StorageFactory('pdo', $options))->get(), new Password());
    }

    /**
     * Test new instance.
     */
    public function testNewInstance()
    {
        $this->assertInstanceOf(RoleToUserMapper::class, $this->roleToUserMapper);
    }
}
