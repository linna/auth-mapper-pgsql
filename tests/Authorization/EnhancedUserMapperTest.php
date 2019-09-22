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
use Linna\Authorization\EnhancedUserMapper;
use Linna\Authorization\Permission;
use Linna\Authorization\PermissionMapper;
use Linna\Authorization\Role;
use Linna\Authorization\RoleMapper;
use Linna\Authorization\RoleToUserMapper;
use Linna\Authentication\UserMapper;
use Linna\DataMapper\NullDomainObject;
use Linna\DataMapper\UUID4;
use Linna\Storage\StorageFactory;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Enhanced User Mapper Test.
 */
class EnhancedUserMapperTest extends TestCase
{
    /**
     * @var EnhancedUserMapper The enhanced user mapper class.
     */
    protected static $enhancedUserMapper;

    /**
     * @var PermissionMapper The permission mapper class.
     */
    protected static $permissionMapper;

    /**
     * @var RoleMapper The role mapper class.
     */
    protected static $roleMapper;

    /**
     * @var PDO Database connection.
     */
    protected static $pdo;

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

    /**
     * Test new instance.
     *
     * @return void
     */
    public function testNewInstance(): void
    {
        $this->assertInstanceOf(EnhancedUserMapper::class, self::$enhancedUserMapper);
    }

    /**
     * User id provider
     *
     * @return array
     */
    public function userIdProvider(): array
    {
        return [
            [1, 1],
            [2, 2],
            [3, 3],
            [4, 4],
            [5, 5],
            [6, 6],
            [7, 7],
            [8, 0]
        ];
    }

    /**
     * Test fetch by id.
     *
     * @dataProvider userIdProvider
     *
     * @param int $userId
     * @param int $expectedId
     *
     * @return void
     */
    public function testFetchById(int $userId, int $expectedId): void
    {
        $enhancedUser = self::$enhancedUserMapper->fetchById($userId);
        $this->assertEquals($enhancedUser->getId(), $expectedId);
    }

    /**
     * User name provider
     *
     * @return array
     */
    public function userNameProvider(): array
    {
        return [
            ['root', 'root'],
            ['User_0', 'User_0'],
            ['User_1', 'User_1'],
            ['User_2', 'User_2'],
            ['User_3', 'User_3'],
            ['User_4', 'User_4'],
            ['User_5', 'User_5'],
            ['bad_user', '']
        ];
    }

    /**
     * Test fetch by name.
     *
     * @dataProvider userNameProvider
     *
     * @param string $userName
     * @param string $expectedName
     *
     * @return void
     */
    public function testFetchByName(string $userName, string $expectedName): void
    {
        $enhancedUser = self::$enhancedUserMapper->fetchByName($userName);

        if ($expectedName === '') {
            $this->assertInstanceOf(NullDomainObject::class, $enhancedUser);
            return;
        }

        $this->assertEquals($enhancedUser->name, $expectedName);
    }

    /**
     * Test fetch all.
     *
     * @return void
     */
    public function testFetchAll(): void
    {
        $this->assertCount(7, self::$enhancedUserMapper->fetchAll());
    }

    /**
     * User fetch limit provider.
     *
     * @return array
     */
    public function userFetchLimitProvider(): array
    {
        return [
            ['root', 0, 1],
            ['User_0', 1, 1],
            ['User_1', 2, 1],
            ['User_2', 3, 1],
            ['User_3', 4, 1],
            ['User_4', 5, 1],
            ['User_5', 6, 1],
        ];
    }

    /**
     * Test fetch limit.
     *
     * @dataProvider userFetchLimitProvider
     *
     * @param string $userName
     * @param int    $offset
     * @param int    $rowCount
     *
     * @return void
     */
    public function testFetchLimit(string $userName, int $offset, int $rowCount): void
    {
        $enhancedUsers = self::$enhancedUserMapper->fetchLimit($offset, $rowCount);

        $key = \array_keys($enhancedUsers)[0];

        $this->assertCount(1, $enhancedUsers);
        $this->assertEquals($enhancedUsers[$key]->name, $userName);
    }

    /**
     * Permission id provider.
     *
     * @return array
     */
    public function permissionIdProvider(): array
    {
        return [
            [1, 7],
            [2, 3],
            [3, 2],
            [4, 2],
            [5, 5],
            [6, 5],
            [7, 0]
        ];
    }

    /**
     * Test fetch by permission.
     *
     * @dataProvider permissionIdProvider
     *
     * @param int $permissionId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByPermission(int $permissionId, int $result): void
    {
        $permission = self::$permissionMapper->fetchById($permissionId);

        if ($permission instanceof Permission) {
            $this->assertCount($result, self::$enhancedUserMapper->fetchByPermission($permission));
        }

        if ($permission instanceof NullDomainObject) {
            $this->assertSame($permissionId, 7);
            $this->assertSame($result, 0);
        }
    }

    /**
     * Test fetch by permission id.
     *
     * @dataProvider permissionIdProvider
     *
     * @param int $permissionId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByPermissionId(int $permissionId, int $result): void
    {
        $this->assertCount($result, self::$enhancedUserMapper->fetchByPermissionId($permissionId));
    }

    /**
     * Permission name provider.
     *
     * @return array
     */
    public function permissionNameProvider(): array
    {
        return [
            ['see users', 7],
            ['update user', 3],
            ['delete user', 2],
            ['create user', 2],
            ['enable user', 5],
            ['disable user', 5],
            ['unknown permission', 0]
        ];
    }

    /**
     * Test fetch by permission name.
     *
     * @dataProvider permissionNameProvider
     *
     * @param string $permissionName
     * @param int    $result
     *
     * @return void
     */
    public function testFetchByPermissionName(string $permissionName, int $result): void
    {
        $this->assertCount($result, self::$enhancedUserMapper->fetchByPermissionName($permissionName));
    }

    /**
     * Role id provider.
     *
     * @return array
     */
    public function roleIdProvider(): array
    {
        return [
            [1, 1],
            [2, 2],
            [3, 4],
            [4, 0]
        ];
    }

    /**
     * Test fetch by role.
     *
     * @dataProvider roleIdProvider
     *
     * @param int $roleId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByRole(int $roleId, int $result): void
    {
        $role = self::$roleMapper->fetchById($roleId);

        if ($role instanceof Role) {
            $this->assertCount($result, self::$enhancedUserMapper->fetchByRole($role));
        }

        if ($role instanceof NullDomainObject) {
            $this->assertSame($roleId, 4);
            $this->assertSame($result, 0);
        }
    }

    /**
     * Test fetch by role id.
     *
     * @dataProvider roleIdProvider
     *
     * @param int $roleId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByRoleId(int $roleId, int $result): void
    {
        $this->assertCount($result, self::$enhancedUserMapper->fetchByRoleId($roleId));
    }

    /**
     * Test fetch by role name.
     *
     * @return void
     */
    public function testFetchByRoleName(): void
    {
    }

    /**
     * Test grant permission.
     *
     * @return void
     */
    public function testGrantPermission(): void
    {
    }

    /**
     * Test grant permission by id.
     *
     * @return void
     */
    public function testGrantPermissionById(): void
    {
    }

    /**
     * Test grant permission.
     *
     * @return void
     */
    public function testGrantPermissionByName(): void
    {
    }

    /**
     * Test revoke permission.
     *
     * @return void
     */
    public function testRevokePermission(): void
    {
    }

    /**
     * Test revoke permission by id.
     *
     * @return void
     */
    public function testRevokePermissionById(): void
    {
    }

    /**
     * Test revoke permission by name.
     *
     * @return void
     */
    public function testRevokePermissionByName(): void
    {
    }

    /**
     * Test add role.
     *
     * @return void
     */
    public function testAddRole(): void
    {
    }

    /**
     * Test add role by id.
     *
     * @return void
     */
    public function testAddRoleById(): void
    {
    }

    /**
     * Test add role by name.
     *
     * @return void
     */
    public function testAddRoleByName(): void
    {
    }

    /**
     * Test remove role.
     *
     * @return void
     */
    public function testRemoveRole(): void
    {
    }

    /**
     * Test remove role by id.
     *
     * @return void
     */
    public function testRemoveRoleById(): void
    {
    }

    /**
     * Test remove role by name.
     *
     * @return void
     */
    public function testRemoveRoleByName(): void
    {
    }
}
