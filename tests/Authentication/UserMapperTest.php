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
use Linna\Authentication\User;
use Linna\Authentication\UserMapper;
use Linna\DataMapper\NullDomainObject;
use Linna\DataMapper\UUID4;
use Linna\Storage\StorageFactory;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * User Mapper Test.
 */
class UserMapperTest extends TestCase
{
    /**
     * @var UserMapper The enhanced authentication mapper class
     */
    protected static $userMapper;

    /**
     * @var PDO Database connection.
     */
    protected static $pdo;

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

        self::$pdo = $pdo;
        self::$userMapper = new UserMapper($pdo, new Password());
    }

    /**
     * Tear Down.
     *
     * @return void
     */
    public static function tearDownAfterClass(): void
    {
        self::$pdo->exec('ALTER SEQUENCE public.user_user_id_seq RESTART WITH 8 INCREMENT BY 1;');
    }

    /**
     * Test new instance.
     *
     * @return void
     */
    public function testNewInstance(): void
    {
        $this->assertInstanceOf(UserMapper::class, self::$userMapper);
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
        $user = self::$userMapper->fetchById($userId);
        $this->assertEquals($user->getId(), $expectedId);
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
        $user = self::$userMapper->fetchByName($userName);

        if ($expectedName === '') {
            $this->assertInstanceOf(NullDomainObject::class, $user);
            return;
        }

        $this->assertEquals($user->name, $expectedName);
    }

    /**
     * Test fetch all.
     *
     * @return void
     */
    public function testFetchAll(): void
    {
        $this->assertCount(7, self::$userMapper->fetchAll());
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
        $users = self::$userMapper->fetchLimit($offset, $rowCount);

        $key = \array_keys($users)[0];

        $this->assertCount(1, $users);
        $this->assertEquals($users[$key]->name, $userName);
    }

    /**
     * Test concrete create.
     *
     * @return void
     */
    public function testConcreteCreate(): void
    {
        $this->assertInstanceOf(User::class, self::$userMapper->create());
    }

    /**
     * Test concrete insert.
     *
     * @return void
     */
    public function testConcreteInsert(): void
    {
        $user = self::$userMapper->create();
        $user->name = 'test_user';
        $user->setPassword('test_password');
        $user->uuid = (new UUID4())->getHex();

        $this->assertEquals(0, $user->rId);
        $this->assertEquals(0, $user->getId());

        self::$userMapper->save($user);

        $this->assertGreaterThan(0, $user->id);
        $this->assertGreaterThan(0, $user->getId());

        $userStored = self::$userMapper->fetchByName('test_user');

        $this->assertInstanceOf(User::class, $userStored);
    }

    /**
     * Test concrete update.
     *
     * @depends testConcreteInsert
     *
     * @return void
     */
    public function testConcreteUpdate(): void
    {
        $userStored = self::$userMapper->fetchByName('test_user');

        $this->assertEquals('test_user', $userStored->name);
        $this->assertInstanceOf(User::class, $userStored);

        $userStored->name = 'test_user_name';

        self::$userMapper->save($userStored);

        $userStoredUpdated = self::$userMapper->fetchByName('test_user_name');

        $this->assertEquals('test_user_name', $userStoredUpdated->name);
        $this->assertInstanceOf(User::class, $userStoredUpdated);
    }

    /**
     * Test concrete delete.
     *
     * @depends testConcreteInsert
     *
     * @return void
     */
    public function testConcreteDelete(): void
    {
        $userStored = self::$userMapper->fetchByName('test_user_name');

        $this->assertEquals('test_user_name', $userStored->name);
        $this->assertInstanceOf(User::class, $userStored);

        self::$userMapper->delete($userStored);

        $this->assertInstanceOf(NullDomainObject::class, $userStored);
    }
}
