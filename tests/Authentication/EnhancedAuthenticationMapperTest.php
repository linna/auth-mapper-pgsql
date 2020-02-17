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

use Linna\Authentication\EnhancedAuthenticationMapper;
use Linna\Authentication\LoginAttempt;
use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use Linna\Storage\StorageFactory;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Enhanced Authentication Mapper Test.
 */
class EnhancedAuthenticationMapperTest extends TestCase
{
    /**
     * @var EnhancedAuthenticationMapper The enhanced authentication mapper class.
     */
    protected static EnhancedAuthenticationMapper $enhancedAuthenticationMapper;

    /**
     * @var ExtendedPDO Database connection.
     */
    protected static ExtendedPDO $pdo;

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
        self::$enhancedAuthenticationMapper = new EnhancedAuthenticationMapper($pdo);


        self::$pdo->exec('ALTER SEQUENCE public.login_attempt_login_attempt_id_seq RESTART WITH 1 INCREMENT BY 1;');

        //populate data base
        self::createFakeData();
    }

    /**
     * Insert fake data into persistent storage for tests.
     *
     * @return void
     */
    protected static function createFakeData(): void
    {
        $loginAttempt = [
            ['root', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['root', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['root', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['root', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['root', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['root', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['admin', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['admin', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['admin', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['admin', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['admin', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['admin', 'mbvi2lgdpcj6vp3qemh2estei2', '192.168.1.2'],
            ['administrator', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['administrator', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['administrator', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['administrator', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['administrator', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['administrator', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['poweruser', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['poweruser', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['poweruser', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['poweruser', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['poweruser', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['poweruser', 'vaqgvpochtif8gh888q6vnlch5', '192.168.1.2'],
            ['fooroot', '3hto06tko273jjc1se0v1aqvvn', '192.168.1.3'],
            ['fooroot', '3hto06tko273jjc1se0v1aqvvn', '192.168.1.3'],
            ['fooroot', '3hto06tko273jjc1se0v1aqvvn', '192.168.1.3'],
            ['fooroot', '3hto06tko273jjc1se0v1aqvvn', '192.168.1.3'],
        ];

        $timeSliding = 0;

        foreach ($loginAttempt as $data) {
            $loginAttempt = self::$enhancedAuthenticationMapper->create();
            $loginAttempt->userName = $data[0];
            $loginAttempt->sessionId = $data[1];
            $loginAttempt->ipAddress = $data[2];
            $loginAttempt->when = \date(DATE_ATOM, ((\time() - 28) +  $timeSliding++));

            self::$enhancedAuthenticationMapper->save($loginAttempt);
        }
    }

    /**
     * Tear Down.
     *
     * @return void
     */
    public static function tearDownAfterClass(): void
    {
        self::$pdo->exec('DELETE FROM public.login_attempt');
    }

    /**
     * Test new instance.
     */
    public function testNewInstance()
    {
        $this->assertInstanceOf(EnhancedAuthenticationMapper::class, self::$enhancedAuthenticationMapper);
    }

    /**
     * User id provider
     *
     * @return array
     */
    public function loginAttemptIdProvider(): array
    {
        return [
            [1, 1],
            [28, 28],
            [29, 0]
        ];
    }

    /**
     * Test fetch by id.
     *
     * @dataProvider loginAttemptIdProvider
     *
     * @param int $loginAttemptId
     * @param int $expectedId
     *
     * @return void
     */
    public function testFetchById(int $loginAttemptId, int $expectedId): void
    {
        $loginAttempt = self::$enhancedAuthenticationMapper->fetchById($loginAttemptId);
        $this->assertEquals($loginAttempt->getId(), $expectedId);
    }

    /**
     * Test fetch all.
     *
     * @return void
     */
    public function testFetchAll(): void
    {
        $this->assertCount(28, self::$enhancedAuthenticationMapper->fetchAll());
    }

    /**
     * Login attempt fetch limit provider.
     *
     * @return array
     */
    public function loginAttemptFetchLimitProvider(): array
    {
        return [
            ['root', 1, 0, 1],
            ['admin', 7, 6, 1],
            ['administrator', 13, 12, 1],
            ['poweruser', 19, 18, 1],
            ['fooroot', 25, 24, 1]
        ];
    }

    /**
     * Test fetch limit.
     *
     * @dataProvider loginAttemptFetchLimitProvider
     *
     * @param string $userName
     * @param int    $offset
     * @param int    $rowCount
     *
     * @return void
     */
    public function testFetchLimit(string $userName, int $id, int $offset, int $rowCount): void
    {
        $loginAttempt = self::$enhancedAuthenticationMapper->fetchLimit($offset, $rowCount);

        $key = \array_keys($loginAttempt)[0];

        $this->assertCount(1, $loginAttempt);
        $this->assertEquals($loginAttempt[$key]->id, $id);
        $this->assertEquals($loginAttempt[$key]->userName, $userName);
    }

    /**
     * Login attempt with the same user provider.
     *
     * @return array
     */
    public function attemptsWithSameUserProvider(): array
    {
        return [
            ['root', 40, 6],
            ['admin', 40, 6],
            ['administrator', 40, 6],
            ['poweruser', 40, 6],
            ['fooroot', 40, 4]
        ];
    }

    /**
     * Test fetch attempts with the same user.
     *
     * @dataProvider attemptsWithSameUserProvider
     *
     * @param string $userName
     * @param int    $timeInSeconds
     * @param int    $attempts
     *
     * @return void
     */
    public function testFetchAttemptsWithSameUser(string $userName, int $timeInSeconds, int $attempts): void
    {
        $this->assertEquals($attempts, self::$enhancedAuthenticationMapper->fetchAttemptsWithSameUser($userName, $timeInSeconds));
    }

    /**
     * Login attempt with the same session provider.
     *
     * @return array
     */
    public function attemptsWithSameSessionProvider(): array
    {
        return [
            ['mbvi2lgdpcj6vp3qemh2estei2', 40, 12],
            ['vaqgvpochtif8gh888q6vnlch5', 40, 12],
            ['3hto06tko273jjc1se0v1aqvvn', 40, 4]
        ];
    }

    /**
     * Test fetch attempts with the same session id.
     *
     * @dataProvider attemptsWithSameSessionProvider
     *
     * @param string $sessionId
     * @param int    $timeInSeconds
     * @param int    $attempts
     *
     * @return void
     */
    public function testFetchAttemptsWithSameSession(string $sessionId, int $timeInSeconds, int $attempts): void
    {
        $this->assertEquals($attempts, self::$enhancedAuthenticationMapper->fetchAttemptsWithSameSession($sessionId, $timeInSeconds));
    }

    /**
     * Login attempt with the same ip provider.
     *
     * @return array
     */
    public function attemptsWithSameIpProvider(): array
    {
        return [
            ['192.168.1.2', 40, 24],
            ['192.168.1.3', 40, 4]
        ];
    }

    /**
     * Test fetch attempts with the same ip address.
     *
     * @dataProvider attemptsWithSameIpProvider
     *
     * @param string $ipAddress
     * @param int    $timeInSeconds
     * @param int    $attempts
     *
     * @return void
     */
    public function testFetchAttemptsWithSameIp(string $ipAddress, int $timeInSeconds, int $attempts): void
    {
        $this->assertEquals($attempts, self::$enhancedAuthenticationMapper->fetchAttemptsWithSameIp($ipAddress, $timeInSeconds));
    }

    /**
     * Test delete old login attempts.
     *
     * @return void
     */
    public function testDeleteOldLoginAttempts(): void
    {
        $this->assertTrue(self::$enhancedAuthenticationMapper->deleteOldLoginAttempts(-86400));
        $this->assertEquals(0, \count(self::$enhancedAuthenticationMapper->fetchAll()));
    }

    /**
     * Test concrete create.
     *
     * @return void
     */
    public function testConcreteCreate(): void
    {
        $this->assertInstanceOf(LoginAttempt::class, self::$enhancedAuthenticationMapper->create());
    }

    /**
     * Test concrete insert.
     *
     * @return void
     */
    public function testConcreteInsert(): void
    {
        $loginAttempt = self::$enhancedAuthenticationMapper->create();
        $loginAttempt->userName = 'test';
        $loginAttempt->sessionId = 'vaqgvpochtzf8gh888q6vnlch5';
        $loginAttempt->ipAddress = '127.0.0.1';
        $loginAttempt->when = \date(DATE_ATOM);

        $this->assertEquals(0, $loginAttempt->id);
        $this->assertEquals(0, $loginAttempt->getId());

        self::$enhancedAuthenticationMapper->save($loginAttempt);

        $this->assertGreaterThan(0, $loginAttempt->id);
        $this->assertGreaterThan(0, $loginAttempt->getId());

        $loginAttemptStored = self::$enhancedAuthenticationMapper->fetchById($loginAttempt->id);

        $this->assertInstanceOf(LoginAttempt::class, $loginAttemptStored);
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
        $loginAttemptStored = \current(self::$enhancedAuthenticationMapper->fetchAll());

        $this->assertEquals('vaqgvpochtzf8gh888q6vnlch5', $loginAttemptStored->sessionId);
        $this->assertInstanceOf(LoginAttempt::class, $loginAttemptStored);

        $loginAttemptStored->sessionId = 'qwertyochtzf8gh888q6vnlch5';

        self::$enhancedAuthenticationMapper->save($loginAttemptStored);

        $loginAttemptUpdated = self::$enhancedAuthenticationMapper->fetchById($loginAttemptStored->id);

        $this->assertEquals('qwertyochtzf8gh888q6vnlch5', $loginAttemptUpdated->sessionId);
        $this->assertInstanceOf(LoginAttempt::class, $loginAttemptUpdated);
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
        $loginAttemptStored = \current(self::$enhancedAuthenticationMapper->fetchAll());

        $this->assertEquals('qwertyochtzf8gh888q6vnlch5', $loginAttemptStored->sessionId);
        $this->assertInstanceOf(LoginAttempt::class, $loginAttemptStored);

        self::$enhancedAuthenticationMapper->delete($loginAttemptStored);

        $this->assertInstanceOf(NullDomainObject::class, $loginAttemptStored);
    }
}
