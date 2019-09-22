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

use Linna\Authorization\PermissionMapper;
use Linna\Storage\StorageFactory;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Permission Mapper Test.
 */
class PermissionMapperTest extends TestCase
{
    /**
     * @var PermissionMapper
     */
    protected $permissionMapper;

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

        $this->permissionMapper = new PermissionMapper((new StorageFactory('pdo', $options))->get());
    }

    /**
     * Test new instance.
     */
    public function testNewInstance()
    {
        $this->assertInstanceOf(PermissionMapper::class, $this->permissionMapper);
    }
}
