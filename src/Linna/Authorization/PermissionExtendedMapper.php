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

use DateTimeImmutable;
use Linna\DataMapper\DomainObjectInterface;
use Linna\Storage\ExtendedPDO;
use stdClass;

/**
 * PermissionMapper.
 */
class PermissionExtendedMapper extends PermissionMapper implements PermissionExtendedMapperInterface
{
    /**
     * Constructor.
     *
     * @param ExtendedPDO $pdo
     */
    public function __construct(
        /** @var ExtendedPDO Database Connection */
        protected ExtendedPDO $pdo,

        /** @var RoleMapperInterface Permission Mapper. */
        protected RoleMapperInterface $roleMapper,

        /** @var UserMapperInterface Enhanced User Mapper. */
        protected UserMapperInterface $userMapper
    ) {
    }

    /**
     * Hydrate an array of objects.
     *
     * @param array<int, stdClass> $array The array containing the resultset from database.
     *
     * @return array<int, EnhancedUser>
     */
    protected function hydrator(array $array): array
    {
        $tmp = [];

        foreach ($array as $value) {

            //get users and roles
            $users = $this->userMapper->fetchByPermissionId($value->permission_id);
            $roles = $this->roleMapper->fetchByPermissionId($value->permission_id);

            $tmp[] = new PermissionExtended(
                id:              $value->permission_id,
                name:            $value->name,
                description:     $value->description,
                inherited:       $value->inherited,
                created:         new DateTimeImmutable($value->created),
                lastUpdate:      new DateTimeImmutable($value->last_update),
                users:           $users,
                roles:           $roles
            );
        }

        return $tmp;
    }

    /**
     * Hydrate an object.
     *
     * @param object $object The object containing the resultset from database.
     *
     * @return DomainObjectInterface
     */
    protected function hydratorSingle(object $object): DomainObjectInterface
    {
        //get users and roles
        $users = $this->userMapper->fetchByPermissionId($object->permission_id);
        $roles = $this->roleMapper->fetchByPermissionId($object->permission_id);

        return new PermissionExtended(
            id:              $object->permission_id,
            name:            $object->name,
            description:     $object->description,
            inherited:       $object->inherited,
            created:         new DateTimeImmutable($object->created),
            lastUpdate:      new DateTimeImmutable($object->last_update),
            users:           $users,
            roles:           $roles
        );
    }

    /**
     * {@inheritdoc}
     */
    /*public function permissionExistById(int|string $permissionId): bool
    {
        //make query
        $stmt = $this->pdo->prepare('SELECT permission_id FROM permission WHERE permission_id = :id');

        $stmt->bindParam(':id', $permissionId, PDO::PARAM_INT);
        $stmt->execute();

        return ($stmt->rowCount() > 0) ? true : false;
    }*/

    /**
     * {@inheritdoc}
     */
    /*public function permissionExistByName(string $permissionName): bool
    {
        //make query
        $stmt = $this->pdo->prepare('SELECT permission_id FROM permission WHERE name = :name');

        $stmt->bindParam(':name', $permissionName, PDO::PARAM_STR);
        $stmt->execute();

        return ($stmt->rowCount() > 0) ? true : false;
    }*/

    /**
     * {@inheritdoc}
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new PermissionExtended();
    }
}
