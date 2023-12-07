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

//use InvalidArgumentException;
use DateTimeImmutable;
use Linna\Authorization\UserMapperInterface;
use Linna\DataMapper\DomainObjectInterface;
//use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use PDO;
use PDOException;
//use RuntimeException;
use stdClass;

/**
 * Role Mapper.
 */
class RoleExtendedMapper extends RoleMapper implements RoleExtendedMapperInterface
{
    /**
     * Constructor.
     *
     * @param ExtendedPDO               $pdo              Valid <code>PDO</code> instace to interact with the persistent storage.
     * @param PermissionMapperInterface $permissionMapper Permission mapper.
     * @param UserMapperInterface       $userMapper       User Mapper
     * @param int                       $fetchMode        If set to FETCH_WHOLE, the <code>EnhancedUser</code> object
     *                                                    contains also an array of <code>Role</code> and <code>Permission</code> object,
     *                                                    if set to FETCH_VOID , the <code>EnhancedUser</code> object contains a void array
     *                                                    for permissions and roles.
     */
    public function __construct(
        /** @var ExtendedPDO Database Connection. */
        protected ExtendedPDO $pdo,

        /** @var PermissionMapperInterface Permission Mapper. */
        protected PermissionMapperInterface $permissionMapper,

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

            //get users and permissions
            $users = $this->userMapper->fetchByRoleId($value->role_id);
            $permissions = $this->permissionMapper->fetchByRoleId($value->role_id);

            $tmp[] = new RoleExtended(
                id:              $value->role_id,
                name:            $value->name,
                description:     $value->description,
                active:          (int) $value->active,
                created:         new DateTimeImmutable($value->created),
                lastUpdate:      new DateTimeImmutable($value->last_update),
                users:           $users,
                permissions:     $permissions
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
        //get users and permissions
        $users = $this->userMapper->fetchByRoleId($object->role_id);
        $permissions = $this->permissionMapper->fetchByRoleId($object->role_id);

        return new RoleExtended(
            id:              $object->role_id,
            name:            $object->name,
            description:     $object->description,
            active:          (int) $object->active,
            created:         new DateTimeImmutable($object->created),
            lastUpdate:      new DateTimeImmutable($object->last_update),
            users:           $users,
            permissions:     $permissions
        );
    }

    /**
     * {@inheritdoc}
     */
    public function grantPermission(RoleExtended &$role, Permission $permission)
    {
        $this->grantPermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function grantPermissionById(RoleExtended &$role, int|string $permissionId)
    {
        //get values to be passed as reference
        $roleId = $role->getId();

        try {
            //make query
            $stmt = $this->pdo->prepare('INSERT INTO public.role_permission (role_id, permission_id) VALUES (:role_id, :permission_id) ON CONFLICT (role_id, permission_id) DO UPDATE SET role_id = :role_id, permission_id = :permission_id');

            $stmt->bindParam(':role_id', $roleId, PDO::PARAM_INT);
            $stmt->bindParam(':permission_id', $permissionId, PDO::PARAM_INT);
            $stmt->execute();

            //update current object
            $role = $this->fetchById($roleId);
        } catch (PDOException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    public function grantPermissionByName(RoleExtended &$role, string $permissionName)
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        if ($permission instanceof Permission) {
            $this->grantPermissionById($role, $permission->getId());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function revokePermission(RoleExtended &$role, Permission $permission)
    {
        $this->revokePermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function revokePermissionById(RoleExtended &$role, int|string $permissionId)
    {
        //get values to be passed as reference
        $roleId = $role->getId();

        try {
            //make query
            $stmt = $this->pdo->prepare('DELETE FROM public.role_permission WHERE role_id = :role_id AND permission_id = :permission_id');

            $stmt->bindParam(':role_id', $roleId, PDO::PARAM_INT);
            $stmt->bindParam(':permission_id', $permissionId, PDO::PARAM_INT);
            $stmt->execute();

            //update current object
            $role = $this->fetchById($roleId);
        } catch (PDOException $e) {
            echo 'Deletion not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    public function revokePermissionByName(RoleExtended &$role, string $permissionName)
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        if ($permission instanceof Permission) {
            $this->revokePermissionById($role, $permission->getId());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function addUser(RoleExtended &$role, User $user)
    {
        $this->addUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function addUserById(RoleExtended &$role, int|string $userId)
    {
        //get values to be passed as reference
        $roleId = $role->getId();

        try {
            //make query
            $stmt = $this->pdo->prepare('INSERT INTO public.user_role (user_id, role_id) VALUES (:user_id, :role_id)  ON CONFLICT (user_id, role_id) DO UPDATE SET user_id = :user_id, role_id = :role_id');

            $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $stmt->bindParam(':role_id', $roleId, PDO::PARAM_INT);
            $stmt->execute();

            $role = $this->fetchById($roleId);
        } catch (PDOException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    public function addUserByName(RoleExtended &$role, string $userName)
    {
        $user = $this->userMapper->fetchByName($userName);

        if ($user instanceof User) {
            $this->addUserById($role, $user->getId());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function removeUser(RoleExtended &$role, User $user)
    {
        $this->removeUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function removeUserById(RoleExtended &$role, int|string $userId)
    {
        //get values to be passed as reference
        $roleId = $role->getId();

        try {
            //make query
            $stmt = $this->pdo->prepare('DELETE FROM user_role WHERE role_id = :role_id AND user_id = :user_id');

            $stmt->bindParam(':role_id', $roleId, PDO::PARAM_INT);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $stmt->execute();

            $role = $this->fetchById($roleId);
        } catch (PDOException $e) {
            echo 'Deletion not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    public function removeUserByName(RoleExtended &$role, string $userName)
    {
        $user = $this->userMapper->fetchByName($userName);

        if ($user instanceof User) {
            $this->removeUserById($role, $user->getId());
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new RoleExtended();
    }
}
