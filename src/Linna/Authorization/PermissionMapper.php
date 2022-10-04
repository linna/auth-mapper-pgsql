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

use InvalidArgumentException;
use Linna\DataMapper\DomainObjectInterface;
use Linna\DataMapper\MapperAbstract;
use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use PDO;
use RuntimeException;

/**
 * PermissionMapper.
 */
class PermissionMapper extends MapperAbstract implements PermissionMapperInterface
{
    /** @var ExtendedPDO Database Connection */
    protected ExtendedPDO $pdo;

    /** @var string Constant part of SELECT query */
    protected string $baseQuery = 'SELECT permission_id AS "id", name, description, last_update AS "lastUpdate" FROM public.permission';

    /**
     * Constructor.
     *
     * @param ExtendedPDO $pdo
     */
    public function __construct(ExtendedPDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * {@inheritdoc}
     */
    public function fetchById(int|string $permissionId): DomainObjectInterface
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} WHERE permission_id = :id");

        $pdos->bindParam(':id', $permissionId, PDO::PARAM_INT);
        $pdos->execute();

        $result = $pdos->fetchObject(Permission::class);

        return ($result instanceof Permission) ? $result : new NullDomainObject();
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByName(string $permissionName): DomainObjectInterface
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} WHERE name = :name");

        $pdos->bindParam(':name', $permissionName, PDO::PARAM_STR);
        $pdos->execute();

        $result = $pdos->fetchObject(Permission::class);

        return ($result instanceof Permission) ? $result : new NullDomainObject();
    }

    /**
     * {@inheritdoc}
     */
    public function fetchAll(): array
    {
        $pdos = $this->pdo->prepare($this->baseQuery);

        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, Permission::class);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchLimit(int $offset, int $rowCount): array
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} LIMIT :rowcount OFFSET :offset");

        $pdos->bindParam(':offset', $offset, PDO::PARAM_INT);
        $pdos->bindParam(':rowcount', $rowCount, PDO::PARAM_INT);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, Permission::class);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByRole(Role $role): array
    {
        return $this->fetchByRoleId($role->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByRoleId(int|string $roleId): array
    {
        $pdos = $this->pdo->prepare('
        SELECT p.permission_id AS "id", p.name, p.description, p.last_update AS "lastUpdate"
        FROM permission AS p
        INNER JOIN public.role_permission AS rp 
        ON rp.permission_id = p.permission_id
        WHERE rp.role_id = :id');

        $pdos->bindParam(':id', $roleId, PDO::PARAM_INT);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, Permission::class);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByRoleName(string $roleName): array
    {
        $pdos = $this->pdo->prepare('
        SELECT p.permission_id AS "id", p.name, p.description, p.last_update AS "lastUpdate"
        FROM public.permission AS p
        INNER JOIN public.role_permission AS rp 
        ON rp.permission_id = p.permission_id
        INNER JOIN public.role as r 
        ON rp.role_id = r.role_id
        WHERE r.name = :name');

        $pdos->bindParam(':name', $roleName, PDO::PARAM_STR);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, Permission::class);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByUser(EnhancedUser $user): array
    {
        return $this->fetchByUserId($user->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByUserId(int|string $userId): array
    {
        $pdos = $this->pdo->prepare('
        (SELECT p.permission_id AS "id", p.name, p.description, 
        0 AS inherited, p.last_update AS "lastUpdate"
        FROM public.permission AS p
        INNER JOIN public.user_permission AS up 
        ON p.permission_id = up.permission_id
        WHERE up.user_id = :id)
        UNION
        (SELECT p.permission_id AS "id", p.name, p.description, 
        r.role_id AS inherited, p.last_update AS "lastUpdate"
        FROM public.permission AS p
        INNER JOIN public.role_permission as rp 
        ON p.permission_id = rp.permission_id
        INNER JOIN public.role AS r 
        ON rp.role_id = r.role_id
        INNER JOIN public.user_role AS ur 
        ON r.role_id = ur.role_id
        WHERE ur.user_id = :id)');

        $pdos->bindParam(':id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, Permission::class);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByUserName(string $userName): array
    {
        $pdos = $this->pdo->prepare('
        (SELECT p.permission_id AS "id", p.name, p.description, 0 AS inherited, p.last_update AS "lastUpdate"
        FROM public.permission AS p
        INNER JOIN public.user_permission AS up 
        ON p.permission_id = up.permission_id
        INNER JOIN public.user AS u 
        ON up.user_id = u.user_id
        WHERE u.name = :name)
        UNION
        (SELECT p.permission_id AS "id", p.name, p.description, r.role_id AS inherited, p.last_update AS "lastUpdate"
        FROM public.permission AS p
        INNER JOIN public.role_permission as rp 
        ON p.permission_id = rp.permission_id
        INNER JOIN public.role AS r 
        ON rp.role_id = r.role_id
        INNER JOIN public.user_role AS ur 
        ON r.role_id = ur.role_id
        INNER JOIN public.user AS u 
        ON ur.user_id = u.user_id
        WHERE u.name = :name)');

        $pdos->bindParam(':name', $userName, PDO::PARAM_STR);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, Permission::class);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchUserPermissionHashTable(int|string $userId): array
    {
        $pdos = $this->pdo->prepare("(SELECT encode(digest(concat(u.user_id, '.', up.permission_id), 'sha256'), 'hex') AS p_hash
        FROM public.user AS u
        INNER JOIN public.user_permission AS up ON u.user_id = up.permission_id 
 	WHERE u.user_id = :id)
        UNION
        (SELECT encode(digest(concat(u.user_id, '.', rp.permission_id), 'sha256'), 'hex') AS p_hash
        FROM public.user AS u
        INNER JOIN public.user_role AS ur 
        ON u.user_id = ur.user_id
        INNER JOIN public.role AS r 
        ON ur.role_id = r.role_id
        INNER JOIN public.role_permission as rp 
        ON r.role_id = rp.role_id 
	WHERE u.user_id = :id)
        ORDER BY p_hash");

        $pdos->bindParam(':id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        return \array_flip($pdos->fetchAll(PDO::FETCH_COLUMN));
    }

    /**
     * {@inheritdoc}
     */
    public function permissionExistById(int|string $permissionId): bool
    {
        $pdos = $this->pdo->prepare('SELECT permission_id FROM public.permission WHERE permission_id = :id');

        $pdos->bindParam(':id', $permissionId, PDO::PARAM_INT);
        $pdos->execute();

        return ($pdos->rowCount() > 0) ? true : false;
    }

    /**
     * {@inheritdoc}
     */
    public function permissionExistByName(string $permissionName): bool
    {
        $pdos = $this->pdo->prepare('SELECT permission_id FROM public.permission WHERE name = :name');

        $pdos->bindParam(':name', $permissionName, PDO::PARAM_STR);
        $pdos->execute();

        return ($pdos->rowCount() > 0) ? true : false;
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new Permission();
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteInsert(DomainObjectInterface &$permission): void
    {
        $this->checkDomainObjectType($permission);

        try {
            $pdos = $this->pdo->prepare('INSERT INTO public.permission (name, description) VALUES (:name, :description)');

            $pdos->bindParam(':name', $permission->name, PDO::PARAM_STR);
            $pdos->bindParam(':description', $permission->description, PDO::PARAM_STR);
            $pdos->execute();

            $permission->setId((int) $this->pdo->lastInsertId());
        } catch (RuntimeException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteUpdate(DomainObjectInterface $permission): void
    {
        $this->checkDomainObjectType($permission);

        $objId = $permission->getId();

        try {
            $pdos = $this->pdo->prepare('UPDATE public.permission SET name = :name, description = :description, last_update = NOW() WHERE (permission_id = :id)');

            $pdos->bindParam(':id', $objId, PDO::PARAM_INT);
            $pdos->bindParam(':name', $permission->name, PDO::PARAM_STR);
            $pdos->bindParam(':description', $permission->description, PDO::PARAM_STR);
            $pdos->execute();
        } catch (RuntimeException $e) {
            echo 'Update not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteDelete(DomainObjectInterface &$permission): void
    {
        $this->checkDomainObjectType($permission);

        $objId = $permission->getId();

        try {
            $pdos = $this->pdo->prepare('DELETE FROM public.permission WHERE permission_id = :id');

            $pdos->bindParam(':id', $objId, PDO::PARAM_INT);
            $pdos->execute();

            $permission = new NullDomainObject();
        } catch (RuntimeException $e) {
            echo 'Delete not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function checkDomainObjectType(DomainObjectInterface $domainObject): void
    {
        if (!($domainObject instanceof Permission)) {
            throw new InvalidArgumentException('Domain Object parameter must be instance of Permission class');
        }
    }
}
