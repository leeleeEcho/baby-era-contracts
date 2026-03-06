// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEnterpriseIAM} from "./interfaces/IEnterpriseIAM.sol";
import {SystemContractBase} from "./abstract/SystemContractBase.sol";
import {DID_REGISTRY_SYSTEM_CONTRACT, L1_MESSENGER_CONTRACT} from "./Constants.sol";
import {IDIDRegistry} from "./interfaces/IDIDRegistry.sol";
import {IL1Messenger} from "./interfaces/IL1Messenger.sol";

contract EnterpriseIAM is IEnterpriseIAM, SystemContractBase {
    uint256 public constant PERM_ISSUE_CREDENTIAL   = 1 << 0;
    uint256 public constant PERM_REVOKE_CREDENTIAL  = 1 << 1;
    uint256 public constant PERM_MANAGE_MEMBERS     = 1 << 2;
    uint256 public constant PERM_MANAGE_ROLES       = 1 << 3;
    uint256 public constant PERM_VIEW_REPORTS       = 1 << 4;
    uint256 public constant PERM_MANAGE_COMPLIANCE  = 1 << 5;
    uint256 public constant PERM_ADMIN              = 1 << 6;
    uint256 public constant PERM_SIGN_TRANSACTIONS  = 1 << 7;

    struct OrganizationData {
        address orgDID;
        address owner;
        uint256 memberCount;
        bool active;
    }

    struct RoleData {
        bytes32 name;
        uint256 permissions;
        address admin;
    }

    mapping(bytes32 => OrganizationData) private _organizations;
    mapping(bytes32 => mapping(uint256 => RoleData)) private _roles;
    mapping(bytes32 => mapping(address => uint256)) private _memberRoles;
    mapping(bytes32 => uint256) private _roleCounter;

    error OrgAlreadyExists(bytes32 orgId);
    error OrgNotFound(bytes32 orgId);
    error OrgNotActive(bytes32 orgId);
    error NotOrgOwner(address caller);
    error InsufficientPermission(address caller, uint256 required);
    error DIDNotActive(address orgDID);
    error NotControllerOrDelegate(address caller, address orgDID);
    error RoleNotFound(bytes32 orgId, uint256 roleId);
    error MemberAlreadyAssigned(bytes32 orgId, address member);
    error MemberNotAssigned(bytes32 orgId, address member);
    error InvalidPermissions();

    function _didRegistry() internal pure returns (IDIDRegistry) {
        return IDIDRegistry(DID_REGISTRY_SYSTEM_CONTRACT);
    }

    modifier onlyOrgOwnerOrPermission(bytes32 orgId, uint256 perm) {
        OrganizationData storage org = _organizations[orgId];
        if (!org.active) revert OrgNotActive(orgId);
        if (msg.sender == org.owner) {
            _;
            return;
        }
        uint256 roleId = _memberRoles[orgId][msg.sender];
        if (roleId == 0) revert InsufficientPermission(msg.sender, perm);
        RoleData storage role = _roles[orgId][roleId];
        if ((role.permissions & PERM_ADMIN) == 0 && (role.permissions & perm) == 0) {
            revert InsufficientPermission(msg.sender, perm);
        }
        _;
    }

    function createOrganization(bytes32 orgId, address orgDID) external override onlySystemCall {
        if (_organizations[orgId].orgDID != address(0)) revert OrgAlreadyExists(orgId);
        if (!_didRegistry().isActive(orgDID)) revert DIDNotActive(orgDID);

        IDIDRegistry.DIDDocument memory doc = _didRegistry().resolveDID(orgDID);
        bool authorized = (doc.controller == msg.sender) || _didRegistry().isDelegate(orgDID, msg.sender);
        if (!authorized) revert NotControllerOrDelegate(msg.sender, orgDID);

        _organizations[orgId] = OrganizationData({
            orgDID: orgDID,
            owner: msg.sender,
            memberCount: 0,
            active: true
        });

        emit OrganizationCreated(orgId, orgDID, msg.sender);
        L1_MESSENGER_CONTRACT.sendToL1(abi.encode(uint8(10), orgId, orgDID, msg.sender));
    }

    function deactivateOrganization(bytes32 orgId) external override onlySystemCall {
        OrganizationData storage org = _organizations[orgId];
        if (org.orgDID == address(0)) revert OrgNotFound(orgId);
        if (msg.sender != org.owner) revert NotOrgOwner(msg.sender);
        org.active = false;
        emit OrganizationDeactivated(orgId);
    }

    function getOrganization(bytes32 orgId) external view override returns (
        address orgDID, address owner, uint256 memberCount, bool active
    ) {
        OrganizationData storage org = _organizations[orgId];
        return (org.orgDID, org.owner, org.memberCount, org.active);
    }

    function createRole(
        bytes32 orgId, bytes32 name, uint256 permissions
    ) external override onlyOrgOwnerOrPermission(orgId, PERM_MANAGE_ROLES) returns (uint256 roleId) {
        if (permissions == 0) revert InvalidPermissions();
        _roleCounter[orgId]++;
        roleId = _roleCounter[orgId];
        _roles[orgId][roleId] = RoleData({name: name, permissions: permissions, admin: msg.sender});
        emit RoleCreated(orgId, roleId, name, permissions);
    }

    function getRole(bytes32 orgId, uint256 roleId) external view override returns (
        bytes32 name, uint256 permissions, address admin
    ) {
        RoleData storage role = _roles[orgId][roleId];
        return (role.name, role.permissions, role.admin);
    }

    function assignRole(
        bytes32 orgId, address member, uint256 roleId
    ) external override onlyOrgOwnerOrPermission(orgId, PERM_MANAGE_MEMBERS) {
        if (_roles[orgId][roleId].name == bytes32(0)) revert RoleNotFound(orgId, roleId);
        if (_memberRoles[orgId][member] != 0) revert MemberAlreadyAssigned(orgId, member);
        _memberRoles[orgId][member] = roleId;
        _organizations[orgId].memberCount++;
        emit RoleAssigned(orgId, member, roleId);
        L1_MESSENGER_CONTRACT.sendToL1(abi.encode(uint8(11), orgId, member, roleId));
    }

    function revokeRole(
        bytes32 orgId, address member
    ) external override onlyOrgOwnerOrPermission(orgId, PERM_MANAGE_MEMBERS) {
        if (_memberRoles[orgId][member] == 0) revert MemberNotAssigned(orgId, member);
        delete _memberRoles[orgId][member];
        _organizations[orgId].memberCount--;
        emit RoleRevoked(orgId, member);
        L1_MESSENGER_CONTRACT.sendToL1(abi.encode(uint8(12), orgId, member));
    }

    function getMemberRole(bytes32 orgId, address member) external view override returns (uint256) {
        return _memberRoles[orgId][member];
    }

    function hasPermission(bytes32 orgId, address member, uint256 permission) external view override returns (bool) {
        if (_organizations[orgId].owner == member) return true;
        uint256 roleId = _memberRoles[orgId][member];
        if (roleId == 0) return false;
        RoleData storage role = _roles[orgId][roleId];
        if ((role.permissions & PERM_ADMIN) != 0) return true;
        return (role.permissions & permission) != 0;
    }
}
