// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, HashSet};

type Error = ();
type Result<T> = std::result::Result<T, Error>;

/// The specified roles have a special features in the room policy
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RoleIndex {
    /// Automatically given to users not in the room.
    Outsider = 0,

    /// Meant for new members in public rooms or invited users in private rooms.
    Visitor = 1,

    /// Meant for approved members or new members in private rooms.
    Regular = 2,

    /// Meant for members trusted enough to moderate other users.
    /// They are protected from other moderators.
    Moderator = 3,

    /// Meant for members trusted to configure the entire room.
    /// They are protected from each moderators and other admins.
    Admin = 4,

    /// Assigned to the creator of the room and there can only be one.
    /// They are protected from everyone.
    Owner = 5,

    /// Custom roles
    Custom(u16),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    // TYPE 1: Enforced by hub

    // Timeout { max_duration: u32 },
    Kick,                         // Removes all their roles
    GiveRole { role: RoleIndex }, // E.g. Admins can add moderators
    DropRole { role: RoleIndex }, // E.g. Admins can remove moderators

    GiveRoleSelf { role: RoleIndex }, // E.g. Alice assigns the role Artist to herself
    DropRoleSelf { role: RoleIndex },

    // TYPE 2: Enforced by clients, the hubs helps if it can
    ReadMessage,
    SendMessage,
    EditMessage,
    EditMessageSelf,
    DeleteMessage,
    DeleteMessageSelf,

    IgnoreRatelimit,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// Give set of default roles.
    Join,

    /// Drops all their roles.
    Kick { target: String },

    /// Add a role to a user.
    // E.g. Admins can add the moderator role to regular users.
    GiveRole { target: String, role: RoleIndex },

    /// Remove a role from a user.
    DropRole { target: String, role: RoleIndex },

    // TYPE 2: Enforced by clients, the hubs helps if it can
    /// Read messages in the room.
    ReadMessage,

    /// Send messages in the room.
    SendMessage,

    /// Edit messages from yourself or others
    EditMessage { target: String },

    /// Delete messages from yourself or others
    DeleteMessage { target: String },
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Role {
    role_name: String,
    role_description: String,
    role_capabilities: Vec<Capability>, // TODO: This could also be a bitvector
    dependencies: Vec<RoleIndex>,       // What roles are required to have this role
    min: u32,
    max: Option<u32>,
    // min_active_participants_constraint: Option<u32>, // TODO: What does this mean?
    // max_active_participants_constraint: Option<u32>,
}

// #[derive(Clone)]
// pub struct PreAuthPerRoleList {
//     target_role: RoleIndex, // TODO: RFC writes type Role, we use role index
//     preauth_domain: String,
//     preauth_workgroup: String, // Uri
//     preauth_group: String,     // Uri
//     preauth_user: String,      // Uri
// }

#[derive(Clone)]
pub struct RoomPolicy {
    roles: HashMap<RoleIndex, Role>,
    default_roles: HashSet<RoleIndex>,
    // pre_auth_list: Vec<PreAuthPerRoleList>,
    // main_rate_limit_ms: u32,
    // thread_rate_limit_ms: u32,
}

#[derive(Clone)]
pub struct RoomState {
    policy: RoomPolicy,
    user_roles: HashMap<String, HashSet<RoleIndex>>,
}

impl RoomState {
    pub fn new(policy: &RoomPolicy, owner: &str) -> Self {
        let mut user_roles = HashMap::new();

        let mut owner_roles = HashSet::new();

        owner_roles.insert(RoleIndex::Regular);
        owner_roles.insert(RoleIndex::Moderator);
        owner_roles.insert(RoleIndex::Admin);
        owner_roles.insert(RoleIndex::Owner);

        user_roles.insert(owner.to_owned(), owner_roles);

        let this = Self {
            policy: policy.clone(),
            user_roles,
        };

        this.role_dependency_checks().unwrap();

        this
    }

    pub fn is_mod(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .ok_or(())?
            .contains(&RoleIndex::Moderator))
    }

    pub fn is_admin(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .ok_or(())?
            .contains(&RoleIndex::Admin))
    }

    pub fn is_owner(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .ok_or(())?
            .contains(&RoleIndex::Owner))
    }

    pub fn is_protected_from(&self, actor: &str, target: &str) -> Result<bool> {
        Ok(self.is_owner(target)?
            || self.is_admin(target)? && !self.is_admin(actor)?
            || self.is_mod(target)? && !self.is_mod(actor)?)
    }

    pub fn user_capabilities(&self, user_id: &str) -> HashSet<Capability> {
        let mut roles = HashSet::new();

        if let Some(assigned_roles) = self.user_roles.get(user_id) {
            roles.extend(assigned_roles);
        } else {
            roles.insert(RoleIndex::Outsider);
        }

        let mut capabilities = HashSet::new();

        for role in roles {
            let role_info = self.policy.roles.get(&role).ok_or(()).unwrap();

            capabilities.extend(role_info.role_capabilities.iter())
        }

        capabilities
    }

    pub fn is_capable(&self, user_id: &str, capability: Capability) -> Result<bool> {
        Ok(self.is_admin(user_id)? || self.user_capabilities(user_id).contains(&capability))
    }

    /// Returns the sorted list of all users
    pub fn joined_users(&self) -> Vec<String> {
        let mut list = self.user_roles.keys().cloned().collect::<Vec<_>>();

        list.sort();

        list
    }

    fn give_user_role(&mut self, user_id: &str, role: RoleIndex) -> Result<()> {
        if self
            .user_roles
            .entry(user_id.to_owned())
            .or_default()
            .insert(role)
        {
            Ok(())
        } else {
            Err(())
        }
    }

    fn drop_user_role(&mut self, user_id: &str, role: RoleIndex) -> Result<()> {
        if self.user_roles.get_mut(user_id).ok_or(())?.remove(&role) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn role_dependency_checks(&self) -> Result<()> {
        for roles in self.user_roles.values() {
            for role in roles {
                let role_info = self.policy.roles.get(role).ok_or(())?;
                for dependency in &role_info.dependencies {
                    if !roles.contains(dependency) {
                        return Err(());
                    }
                }
            }
        }

        Ok(())
    }

    fn drop_kicked_users(&mut self) -> Result<()> {
        self.user_roles.retain(|_user_id, roles| !roles.is_empty());

        Ok(())
    }

    pub fn make_actions(&mut self, user_id: &str, actions: &[Action]) -> Result<()> {
        let mut new_state = self.clone();

        for action in actions {
            match action {
                Action::Join => {
                    // TODO: Check capability

                    for role in new_state.policy.default_roles.clone() {
                        new_state.give_user_role(user_id, role)?;
                    }
                }
                Action::Kick { target } => {
                    if !new_state.is_capable(user_id, Capability::Kick)? {
                        return Err(());
                    }

                    if new_state.is_protected_from(user_id, target)? {
                        return Err(());
                    }

                    for role in new_state.user_roles.get(target).ok_or(())?.clone() {
                        new_state.drop_user_role(target, role)?;
                    }
                }
                Action::GiveRole { target, role } => {
                    let valid_to_self = target == user_id
                        && new_state
                            .is_capable(user_id, Capability::GiveRoleSelf { role: *role })?;

                    let valid_to_other =
                        new_state.is_capable(user_id, Capability::GiveRole { role: *role })?;
                    // TODO: Do we want protection here? && !new_state.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(());
                    }

                    new_state.give_user_role(target, *role)?;
                }
                Action::DropRole { target, role } => {
                    let valid_to_self = target == user_id
                        && new_state
                            .is_capable(user_id, Capability::DropRoleSelf { role: *role })?;

                    let valid_to_other = new_state
                        .is_capable(user_id, Capability::DropRole { role: *role })?
                        && !new_state.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(());
                    }

                    new_state.drop_user_role(target, *role)?;
                }
                Action::ReadMessage => {
                    if !new_state.is_capable(user_id, Capability::ReadMessage)? {
                        return Err(());
                    }
                }
                Action::SendMessage => {
                    if !new_state.is_capable(user_id, Capability::SendMessage)? {
                        return Err(());
                    }

                    // TODO: Check
                    // - rate limit
                    // - max message size
                    // - allowed content types
                }
                Action::EditMessage { target } => {
                    let valid_to_self = target == user_id
                        && new_state.is_capable(user_id, Capability::EditMessageSelf)?;

                    let valid_to_other = new_state.is_capable(user_id, Capability::EditMessage)?
                        && !new_state.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(());
                    }

                    // TODO: Check
                    // - max message size
                    // - allowed content types
                }

                Action::DeleteMessage { target } => {
                    let valid_to_self = target == user_id
                        && new_state.is_capable(user_id, Capability::DeleteMessageSelf)?;

                    let valid_to_other = new_state
                        .is_capable(user_id, Capability::DeleteMessage)?
                        && !new_state.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(());
                    }
                }
            }
        }

        new_state.role_dependency_checks()?;
        new_state.drop_kicked_users()?;

        *self = new_state;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        let mut roles = HashMap::new();

        // TODO: Should some roles be hardcoded?

        roles.insert(
            RoleIndex::Outsider,
            Role {
                role_name: "Outsider".to_owned(),
                role_description: "Not in the room".to_owned(),
                role_capabilities: vec![],
                dependencies: vec![],
                min: 0,
                max: Some(0), // There should be no outsiders inside the room
            },
        );

        roles.insert(
            RoleIndex::Visitor,
            Role {
                role_name: "Visitor".to_owned(),
                role_description: "Can read, but not send messages".to_owned(),
                role_capabilities: vec![Capability::ReadMessage],
                dependencies: vec![],
                min: 0,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Regular,
            Role {
                role_name: "Regular user".to_owned(),
                role_description: "Can read and send messages".to_owned(),
                role_capabilities: vec![
                    Capability::ReadMessage,
                    Capability::SendMessage,
                    Capability::GiveRole {
                        role: RoleIndex::Visitor,
                    },
                ],
                dependencies: vec![],
                min: 1,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Moderator,
            Role {
                role_name: "Moderator".to_owned(),
                role_description: "Can edit or remove messages sent by others".to_owned(),
                role_capabilities: vec![Capability::EditMessage],
                dependencies: vec![RoleIndex::Regular],
                min: 1,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Admin,
            Role {
                role_name: "Admin".to_owned(),
                role_description: "Has all capabilities".to_owned(),
                role_capabilities: vec![],
                dependencies: vec![RoleIndex::Regular],
                min: 1,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Owner,
            Role {
                role_name: "Owner".to_owned(),
                role_description: "Is protected from admins".to_owned(),
                role_capabilities: vec![],
                dependencies: vec![RoleIndex::Admin],
                min: 1,
                max: None,
            },
        );

        let mut default_roles = HashSet::new();
        default_roles.insert(RoleIndex::Visitor);

        let policy = RoomPolicy {
            roles,
            default_roles,
            //pre_auth_list: vec![],
            //main_rate_limit_ms: 10000, // wait 10 seconds after every message
            //thread_rate_limit_ms: 100, // almost no delay in threads
        };

        let mut room_state = RoomState::new(&policy, "@timo:phnx.im");

        // Only the owner is in the room
        assert_eq!(room_state.joined_users(), vec!["@timo:phnx.im".to_owned()]);

        // @spam joins
        room_state
            .make_actions("@spam:phnx.im", &[Action::Join])
            .unwrap();

        // Now both are in the room
        assert_eq!(
            room_state.joined_users(),
            vec!["@spam:phnx.im".to_owned(), "@timo:phnx.im".to_owned()]
        );

        // @spam has the default role: Visitor
        assert!(room_state
            .user_roles
            .get("@spam:phnx.im")
            .unwrap()
            .contains(&RoleIndex::Visitor));

        // Visitors can only read, not send
        room_state
            .make_actions("@spam:phnx.im", &[Action::ReadMessage])
            .unwrap();
        room_state
            .make_actions("@spam:phnx.im", &[Action::SendMessage])
            .unwrap_err();

        // The owner promotes @spam to a regular user
        room_state
            .make_actions(
                "@timo:phnx.im",
                &[
                    Action::DropRole {
                        target: "@spam:phnx.im".to_owned(),
                        role: RoleIndex::Visitor,
                    },
                    Action::GiveRole {
                        target: "@spam:phnx.im".to_owned(),
                        role: RoleIndex::Regular,
                    },
                ],
            )
            .unwrap();

        // @spam can send messages now
        room_state
            .make_actions("@spam:phnx.im", &[Action::SendMessage])
            .unwrap();

        // The owner can kick @spam, removing all the roles
        room_state
            .make_actions(
                "@timo:phnx.im",
                &[Action::Kick {
                    target: "@spam:phnx.im".to_owned(),
                }],
            )
            .unwrap();

        // Only the owner is in the room
        assert_eq!(room_state.joined_users(), vec!["@timo:phnx.im".to_owned()]);
    }
}
