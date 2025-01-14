// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    iter,
};

type Timestamp = u32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    // TYPE 1: Enforced by hub

    // Membership
    // Join,
    // Knock,
    // Invite,
    // Timeout { max_duration: u32 }, // Applies the role Disabled for the duration, then the user can remove the role by themselves
    Kick,                         // Removes all their roles
    GiveRole { role: RoleIndex }, // E.g. Admins can add moderators
    DropRole { role: RoleIndex }, // E.g. Admins can remove moderators

    GiveRoleSelf { role: RoleIndex }, // E.g. Alice assigns the role Artist to herself
    DropRoleSelf { role: RoleIndex },

    Disabled,

    // TYPE 2: Enforced by clients, the hubs helps if it can
    ReadMessage,
    SendMessage,
    EditMessage,

    IgnoreRatelimit,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Action {
    Join,                                         // Give set of default roles
    Kick,                                         // Drops all their roles
    GiveRole { target: String, role: RoleIndex }, // E.g. Admins can add moderators
    DropRole { target: String, role: RoleIndex }, // E.g. Admins can remove moderators

    // TYPE 2: Enforced by clients, the hubs helps if it can
    ReadMessage,
    SendMessage,
    EditMessage,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RoleIndex {
    Outsider = 0,  // For users not in the room
    Disabled = 1,  // For who were timed out
    Visitor = 2,   // Default for new members in public rooms
    Regular = 3,   // For approved members or new members in invite-only rooms
    Moderator = 4, // Extends regular
    Admin = 5,     // Extends moderator
    Owner = 6,     // Extends owner
    Custom(u16),   // Custom roles
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Role {
    role_name: String,
    role_description: String,
    role_capabilities: Vec<Capability>, // TODO: This could also be a bitvector
    dependencies: Vec<RoleIndex>,       // What roles are required to have this role
    auto_expires_after: Option<Timestamp>, // Timestamp after which this role is no longer active
    min: u32,
    max: Option<u32>,
    // min_active_participants_constraint: Option<u32>, // TODO: What does this mean?
    // max_active_participants_constraint: Option<u32>,
}

#[derive(Clone)]
pub struct PreAuthPerRoleList {
    target_role: RoleIndex, // TODO: RFC writes type Role, we use role index
    preauth_domain: String,
    preauth_workgroup: String, // Uri
    preauth_group: String,     // Uri
    preauth_user: String,      // Uri
}

#[derive(Clone)]
pub struct RoomPolicy {
    roles: HashMap<RoleIndex, Role>,
    pre_auth_list: Vec<PreAuthPerRoleList>,
    main_rate_limit_ms: u32,
    thread_rate_limit_ms: u32,
}

#[derive(Clone)]
pub struct RoomState {
    policy: RoomPolicy,
    user_roles: HashMap<String, HashMap<RoleIndex, Timestamp>>,
}

impl RoomState {
    pub fn new(policy: &RoomPolicy, creator: &str) -> Self {
        let mut user_roles = HashMap::new();

        let mut owner_roles = HashSet::new();

        owner_roles.insert(RoleIndex::Regular);
        owner_roles.insert(RoleIndex::Moderator);
        owner_roles.insert(RoleIndex::Admin);
        owner_roles.insert(RoleIndex::Owner);

        Self {
            policy: policy.clone(),
            user_roles,
        }
    }

    pub fn user_capabilities(&self, user_id: &str) -> HashSet<Capability> {
        let mut roles = HashMap::new();

        if let Some(assigned_roles) = self.user_roles.get(user_id) {
            roles.extend(assigned_roles);
        } else {
            roles.insert(RoleIndex::Outsider, 0);
        }

        let mut capabilities = HashSet::new();

        for (role, timestamp) in roles {
            let role_info = self.policy.roles.get(&role).ok_or(()).unwrap();

            capabilities.extend(role_info.role_capabilities.iter())
        }

        capabilities
    }

    pub fn is_role_active(&self, user_id: &str, role: RoleIndex) -> Result<bool, ()> {
        let Some(role_timestamp) = self.user_roles.get(user_id).ok_or(())?.get(&role) else {
            // User does not have this role
            return Ok(false);
        };

        let role_info = self
            .policy
            .roles
            .get(&role)
            .expect("all assigned roles are defined in the policy");

        if let Some(expires_after) = role_info.auto_expires_after {
            // Role may have expired
            Ok(self.timestamp - role_timestamp <= &expires_after)
        } else {
            // Role cannot expire
            Ok(true)
        }
    }

    pub fn give_user_role(&mut self, user_id: &str, role: RoleIndex) -> Result<(), ()> {
        if self
            .user_roles
            .entry(user_id.to_owned())
            .or_default()
            .insert(role, self.current_timestamp)
            .is_none()
        {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn role_dependency_checks(&self, user_ids: &[&str]) -> Result<(), ()> {
        for (user_id, roles) in self.user_roles {
            for (role, timestamp) in roles {
                if !self.is_role_active(&user_id, role)? {
                    continue;
                }

                let role_info = self.policy.roles.get(&role).ok_or(())?;
                for dependency in &role_info.dependencies {
                    if roles.contains_key(dependency)
                    if !self.user_has_role(user_id, *dependency) {
                        return Err(());
                    }
                }
            }
        }

        Ok(())
    }

    pub fn make_actions(&mut self, user_id: &str, actions: &[Action]) -> Result<(), ()> {
        let user_capabilities = self.user_capabilities(user_id);

        if user_capabilities.contains(&Capability::Disabled) {
            return Err(());
        }

        let mut new_state = self.clone();

        for action in actions {
            match action {
                Action::Join => {}
                Action::Kick => {
                    if !user_capabilities.contains(&Capability::Kick) {
                        return Err(());
                    }

                    todo!();
                }
                Action::GiveRole { target, role } => {
                    new_state.give_user_role(user_id, *role)?;
                }
                Action::DropRole { target, role } => {
                    new_state.drop_user_role(user_id, *role)?;
                }
                Action::ReadMessage => {
                    if !user_capabilities.contains(&Capability::ReadMessage) {
                        return Err(());
                    }
                }
                Action::SendMessage => {
                    if !user_capabilities.contains(&Capability::SendMessage) {
                        return Err(());
                    }
                }
                Action::EditMessage => {
                    if !user_capabilities.contains(&Capability::EditMessage) {
                        return Err(());
                    }
                }
            }
        }

        self.role_dependency_checks()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        let mut roles = HashMap::new();

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
                role_capabilities: vec![Capability::ReadMessage, Capability::SendMessage],
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
                role_description: "Can do anything".to_owned(),
                role_capabilities: vec![
                    Capability::EditMessage,
                    Capability::GiveAnyRole,
                    Capability::DropAnyRole,
                ],
                dependencies: vec![RoleIndex::Regular],
                min: 1,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Owner,
            Role {
                role_name: "Owner".to_owned(),
                role_description: "Cannot be influenced by admins".to_owned(),
                role_capabilities: vec![
                    Capability::EditMessage,
                    Capability::GiveAnyRole,
                    Capability::DropAnyRole,
                ],
                dependencies: vec![RoleIndex::Admin],
                min: 1,
                max: None,
            },
        );

        let policy = RoomPolicy {
            roles,
            main_rate_limit_ms: 10000, // wait 10 seconds after every message
            thread_rate_limit_ms: 100, // almost no delay in threads
            pre_auth_list: vec![],
        };

        let mut room_state = RoomState::new(&policy, "@timo:phnx.im");

        room_state
            .make_actions("@spam:phnx.im", &[Action::Join])
            .unwrap();
    }
}
