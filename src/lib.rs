// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Mimi Room Policy

use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

/// An error returned from room policy operations.
#[derive(Debug)]
pub enum Error {
    /// The operation would have no effect.
    NothingToDo,

    /// The target role is not part of the room policy.
    RoleNotDefined,

    /// The user is not in the room.
    UserNotInRoom,

    /// A user would have a role, but not the dependency roles.
    RoleDependencyViolated,

    /// Too few or too many users would have a role.
    RoleMinMaxViolated,

    /// The user does not have the required capability or the target is protected from the user.
    NotCapable,
}

type Result<T> = std::result::Result<T, Error>;

/// The specified roles have a special features in the room policy.
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

/// Capabilities grant permission to do certain actions and are always positive.
///
/// The following set of actions are not capabilities, because they can be used any member:
/// - ReadMessage: Read messages sent by any user in the room
/// - DropRoleSelf: The user removes a role from themselves, taking away some capabilities.
/// - Leave: Leave the room
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    // TYPE 1: Enforced by hub
    /// Join the room.
    Join,

    /// Ask to be invited into the room.
    Knock,

    /// Force a user to leave the room. They are allowed to rejoin.
    /// This effectively removes all roles from the user.
    Kick,

    /// Adding a role to a user, granting them some capabilities.
    /// E.g. Admins can add moderators.
    GiveRoleOther { role: RoleIndex },

    /// Removing a role from a user, taking away some capabilities.
    /// E.g. Admins can remove moderators.
    DropRoleOther { role: RoleIndex },

    /// A user adds a role to themselves, granting them some capabilities.
    /// E.g. Alice assigns the "Artist" role to herself.
    GiveRoleSelf { role: RoleIndex },

    /// A user does not have to respect the ratelimit defined in the room policy.
    IgnoreRatelimit,

    // TYPE 2: Enforced by clients, the hubs helps if it can
    /// Send a message of a specific type into the room.
    SendMessage { message_type: MessageType },

    /// Edit messages sent by others.
    /// E.g. Removing sensitive details from a message.
    EditMessageOther,

    /// Edit message sent by yourself.
    /// E.g. Clarifying a question or correcting typos.
    EditMessageSelf,

    /// Delete messages sent by others.
    /// E.g. Removing spam.
    DeleteMessageOther,

    /// Deleting messages sent by yourself.
    /// E.g. After accidentally sending a message into a wrong chat.
    DeleteMessageSelf,
}

/// Different types of messages.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// A text message.
    Text,

    /// An image.
    Image,

    /// A regular audio message
    Audio,

    /// A voice audio message.
    Voice,

    /// A video.
    Video,

    /// An arbitrary file.
    File,

    /// Message that start or end a conference
    ControlConference,
}

/// An action that makes use of capabilities.
///
/// There is a lot of similarity to `Capability`, but this is a separate enum because some actions require more information.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// Give set of default roles.
    Join,

    /// Drops all their roles. You can kick yourself to leave the room.
    Kick { target: String },

    /// Add a role to a user.
    // E.g. Admins can add the moderator role to regular users.
    GiveRole { target: String, role: RoleIndex },

    /// Remove a role from a user.
    DropRole { target: String, role: RoleIndex },

    // TYPE 2: Enforced by clients, the hubs helps if it can
    /// Send messages in the room.
    SendMessage { message_type: MessageType },

    /// Edit messages from yourself or others
    EditMessage { target: String },

    /// Delete messages from yourself or others
    DeleteMessage { target: String },
}

/// The definition of a role for the room policy.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RoleInfo {
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

/// The set of rules that the room will follow.
#[derive(Clone)]
pub struct RoomPolicy {
    roles: HashMap<RoleIndex, RoleInfo>,
    default_roles: HashSet<RoleIndex>,
    parent_room: Option<String>,
    password_protected: Option<String>,
    delivery_notifications: Optionality,
    read_receipts: Optionality,
    pseudonymous_ids: bool,
    // pre_auth_list: Vec<PreAuthPerRoleList>,
    // main_rate_limit_ms: u32,
    // thread_rate_limit_ms: u32,
}

/// A value to indicate preference of a feature.
#[derive(Clone)]
pub enum Optionality {
    /// The decision is up to the user or client.
    Optional = 0,

    /// The feature must be active.
    Required = 1,

    /// The feature must be disabled.
    Forbidden = 2,
}

// pub enum MembershipStyle {
//     Open, // outsider has join permission
//     InviteOnly, // outsider does not have join permission
//     FixedMembership, // no one has the join or invite permission
//     ParentDependent, // ??
// }

/// The state of the room.
#[derive(Clone)]
pub struct RoomState {
    /// The general rules for the room.
    policy: RoomPolicy,

    /// The current roles for each user.
    /// Users in this map are all part of the room and allowed to read messages.
    /// A user with no roles is automatically removed from.
    user_roles: HashMap<String, HashSet<RoleIndex>>,
}

/// A list of presets for common room policies.
pub enum PolicyTemplate {
    /// Visitors cannot chat.
    Announcement,

    /// All members can chat.
    Public,

    /// Private room, members can send invites.
    InviteOnly,

    /// Private room, but anyone can knock.
    Knock,

    /// Private room, only admins can invite.
    FixedMembership,

    /// User can join if they are part of the parent room.
    ParentDependent,
}

/// The state of the room. The consistency checks verifed that the state is valid.
pub struct VerifiedRoomState(RoomState);

impl RoomState {
    /// Construct a new room using the specified template.
    pub fn new_from_template(owner: &str, template: PolicyTemplate) -> Self {
        let mut roles = HashMap::new();

        roles.insert(
            RoleIndex::Outsider,
            RoleInfo {
                role_name: "Outsider".to_owned(),
                role_description: "Not in the room".to_owned(),
                role_capabilities: match template {
                    PolicyTemplate::Public => vec![Capability::Join],
                    PolicyTemplate::Knock => vec![Capability::Knock],
                    _ => vec![],
                },
                dependencies: vec![],
                min: 0,
                max: Some(0), // There should be no outsiders inside the room
            },
        );

        roles.insert(
            RoleIndex::Visitor,
            match template {
                PolicyTemplate::Announcement => RoleInfo {
                    role_name: "Visitor".to_owned(),
                    role_description: "Can only read".to_owned(),
                    role_capabilities: vec![Capability::GiveRoleOther {
                        role: RoleIndex::Visitor, // Invite users
                    }],
                    dependencies: vec![],
                    min: 0,
                    max: None,
                },

                PolicyTemplate::Public => RoleInfo {
                    role_name: "Visitor".to_owned(),
                    role_description:
                        "Can read, and send text messages and images, but rate-limited".to_owned(),
                    role_capabilities: vec![
                        Capability::SendMessage {
                            message_type: MessageType::Text,
                        },
                        Capability::SendMessage {
                            message_type: MessageType::Image,
                        },
                        Capability::EditMessageSelf,
                        Capability::DeleteMessageSelf,
                        Capability::GiveRoleOther {
                            role: RoleIndex::Visitor, // Invite users
                        },
                    ],
                    dependencies: vec![],
                    min: 0,
                    max: None,
                },

                PolicyTemplate::InviteOnly | PolicyTemplate::Knock | PolicyTemplate::FixedMembership => RoleInfo {
                    role_name: "Visitor".to_owned(),
                    role_description:
                        "User was invited and can read messages, but cannot send until accepting the invite".to_owned(),
                    role_capabilities: vec![
                        // Accept the invite
                        Capability::GiveRoleSelf {
                            role: RoleIndex::Regular,
                        },
                    ],
                    dependencies: vec![],
                    min: 0,
                    max: None,
                },

                PolicyTemplate::ParentDependent => todo!(),
            },
        );

        roles.insert(
            RoleIndex::Regular,
            RoleInfo {
                role_name: "Regular user".to_owned(),
                role_description: "Can read and send messages without rate-limit".to_owned(),
                role_capabilities: vec![
                    // Send messages
                    Capability::SendMessage {
                        message_type: MessageType::Text,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::Image,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::Voice,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::Audio,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::Video,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::File,
                    },
                    // No conference control messages are allowed

                    // No rate-limit for approved users
                    Capability::IgnoreRatelimit,
                ],
                dependencies: vec![RoleIndex::Visitor],
                min: 0,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Moderator,
            RoleInfo {
                role_name: "Moderator".to_owned(),
                role_description:
                    "Can edit or remove messages sent by others. Can promote more moderators"
                        .to_owned(),
                role_capabilities: vec![
                    // Control a conference
                    Capability::SendMessage {
                        message_type: MessageType::ControlConference,
                    },
                    // Moderate
                    Capability::EditMessageOther,
                    Capability::DeleteMessageOther,
                    // Add more moderators
                    Capability::GiveRoleOther {
                        role: RoleIndex::Moderator,
                    },
                ],
                dependencies: vec![RoleIndex::Regular],
                min: 0,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Admin,
            RoleInfo {
                role_name: "Admin".to_owned(),
                role_description: "Has all capabilities".to_owned(),
                role_capabilities: vec![
                    // Admins have all capabilities anyway
                ],
                dependencies: vec![RoleIndex::Moderator],
                min: 0,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Owner,
            RoleInfo {
                role_name: "Owner".to_owned(),
                role_description: "Is protected from admins".to_owned(),
                role_capabilities: vec![
                    // Admins have all capabilities anyway
                ],
                dependencies: vec![RoleIndex::Admin],
                min: 1,
                max: Some(1),
            },
        );

        let mut default_roles = HashSet::new();
        default_roles.insert(RoleIndex::Visitor);

        let policy = RoomPolicy {
            roles,
            default_roles,
            parent_room: None,
            password_protected: None,
            delivery_notifications: Optionality::Optional,
            read_receipts: Optionality::Optional,
            pseudonymous_ids: false,
            //pre_auth_list: vec![],
            //main_rate_limit_ms: 10000, // wait 10 seconds after every message
            //thread_rate_limit_ms: 100, // almost no delay in threads
        };

        RoomState::new(owner, &policy)
    }

    /// Construct a new room with the given policy.
    pub fn new(owner: &str, policy: &RoomPolicy) -> Self {
        let mut user_roles = HashMap::new();

        let mut owner_roles = HashSet::new();

        owner_roles.insert(RoleIndex::Visitor);
        owner_roles.insert(RoleIndex::Regular);
        owner_roles.insert(RoleIndex::Moderator);
        owner_roles.insert(RoleIndex::Admin);
        owner_roles.insert(RoleIndex::Owner);

        user_roles.insert(owner.to_owned(), owner_roles);

        Self {
            policy: policy.clone(),
            user_roles,
        }
    }

    /// Returns true if the user has the Moderator role.
    pub fn is_mod(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .ok_or(Error::UserNotInRoom)?
            .contains(&RoleIndex::Moderator))
    }

    /// Returns true if the user has the Admin role.
    pub fn is_admin(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .ok_or(Error::UserNotInRoom)?
            .contains(&RoleIndex::Admin))
    }

    /// Returns true if the user has the Owner role.
    pub fn is_owner(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .ok_or(Error::UserNotInRoom)?
            .contains(&RoleIndex::Owner))
    }

    /// Returns true if the target is protected from the actor:
    /// - Owners are protected from everyone.
    /// - Admins are protected from other admins.
    /// - Moderators are protected from other moderators.
    ///
    /// Because all admins are also moderators, admins are protected from moderators.
    pub fn is_protected_from(&self, actor: &str, target: &str) -> Result<bool> {
        Ok(self.is_owner(target)?
            || self.is_admin(target)? && !self.is_admin(actor)?
            || self.is_mod(target)? && !self.is_mod(actor)?)
    }

    /// The list of all capabilities of a user as determined by their roles.
    ///
    /// - Admins implicitly have all capabilities, even those not listed by this function.
    /// - If a user has no roles, they receive the capabilities of the Outsider role.
    pub fn user_explicit_capabilities(&self, user_id: &str) -> Result<HashSet<Capability>> {
        let mut roles = HashSet::new();

        if let Some(assigned_roles) = self.user_roles.get(user_id) {
            roles.extend(assigned_roles);
        } else {
            roles.insert(RoleIndex::Outsider);
        }

        let mut capabilities = HashSet::new();

        for role in roles {
            let role_info = self.policy.roles.get(&role).ok_or(Error::RoleNotDefined)?;

            capabilities.extend(role_info.role_capabilities.iter())
        }

        Ok(capabilities)
    }

    /// Returns true if the user has this capability explicitly or if they are an administrator.
    pub fn is_capable(&self, user_id: &str, capability: Capability) -> Result<bool> {
        Ok(self.is_admin(user_id)?
            || self
                .user_explicit_capabilities(user_id)?
                .contains(&capability))
    }

    /// Returns the sorted list of all users.
    pub fn joined_users(&self) -> Vec<String> {
        let mut list = self.user_roles.keys().cloned().collect::<Vec<_>>();

        list.sort();

        list
    }

    /// Adds a role to a user.
    fn give_user_role(&mut self, user_id: &str, role: RoleIndex) -> Result<()> {
        if self
            .user_roles
            .entry(user_id.to_owned())
            .or_default()
            .insert(role)
        {
            Ok(())
        } else {
            Err(Error::NothingToDo)
        }
    }

    /// Removes a role from a user.
    fn drop_user_role(&mut self, user_id: &str, role: RoleIndex) -> Result<()> {
        if self
            .user_roles
            .get_mut(user_id)
            .ok_or(Error::UserNotInRoom)?
            .remove(&role)
        {
            Ok(())
        } else {
            Err(Error::NothingToDo)
        }
    }

    fn consistency_checks(mut self) -> Result<VerifiedRoomState> {
        let mut role_counts = HashMap::new();
        // Role dependencies
        for roles_of_user in self.user_roles.values() {
            for role in roles_of_user {
                *role_counts.entry(role).or_insert(0_u32) += 1;
                let role_info = self.policy.roles.get(role).ok_or(Error::RoleNotDefined)?;
                for dependency in &role_info.dependencies {
                    if !roles_of_user.contains(dependency) {
                        return Err(Error::RoleDependencyViolated);
                    }
                }
            }
        }

        for (role, count) in role_counts {
            let role_info = self.policy.roles.get(role).ok_or(Error::RoleNotDefined)?;

            if count < role_info.min || role_info.max.is_some_and(|max| count > max) {
                return Err(Error::RoleMinMaxViolated);
            }
        }

        // Drop users that have no role
        self.user_roles.retain(|_user_id, roles| !roles.is_empty());

        Ok(VerifiedRoomState(self))
    }

    /// Applies the list of actions in the given order. This will not verify consistency.
    pub fn try_make_actions(mut self, user_id: &str, actions: &[Action]) -> Result<Self> {
        for action in actions {
            match action {
                Action::Join => {
                    // TODO: Check capability

                    for role in self.policy.default_roles.clone() {
                        self.give_user_role(user_id, role)?;
                    }
                }
                Action::Kick { target } => {
                    if user_id != target && !self.is_capable(user_id, Capability::Kick)? {
                        return Err(Error::NotCapable);
                    }

                    if self.is_protected_from(user_id, target)? {
                        return Err(Error::NotCapable);
                    }

                    for role in self
                        .user_roles
                        .get(target)
                        .ok_or(Error::UserNotInRoom)?
                        .clone()
                    {
                        self.drop_user_role(target, role)?;
                    }
                }
                Action::GiveRole { target, role } => {
                    let valid_to_self = target == user_id
                        && self.is_capable(user_id, Capability::GiveRoleSelf { role: *role })?;

                    let valid_to_other =
                        self.is_capable(user_id, Capability::GiveRoleOther { role: *role })?;
                    // TODO: Do we want protection here? && !self.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(Error::NotCapable);
                    }

                    self.give_user_role(target, *role)?;
                }
                Action::DropRole { target, role } => {
                    let valid_to_self = target == user_id;

                    let valid_to_other = self
                        .is_capable(user_id, Capability::DropRoleOther { role: *role })?
                        && !self.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(Error::NotCapable);
                    }

                    self.drop_user_role(target, *role)?;
                }
                Action::SendMessage { message_type } => {
                    if !self.is_capable(
                        user_id,
                        Capability::SendMessage {
                            message_type: *message_type,
                        },
                    )? {
                        return Err(Error::NotCapable);
                    }

                    // TODO: Check
                    // - rate limit
                    // - max message size
                    // - allowed content types
                }
                Action::EditMessage { target } => {
                    let valid_to_self = target == user_id
                        && self.is_capable(user_id, Capability::EditMessageSelf)?;

                    let valid_to_other = self.is_capable(user_id, Capability::EditMessageOther)?
                        && !self.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(Error::NotCapable);
                    }

                    // TODO: Check
                    // - max message size
                    // - allowed content types
                }

                Action::DeleteMessage { target } => {
                    let valid_to_self = target == user_id
                        && self.is_capable(user_id, Capability::DeleteMessageSelf)?;

                    let valid_to_other = self
                        .is_capable(user_id, Capability::DeleteMessageOther)?
                        && !self.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(Error::NotCapable);
                    }
                }
            }
        }

        Ok(self)
    }
}

impl VerifiedRoomState {
    pub fn new_from_template(owner: &str, template: PolicyTemplate) -> Self {
        let state = RoomState::new_from_template(owner, template);

        state
            .consistency_checks()
            .expect("new_from_template is always valid")
    }

    pub fn new(owner: &str, policy: &RoomPolicy) -> Result<Self> {
        let state = RoomState::new(owner, policy);

        state.consistency_checks()
    }

    pub fn make_actions(&mut self, user_id: &str, actions: &[Action]) -> Result<()> {
        let result = self.0.clone().try_make_actions(user_id, actions)?;

        *self = result.consistency_checks()?;

        Ok(())
    }
}

impl Deref for VerifiedRoomState {
    type Target = RoomState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        let mut room_state =
            VerifiedRoomState::new_from_template("@timo:phnx.im", PolicyTemplate::Announcement);

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
        room_state.make_actions("@spam:phnx.im", &[]).unwrap();
        room_state
            .make_actions(
                "@spam:phnx.im",
                &[Action::SendMessage {
                    message_type: MessageType::Image,
                }],
            )
            .unwrap_err();

        // The owner promotes @spam to a regular user
        room_state
            .make_actions(
                "@timo:phnx.im",
                &[Action::GiveRole {
                    target: "@spam:phnx.im".to_owned(),
                    role: RoleIndex::Regular,
                }],
            )
            .unwrap();

        // @spam can send messages now
        room_state
            .make_actions(
                "@spam:phnx.im",
                &[Action::SendMessage {
                    message_type: MessageType::Image,
                }],
            )
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
