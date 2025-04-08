// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! There are three types of capabilities users can have and they are handled in different ways. Each requests must only use one type of capability and must otherwise be split into multiple requests.
//! 1. Policy-changing capabilities: If the user adds or removes roles or changes role properties, this must be handled very carefully to not cause problems with other roles or the existing room state.
//! 2. State-changing capabilities: Proposals can use these capabilities to change the role assignments to users, but cannot change the roles themselves.
//! 3. Timeline-changing capabilities: These capabilities are for sending messages, editing messages, starting a poll, etc. There are no room policy proposals for these capabilities. Instead, the code handling timeline events should consult the room policy to see if the event is allowed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
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

    /// Could not create a new role, because a role with this RoleIndex already exists.
    RoleAlreadyExists,

    /// The action could not be taken, because of special rules for the relevant capability.
    SpecialCapability,

    /// The action could not be taken, because of special rules for the relevant role.
    SpecialRole,

    /// A string value could not be set, because it is too long.
    StringTooLong,

    /// The dependencies could not be changed.
    InvalidRoleDependencies,

    /// A role could not be removed, because there are still users with this role.
    RoleInUse,

    /// The user was banned.
    Banned,
    InvalidRoleDefinition,
    InvalidMinMaxConstraints,
    InvalidRoleTransition {
        source: RoleIndex,
        target: RoleIndex,
    },
}

type Result<T> = std::result::Result<T, Error>;

/// The specified roles have a special features in the room policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u32)]
pub enum RoleIndex {
    /// Outsiders are not in the room and are not trusted at all.
    Outsider = 0,

    Banned = 1,

    Regular = 2,

    Admin = 3,

    Owner = 4,

    /// Custom roles
    Custom(u32),
}

/// The definition of a role for the room policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleInfo {
    role_name: String,
    role_description: String,
    role_capabilities: Vec<Capability>, // TODO: This could also be a bitvector
    min_participants_constraint: u32,
    max_participants_constraint: Option<u32>,
    min_active_participants_constraint: u32,
    max_active_participants_constraint: Option<u32>,
    authorized_role_changes: BTreeMap<RoleIndex, Vec<RoleIndex>>,
    self_role_changes: Vec<RoleIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Capability {
    // AddParticipant,
    // RemoveParticipant,
    // AddOwnClient,
    // RemoveSelf,
    // AddSelf,
    // CreateJoinCode, // reserved for future use
    // UseJoinCode,
    // Ban,
    // UnBan,
    // Kick,
    // Knock,
    // AcceptKnock,
    // ChangeUserRole,
    // ChangeOwnRole,
    // CreateSubgroup,
    SendMessage,
    ReceiveMessage,
    // CopyMessage,
    // ReportAbuse,
    ReactToMessage,
    // EditReaction,
    DeleteReaction,
    EditOwnMessage,
    // EditOtherMessage,
    DeleteOwnMessage,
    DeleteAnyMessage,
    // StartTopic,
    // ReplyInTopic,
    // EditTopic,
    // SendDirectMessage,
    // TargetMessage,
    UploadImage,
    UploadVideo,
    UploadAttachment,
    // DownloadImage,
    // DownloadVideo,
    // DownloadAttachment,
    // SendLink,
    // SendLinkPreview,
    // FollowLink,
    // CopyLink,
    ChangeRoomName,
    ChangeRoomDescription,
    ChangeRoomAvatar,
    // ChangeRoomSubject,
    // ChangeRoomMood,
    // ChangeOwnName,
    // ChangeOwnPresence,
    // ChangeOwnMood,
    // ChangeOwnAvatar,
    StartCall,
    JoinCall,
    // SendAudio,
    // ReceiveAudio,
    // SendVideo,
    // ReceiveVideo,
    // ShareScreen,
    // ViewSharedScreen,
    // ChangeRoomMembershipStyle,
    ChangeRoleDefinitions,
    // ChangePreauthorizedUserList,
    // ChangeMlsOperationalPolicies,
    // DestroyRoom,
    // SendMLSReinitProposal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MimiProposal {
    //
    // Join a room, leave a room, kick a user, ban a user.
    //
    ChangeRole { target: u32, role: RoleIndex },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MembershipStyle {
    Reserved = 0,
    Ordinary = 1,
    FixedMembership = 2,
    ParentDependent = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkPolicy {
    on_request: bool,
    join_link: String,
    multiuser: bool,
    expiration: u32,
    link_requests: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoggingPolicy {
    logging: Optionality,
    logging_clients: Vec<String>,
    machine_readable_policy: String,
    human_readable_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryPolicy {
    history_sharing: Optionality,
    who_can_share: Vec<RoleIndex>,
    automatically_share: bool,
    max_time_period: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Bot {
    description: String,
    homepage: String,
    bot_role: RoleIndex,
    can_read: bool,
    can_write: bool,
    can_target_message_in_group: bool,
    per_user_content: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExtension {
    name: String,
    value_type: (),
    value: Vec<u8>,
}

/// A value to indicate preference of a feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Optionality {
    /// The decision is up to the user or client.
    Optional = 0,

    /// The feature must be active.
    Required = 1,

    /// The feature must be disabled.
    Forbidden = 2,
}

/// The set of rules that the room will follow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomPolicy {
    roles: BTreeMap<RoleIndex, RoleInfo>,

    uncommitted_proposals: Vec<MimiProposal>,

    membership_style: MembershipStyle,
    multi_device: bool,
    parent_room_uri: String,
    persistent_room: bool,
    delivery_notifications: Optionality,
    read_receipts: Optionality,
    semi_anonymous_ids: bool,
    discoverable: bool,
    link_policy: LinkPolicy,
    logging_policy: LoggingPolicy,
    history_sharing: HistoryPolicy,
    allowed_bots: BTreeMap<String, Bot>,
    policy_extensions: Vec<PolicyExtension>,
}

impl RoomPolicy {
    pub fn default_dm() -> Self {
        let mut roles = BTreeMap::new();

        let regular_role = RoleInfo {
            role_name: "User".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: vec![Capability::ReceiveMessage, Capability::SendMessage],
            min_participants_constraint: 1,
            max_participants_constraint: None,
            min_active_participants_constraint: 0,
            max_active_participants_constraint: None,
            authorized_role_changes: BTreeMap::new(),
            self_role_changes: Vec::new(),
        };

        let owner_role = RoleInfo {
            role_name: "Owner".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: vec![Capability::ReceiveMessage, Capability::SendMessage],
            min_participants_constraint: 1,
            max_participants_constraint: Some(1),
            min_active_participants_constraint: 1,
            max_active_participants_constraint: Some(1),
            authorized_role_changes: BTreeMap::new(),
            self_role_changes: Vec::new(),
        };

        roles.insert(RoleIndex::Regular, regular_role);
        roles.insert(RoleIndex::Owner, owner_role);

        Self {
            roles,
            membership_style: MembershipStyle::FixedMembership,
            ..Self::default_private()
        }
    }

    pub fn default_private() -> Self {
        let mut roles = BTreeMap::new();

        // Regular
        let mut regular_role_changes = BTreeMap::new();
        regular_role_changes.insert(
            RoleIndex::Outsider,
            vec![RoleIndex::Regular], // Can invite
        );

        // Admin
        let mut admin_role_changes = BTreeMap::new();
        admin_role_changes.insert(
            RoleIndex::Outsider,
            vec![RoleIndex::Regular, RoleIndex::Admin],
        );
        admin_role_changes.insert(
            RoleIndex::Regular,
            vec![RoleIndex::Outsider, RoleIndex::Admin],
        );

        // Owner
        let mut owner_role_changes = BTreeMap::new();
        owner_role_changes.insert(
            RoleIndex::Outsider,
            vec![RoleIndex::Regular, RoleIndex::Admin, RoleIndex::Owner],
        );
        owner_role_changes.insert(
            RoleIndex::Regular,
            vec![RoleIndex::Outsider, RoleIndex::Admin, RoleIndex::Owner],
        );
        owner_role_changes.insert(
            RoleIndex::Admin,
            vec![RoleIndex::Outsider, RoleIndex::Regular],
        );

        let outsider_role = RoleInfo {
            role_name: "Outsider".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: Vec::new(),
            min_participants_constraint: 0,
            max_participants_constraint: Some(0),
            min_active_participants_constraint: 0,
            max_active_participants_constraint: Some(0),
            authorized_role_changes: BTreeMap::new(),
            self_role_changes: Vec::new(),
        };

        let regular_role = RoleInfo {
            role_name: "Regular user".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: vec![Capability::ReceiveMessage, Capability::SendMessage],
            min_participants_constraint: 0,
            max_participants_constraint: None,
            min_active_participants_constraint: 0,
            max_active_participants_constraint: None,
            authorized_role_changes: regular_role_changes,
            self_role_changes: vec![RoleIndex::Outsider],
        };

        let admin_role = RoleInfo {
            role_name: "Admin".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: vec![Capability::ReceiveMessage, Capability::SendMessage],
            min_participants_constraint: 0,
            max_participants_constraint: None,
            min_active_participants_constraint: 0,
            max_active_participants_constraint: None,
            authorized_role_changes: admin_role_changes,
            self_role_changes: vec![RoleIndex::Outsider, RoleIndex::Regular],
        };

        let owner_role = RoleInfo {
            role_name: "Owner".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: vec![Capability::ReceiveMessage, Capability::SendMessage],
            min_participants_constraint: 1,
            max_participants_constraint: Some(1),
            min_active_participants_constraint: 1,
            max_active_participants_constraint: Some(1),
            authorized_role_changes: owner_role_changes,
            self_role_changes: vec![RoleIndex::Outsider, RoleIndex::Regular, RoleIndex::Admin],
        };

        roles.insert(RoleIndex::Outsider, outsider_role);
        roles.insert(RoleIndex::Regular, regular_role);
        roles.insert(RoleIndex::Admin, admin_role);
        roles.insert(RoleIndex::Owner, owner_role);

        Self {
            roles,
            uncommitted_proposals: Vec::new(),
            membership_style: MembershipStyle::Ordinary,
            multi_device: true,
            parent_room_uri: "".to_owned(),
            persistent_room: false,
            delivery_notifications: Optionality::Optional,
            read_receipts: Optionality::Optional,
            semi_anonymous_ids: true,
            discoverable: false,
            link_policy: LinkPolicy {
                on_request: true,
                join_link: "".to_owned(),
                multiuser: true,
                expiration: 0,
                link_requests: "".to_owned(),
            },
            logging_policy: LoggingPolicy {
                logging: Optionality::Forbidden,
                logging_clients: Vec::new(),
                machine_readable_policy: "".to_owned(),
                human_readable_policy: "".to_owned(),
            },
            history_sharing: HistoryPolicy {
                history_sharing: Optionality::Forbidden,
                who_can_share: Vec::new(),
                automatically_share: false,
                max_time_period: 0,
            },
            allowed_bots: BTreeMap::new(),
            policy_extensions: Vec::new(),
        }
    }

    pub fn default_public() -> Self {
        let mut roles = BTreeMap::new();

        // Regular
        let mut regular_role_changes = BTreeMap::new();
        regular_role_changes.insert(
            RoleIndex::Outsider,
            vec![RoleIndex::Regular], // Can invite
        );

        // Admin
        let mut admin_role_changes = BTreeMap::new();
        admin_role_changes.insert(
            RoleIndex::Outsider,
            vec![RoleIndex::Banned, RoleIndex::Regular, RoleIndex::Admin],
        );
        admin_role_changes.insert(
            RoleIndex::Banned,
            vec![RoleIndex::Outsider, RoleIndex::Regular, RoleIndex::Admin],
        );
        admin_role_changes.insert(
            RoleIndex::Regular,
            vec![RoleIndex::Outsider, RoleIndex::Banned, RoleIndex::Admin],
        );

        // Owner
        let mut owner_role_changes = BTreeMap::new();
        owner_role_changes.insert(
            RoleIndex::Outsider,
            vec![
                RoleIndex::Banned,
                RoleIndex::Regular,
                RoleIndex::Admin,
                RoleIndex::Owner,
            ],
        );
        owner_role_changes.insert(
            RoleIndex::Banned,
            vec![
                RoleIndex::Outsider,
                RoleIndex::Regular,
                RoleIndex::Admin,
                RoleIndex::Owner,
            ],
        );
        owner_role_changes.insert(
            RoleIndex::Regular,
            vec![
                RoleIndex::Outsider,
                RoleIndex::Banned,
                RoleIndex::Admin,
                RoleIndex::Owner,
            ],
        );
        owner_role_changes.insert(
            RoleIndex::Admin,
            vec![RoleIndex::Outsider, RoleIndex::Banned, RoleIndex::Regular],
        );

        let outsider_role = RoleInfo {
            role_name: "Outsider".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: Vec::new(),
            min_participants_constraint: 0,
            max_participants_constraint: Some(0),
            min_active_participants_constraint: 0,
            max_active_participants_constraint: Some(0),
            authorized_role_changes: BTreeMap::new(),
            self_role_changes: vec![RoleIndex::Regular],
        };

        let banned_role = RoleInfo {
            role_name: "Banned".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: Vec::new(),
            min_participants_constraint: 0,
            max_participants_constraint: None,
            min_active_participants_constraint: 0,
            max_active_participants_constraint: Some(0),
            authorized_role_changes: BTreeMap::new(),
            self_role_changes: Vec::new(),
        };

        let regular_role = RoleInfo {
            role_name: "Regular user".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: vec![Capability::ReceiveMessage, Capability::SendMessage],
            min_participants_constraint: 0,
            max_participants_constraint: None,
            min_active_participants_constraint: 0,
            max_active_participants_constraint: None,
            authorized_role_changes: regular_role_changes,
            self_role_changes: vec![RoleIndex::Outsider],
        };

        let admin_role = RoleInfo {
            role_name: "Admin".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: vec![Capability::ReceiveMessage, Capability::SendMessage],
            min_participants_constraint: 0,
            max_participants_constraint: None,
            min_active_participants_constraint: 0,
            max_active_participants_constraint: None,
            authorized_role_changes: admin_role_changes,
            self_role_changes: vec![RoleIndex::Outsider, RoleIndex::Regular],
        };

        let owner_role = RoleInfo {
            role_name: "Owner".to_owned(),
            role_description: "".to_owned(),
            role_capabilities: vec![Capability::ReceiveMessage, Capability::SendMessage],
            min_participants_constraint: 1,
            max_participants_constraint: Some(1),
            min_active_participants_constraint: 1,
            max_active_participants_constraint: Some(1),
            authorized_role_changes: owner_role_changes,
            self_role_changes: vec![RoleIndex::Outsider, RoleIndex::Regular, RoleIndex::Admin],
        };

        roles.insert(RoleIndex::Outsider, outsider_role);
        roles.insert(RoleIndex::Banned, banned_role);
        roles.insert(RoleIndex::Regular, regular_role);
        roles.insert(RoleIndex::Admin, admin_role);
        roles.insert(RoleIndex::Owner, owner_role);

        Self {
            roles,
            history_sharing: HistoryPolicy {
                history_sharing: Optionality::Required,
                who_can_share: vec![RoleIndex::Admin, RoleIndex::Owner],
                automatically_share: true,
                max_time_period: 60 * 60 * 24 * 10, // Last 10 days
            },
            ..Self::default_private()
        }
    }

    fn try_policy_proposals(&mut self, proposals: &[MimiProposal]) -> Result<()> {
        for proposal in proposals {}
        Ok(())
    }
}

/// The state of the room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomState {
    /// The general rules for the room.
    policy: RoomPolicy,

    users: BTreeMap<u32, RoleIndex>,
}

impl RoomState {
    pub fn user_role(&self, user_id: &u32) -> RoleIndex {
        self.users
            .get(user_id)
            .cloned()
            .unwrap_or(RoleIndex::Outsider)
    }

    pub fn user_capabilities(&self, user_id: &u32) -> &[Capability] {
        &self.policy.roles[&self.user_role(user_id)].role_capabilities
    }

    pub fn has_capability(&self, user_id: &u32, capability: Capability) -> bool {
        self.user_capabilities(user_id).contains(&capability)
    }

    fn try_regular_proposals(&mut self, sender: &u32, proposals: &[MimiProposal]) -> Result<()> {
        for proposal in proposals {
            match proposal {
                MimiProposal::ChangeRole { target, role } => {
                    let sender_user_role = self.user_role(sender);
                    let target_user_role = self.user_role(target);

                    let possible_roles = if sender == target {
                        &*self.policy.roles[&sender_user_role].self_role_changes
                    } else {
                        self.policy.roles[&sender_user_role]
                            .authorized_role_changes
                            .get(&target_user_role)
                            .map_or(&[][..], |x| x) // Default to empty list
                    };

                    if possible_roles.contains(role) {
                        if *role == RoleIndex::Outsider {
                            self.users.remove(target);
                        } else {
                            self.users.insert(target.clone(), role.clone());
                        }
                    } else {
                        return Err(Error::NotCapable);
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedRoomState(RoomState);

impl VerifiedRoomState {
    fn consistency_checks(state: RoomState) -> Result<Self> {
        // POLICY CHECKS

        // No outsiders are explicitly listed
        if state.users.values().any(|u| *u == RoleIndex::Outsider) {
            return Err(Error::UserNotInRoom);
        }

        // Outsider role must have name "Outsider" if it exists. And participants 0
        let Some(outsider_role) = state.policy.roles.get(&RoleIndex::Outsider) else {
            return Err(Error::SpecialRole);
        };

        if outsider_role.role_name != "Outsider"
            || outsider_role.max_participants_constraint != Some(0)
        {
            return Err(Error::SpecialRole);
        }

        // Banned role must have name "Banned" if it exists. And active participants 0
        if let Some(banned_role) = state.policy.roles.get(&RoleIndex::Banned) {
            if banned_role.role_name != "Banned"
                || banned_role.max_active_participants_constraint != Some(0)
            {
                return Err(Error::SpecialRole);
            }
        }

        // Role transitions all point to valid role ids that are not the same.
        // TODO

        for (role_index, role_info) in &state.policy.roles {
            if role_info.role_name.is_empty()
                || role_info
                    .max_participants_constraint
                    .is_some_and(|max| max < role_info.min_participants_constraint)
                || role_info
                    .max_active_participants_constraint
                    .is_some_and(|max| max < role_info.min_active_participants_constraint)
            {
                return Err(Error::InvalidMinMaxConstraints);
            }

            for (source_role, targets) in &role_info.authorized_role_changes {
                if !state.policy.roles.contains_key(source_role) {
                    return Err(Error::RoleNotDefined);
                }

                for target_role in targets {
                    if source_role == target_role {
                        return Err(Error::InvalidRoleTransition {
                            source: *source_role,
                            target: *target_role,
                        });
                    }
                    if !state.policy.roles.contains_key(target_role) {
                        return Err(Error::RoleNotDefined);
                    }
                }
            }

            for target_role in &role_info.self_role_changes {
                if role_index == target_role {
                    return Err(Error::InvalidRoleTransition {
                        source: *role_index,
                        target: *target_role,
                    });
                }
                if !state.policy.roles.contains_key(target_role) {
                    return Err(Error::RoleNotDefined);
                }
            }
        }

        // ROOM STATE CHECKS

        let mut role_member_count = BTreeMap::new();
        for user_role in state.users.values() {
            *role_member_count.entry(user_role).or_insert(0_u32) += 1;

            if !state.policy.roles.contains_key(user_role) {
                return Err(Error::RoleNotDefined);
            }
        }

        for (role_index, role_info) in &state.policy.roles {
            let count = role_member_count.get(&role_index).unwrap_or(&0);
            if role_info
                .max_participants_constraint
                .is_some_and(|max| *count > max)
                || *count < role_info.min_participants_constraint
            {
                return Err(Error::RoleMinMaxViolated);
            }
        }

        // TODO: Active participants?
        // TODO: How to make sure the user is removed from mls group

        Ok(VerifiedRoomState(state))
    }

    pub fn new(owner: &u32, policy: RoomPolicy) -> Result<Self> {
        let mut users = BTreeMap::new();
        users.insert(owner.to_owned(), RoleIndex::Owner);

        let state = RoomState { users, policy };

        Self::consistency_checks(state)
    }

    pub fn has_capability(&self, user_id: &u32, capability: Capability) -> bool {
        self.0.has_capability(user_id, capability)
    }

    pub fn try_regular_proposals(
        &mut self,
        sender: &u32,
        proposals: &[MimiProposal],
    ) -> Result<()> {
        let mut state = self.0.clone();

        state.try_regular_proposals(sender, proposals)?;

        *self = Self::consistency_checks(state)?;

        Ok(())
    }

    pub fn try_policy_proposals(&mut self, sender: &u32, proposals: &[MimiProposal]) -> Result<()> {
        let mut state = self.0.clone();
        state.policy.try_policy_proposals(proposals)?;

        *self = Self::consistency_checks(state)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_only_room() {
        let alice = 0; //"alice".to_owned();
        let bob = 1; //"bob".to_owned();

        // Alice creates an invite-only room
        let mut room = VerifiedRoomState::new(&alice, RoomPolicy::default_private()).unwrap();

        // Bob cannot join
        assert_eq!(
            room.try_regular_proposals(
                &bob,
                &[MimiProposal::ChangeRole {
                    target: bob.clone(),
                    role: RoleIndex::Regular,
                }],
            ),
            Err(Error::NotCapable)
        );

        // Bob cannot send messages
        assert!(!room.has_capability(&bob, Capability::SendMessage));

        // Alice can add Bob
        room.try_regular_proposals(
            &alice,
            &[MimiProposal::ChangeRole {
                target: bob.clone(),
                role: RoleIndex::Regular,
            }],
        )
        .unwrap();

        // Bob can now send messages
        assert!(room.has_capability(&bob, Capability::SendMessage));

        // Bob cannot kick Alice
        assert_eq!(
            room.try_regular_proposals(
                &bob,
                &[MimiProposal::ChangeRole {
                    target: alice.clone(),
                    role: RoleIndex::Outsider,
                }],
            ),
            Err(Error::NotCapable)
        );

        // Alice can kick bob
        room.try_regular_proposals(
            &alice,
            &[MimiProposal::ChangeRole {
                target: bob.clone(),
                role: RoleIndex::Outsider,
            }],
        )
        .unwrap();

        // Bob cannot send messages
        assert!(!room.has_capability(&bob, Capability::SendMessage));
    }

    #[test]
    fn public_room() {
        let alice = 0; //"alice".to_owned();
        let bob = 1; //"bob".to_owned();

        // Alice creates a public room
        let mut room = VerifiedRoomState::new(&alice, RoomPolicy::default_public()).unwrap();

        // Bob can join
        room.try_regular_proposals(
            &bob,
            &[MimiProposal::ChangeRole {
                target: bob.clone(),
                role: RoleIndex::Regular,
            }],
        )
        .unwrap();

        // Alice can kick bob
        room.try_regular_proposals(
            &alice,
            &[MimiProposal::ChangeRole {
                target: bob.clone(),
                role: RoleIndex::Outsider,
            }],
        )
        .unwrap();

        // Bob can rejoin
        room.try_regular_proposals(
            &bob,
            &[MimiProposal::ChangeRole {
                target: bob.clone(),
                role: RoleIndex::Regular,
            }],
        )
        .unwrap();

        // Alice can ban bob
        room.try_regular_proposals(
            &alice,
            &[MimiProposal::ChangeRole {
                target: bob.clone(),
                role: RoleIndex::Banned,
            }],
        )
        .unwrap();

        // Bob cannot rejoin
        assert_eq!(
            room.try_regular_proposals(
                &bob,
                &[MimiProposal::ChangeRole {
                    target: bob.clone(),
                    role: RoleIndex::Regular,
                }],
            ),
            Err(Error::NotCapable)
        );
    }
}
