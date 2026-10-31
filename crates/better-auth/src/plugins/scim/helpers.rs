pub(super) fn scim_group_member_id(group_id: &str, user_id: &str) -> String {
    format!("{group_id}:{user_id}")
}
