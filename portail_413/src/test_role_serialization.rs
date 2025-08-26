use crate::models::user::UserRole;

#[test]
fn test_user_role_serialization() {
    let role = UserRole::Admin;
    let json = serde_json::to_string(&role).expect("Checked operation");
    log::info!("Sérialisation: {}", json);
    assert_eq!(json, r#""admin""#);
    
    let parsed: UserRole = serde_json::from_str(&json).expect("Checked operation");
    log::info!("Désérialisation: {:?}", parsed);
    assert_eq!(parsed, UserRole::Admin);
}
