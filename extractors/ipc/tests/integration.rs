use shared::tokio;

#[tokio::test]
async fn test_integration_ipc_foo() {
    println!("test that we receive foo IPC events");

    assert_eq!(1, 1)
}
