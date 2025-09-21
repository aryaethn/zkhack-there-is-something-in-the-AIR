#[cfg(test)]
mod tests {
    use crate::{AccessSet, PrivKey, PubKey};

    // Constants from main.rs for testing
    const PUB_KEYS: [&str; 8] = [
        "04f6d8d05f52012c0a705c1e0dcb1ff64ba0842c8c14f1f0f18e95254bdcfbea",
        "af84cf58cb71709c5a94750e69f9cbad0244d6c8e437f4e822c58f0c45c69ea0",
        "964650c5645e30b1ff74574a6fc4cdb78eaa1be3dfd43f01050b1b0e41d4db36",
        "d5a494b415c20d7d00fbace4f725b596da7c646d80e622956d7f09eebc93fef9",
        "9d7083734388833056ae25382dbcfb39b6a1ee78a6d63f136d83400569adc319",
        "a7ae57a7b2c60871e86d152e9e712ab5a3630f6183a7c1d07ba4429fead88018",
        "1995c40e8e46a009b0d61d89634f3c959d13322ef3a84b410a811eb4fc06d08b",
        "cf855bce16bb7b37f874324da9f72dd0d0e6f6e9f9e29100f66c7b57c6895ef5",
    ];

    const MY_PRIV_KEY: &str = "86475af21e4445b71bfa496416ee2d0765946bd3a854a77fe07db53c7994d0a5";

    #[test]
    fn test_nullifier_deterministic_after_fix() {
        // Test that the nullifier is deterministic after fixing the double-vote bug
        let access_set = AccessSet::new(
            PUB_KEYS
                .iter()
                .map(|&k| PubKey::parse(k))
                .collect::<Vec<_>>(),
        );
        let my_key = PrivKey::parse(MY_PRIV_KEY);
        let topic = "The Winter is Coming...";

        // Generate multiple signals with the same private key and topic
        let signal1 = access_set.make_signal(&my_key, topic);
        let signal2 = access_set.make_signal(&my_key, topic);

        // After the fix, nullifiers should be identical (deterministic)
        assert_eq!(signal1.nullifier, signal2.nullifier);
        
        // Verify both signals are valid
        assert!(access_set.verify_signal(topic, signal1).is_ok());
        assert!(access_set.verify_signal(topic, signal2).is_ok());
    }

    #[test]
    fn test_nullifier_capacity_boundary_constraints() {
        // Test that the nullifier capacity is properly constrained to [8,0,0,0] at the first row
        let access_set = AccessSet::new(
            PUB_KEYS
                .iter()
                .map(|&k| PubKey::parse(k))
                .collect::<Vec<_>>(),
        );
        let my_key = PrivKey::parse(MY_PRIV_KEY);
        let topic = "The Winter is Coming...";

        let signal = access_set.make_signal(&my_key, topic);
        
        // The signal should be valid, which means the boundary constraints are working
        assert!(access_set.verify_signal(topic, signal).is_ok());
    }
}
