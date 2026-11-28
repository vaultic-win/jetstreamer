// These exact sources implement the fixed historical235v2 remote-object
// metadata prestart. Sharing the launcher does not make a different command a
// consumer of235/237 indices. Ordinary scripts and every selected-root/actor,
// metadata-plan, process, mapping, descriptor and staged-reference gate remain.
const SHARED_GCLOUD_METADATA: &[(&str, &str)] = &[
    (
        "/home/linuxbrew/.linuxbrew/share/google-cloud-sdk/bin/gcloud",
        "03d163265c038e9a67b0760ed98de9b5970c4c9d172dbfec03384939d02d4800",
    ),
    (
        "/home/linuxbrew/.linuxbrew/share/google-cloud-sdk/lib/gcloud.py",
        "c8acc602cebef4ca64ecfdb4f531718dd2dce85a86c735a52530f9555eb02962",
    ),
    (
        "/home/linuxbrew/.linuxbrew/share/google-cloud-sdk/lib/surface/storage/objects/describe.py",
        "ba3dad2e4284af208cce4e31ea85c85c038905a62fc4c6b5421d6d23b7f950b5",
    ),
    (
        "/home/linuxbrew/.linuxbrew/share/google-cloud-sdk/lib/googlecloudsdk/api_lib/storage/gcs_json/client.py",
        "a8c72d042ee98c13571b8bd8938bde0f43e7f78e3ab20a64928aba88ce76ca07",
    ),
];
fn validate_shared_gcloud_metadata(r: &Recipe) -> Result<()> {
    for i in &r.inputs {
        if i.kind != InputKind::SharedGcloudMetadataScript {
            continue;
        }
        ensure!(
            r.role == RecipeRole::CompletedProducer
                && r.installed == Path::new("/run/systemd/system/horizon-qualify-235-general-shrink-debt-budget506-e3f15eb2-v2.service")
                && r.original.sha256 == "c069beaf526b0dc7121a350f001bac10a6cfa249a826803ecfa09d8d4a976264"
                && r.terminal_actor.unit == "horizon-qualify-235-general-shrink-debt-budget506-e3f15eb2-v2.service"
                && r.terminal_actor.invocation_id == "b8c33086cca3407a8a1d79953b40b542"
                && i.binding.uid == 1000
                && i.json_type.is_none()
                && i.children.is_empty()
                && SHARED_GCLOUD_METADATA.iter().any(|(path, digest)| {
                    i.binding.path == Path::new(path) && i.binding.sha256 == *digest
                }),
            "not exact historical235v2 shared metadata-script provenance"
        );
    }
    Ok(())
}

#[cfg(test)]
mod shared_gcloud_metadata_tests {
    use super::*;
    fn recipe() -> Recipe {
        let (installed, digest, unit, role) = FIXED_RECIPES
            .iter()
            .find(|(_, _, unit, _)| {
                *unit == "horizon-qualify-235-general-shrink-debt-budget506-e3f15eb2-v2.service"
            })
            .unwrap();
        Recipe {
            installed: (*installed).into(),
            original: Evidence {
                path: format!("/var/lib/jetstreamer/retained/{unit}").into(),
                sha256: (*digest).into(),
                uid: 0,
            },
            role: *role,
            terminal_actor: Actor {
                unit: (*unit).into(),
                invocation_id: "b8c33086cca3407a8a1d79953b40b542".into(),
                historical_provenance: None,
            },
            readset_review: Evidence {
                path: "/var/lib/jetstreamer/readset.json".into(),
                sha256: "a".repeat(64),
                uid: 0,
            },
            inputs: SHARED_GCLOUD_METADATA
                .iter()
                .map(|(path, digest)| Input {
                    binding: Evidence {
                        path: (*path).into(),
                        sha256: (*digest).into(),
                        uid: 1000,
                    },
                    kind: InputKind::SharedGcloudMetadataScript,
                    json_type: None,
                    children: Vec::new(),
                })
                .collect(),
        }
    }
    #[test]
    fn only_exact_metadata_scripts_in_the_original235v2_role_can_be_shared_provenance() {
        let mut p = crate::tests::plan();
        p.typed_recipes.push(recipe());
        validate(&p).unwrap();
        for n in 0..SHARED_GCLOUD_METADATA.len() {
            for field in ["path", "digest", "uid", "children", "json"] {
                let mut r = recipe();
                let i = &mut r.inputs[n];
                match field {
                    "path" => i.binding.path = "/var/lib/jetstreamer/arbitrary.py".into(),
                    "digest" => i.binding.sha256 = "b".repeat(64),
                    "uid" => i.binding.uid = 0,
                    "children" => i.children.push("/var/lib/jetstreamer/spec.json".into()),
                    "json" => i.json_type = Some(JsonType::PriorIndexPlan),
                    _ => unreachable!(),
                }
                assert!(validate_shared_gcloud_metadata(&r).is_err(), "{n}: {field}");
            }
        }
        for field in ["role", "installed", "recipe", "unit", "iid"] {
            let mut r = recipe();
            match field {
                "role" => r.role = RecipeRole::Publication,
                "installed" => r.installed = "/etc/systemd/system/foreign.service".into(),
                "recipe" => r.original.sha256 = "b".repeat(64),
                "unit" => r.terminal_actor.unit = "foreign.service".into(),
                "iid" => r.terminal_actor.invocation_id = "b".repeat(32),
                _ => unreachable!(),
            }
            assert!(validate_shared_gcloud_metadata(&r).is_err(), "{field}");
        }
    }
    #[test]
    fn shared_launcher_alone_is_not_an_index_reference_but_actual_consumer_edges_remain() {
        let mut p = crate::tests::plan();
        p.typed_recipes.push(recipe());
        let command = format!(
            "ExecStart={} storage objects describe gs://another/object\n",
            SHARED_GCLOUD_METADATA[0].0
        );
        assert!(!indirect_reference(command.as_bytes(), &p));
        assert!(!recipe_reference(command.as_bytes(), &p));
        let target = format!(
            "{} --output={}\n",
            command.trim(),
            p.indexes[0].path.display()
        );
        assert!(recipe_reference(target.as_bytes(), &p));
        for i in &p.typed_recipes[0].inputs {
            assert!(!consumer_input(i));
            assert!(!input_links_allowed(
                &i.kind,
                &i.binding.path,
                1000,
                1000,
                2
            ));
        }
        p.typed_recipes[0].inputs[0].kind = InputKind::Script;
        assert!(indirect_reference(command.as_bytes(), &p));
        p.typed_recipes[0].inputs[0].kind = InputKind::Json;
        p.typed_recipes[0].inputs[0].json_type = Some(JsonType::PriorIndexPlan);
        assert!(indirect_reference(command.as_bytes(), &p));
        p.typed_recipes[0].inputs[0].json_type = Some(JsonType::PublicationV2);
        assert!(indirect_reference(command.as_bytes(), &p));
    }
}
