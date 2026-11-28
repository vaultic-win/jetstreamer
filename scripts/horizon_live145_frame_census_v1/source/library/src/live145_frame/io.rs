use super::*;
use serde::de::{MapAccess,SeqAccess,Visitor};
use std::{fmt,process::Command as ProcessCommand};
struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((name, UniqueJson(value))) =
                    map.next_entry::<String, UniqueJson>()?
                {
                    if values.insert(name, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON field"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub(super) fn unique_json(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UniqueJson(value) = UniqueJson::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

pub(super) fn properties(name: &str) -> Result<Value> {
    ensure!(
        (name.ends_with(".service") || name.ends_with(".timer"))
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c)),
        "invalid native unit name"
    );
    let guard_policy = false;
    let fields = if guard_policy {
        "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainCode,ControlGroup,ExecStart,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,TriggeredBy,Triggers,Unit,User,Type,TimeoutStartUSec"
    } else {
        "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainCode,ControlGroup,ExecStart,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,TriggeredBy,Triggers,Unit,User,Type"
    };
    let out = ProcessCommand::new("/usr/bin/timeout")
        .args(["--signal=TERM","--kill-after=2s","8s","/usr/bin/systemctl","--system","show", name, "--no-pager", fields])
        .env_remove("SYSTEMD_HOST").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env("LC_ALL","C")
        .output()?;
    ensure!(
        out.stdout.len() <= 1 << 20,
        "native property output bound exceeded"
    );
    let mut values = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("invalid native property line: {line:?}"))?;
        ensure!(
            values.insert(key.into(), json!(value)).is_none(),
            "duplicate native property"
        );
    }
    let value = Value::Object(values);
    ensure!(
        value["Id"] == name
            && (out.status.success()
                || (value["LoadState"] == "not-found" && value["MainPID"] == "0")),
        "native unit query failed"
    );
    Ok(value)
}
