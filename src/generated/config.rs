use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "apiKey")]
    pub api_key: String,
    #[serde(alias = "askBehavior")]
    pub ask_behavior: Option<String>,
    #[serde(alias = "consumerId")]
    pub consumer_id: Option<String>,
    #[serde(alias = "evaluateResponse")]
    pub evaluate_response: Option<bool>,
    #[serde(alias = "failMode")]
    pub fail_mode: Option<String>,
    #[serde(alias = "mode")]
    pub mode: Option<String>,
    #[serde(alias = "providerName")]
    pub provider_name: Option<String>,
    #[serde(alias = "sessionIdBodyField")]
    pub session_id_body_field: Option<String>,
    #[serde(alias = "sessionIdHeader")]
    pub session_id_header: Option<String>,
    #[serde(alias = "timeoutMs")]
    pub timeout_ms: Option<i64>,
    #[serde(
        alias = "trustguardUrl",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub trustguard_url: pdk::hl::Service,
    #[serde(alias = "unrecognizedRequestFormat")]
    pub unrecognized_request_format: Option<String>,
    #[serde(alias = "unrecognizedResponseFormat")]
    pub unrecognized_response_format: Option<String>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    abi.service_create(config.trustguard_url)?;
    abi.setup()?;
    Ok(())
}
