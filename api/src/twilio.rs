//
// Twilio boilerplate
//

use anyhow::anyhow;
use anyhow::bail;

use http_types::StatusCode;
use surf::Body;

use anyhow::Result;

use http_types::convert::{Deserialize, Serialize};

use serde_json::Value;

use std::env;

use std::convert::AsRef;
use strum_macros::AsRefStr;


#[derive(AsRefStr, Debug)]
enum Products
{
    #[strum(serialize = "lookups")]
    Lookups,
    #[strum(serialize = "verify")]
    Verify,
}


pub async fn validate_phone(phone: &str, country: &str) -> Result<String>
{
    #[derive(Debug, Serialize, Deserialize)]
    #[allow(non_snake_case)]
    struct Query<'a>
    {
        CountryCode: &'a str,
    }

    let query = Query { CountryCode: country };

    let path = format!("PhoneNumbers/{}", phone);
    let url = build_url(Products::Lookups, &path)?;

    let mut res = surf::get(url.as_str())
        .header("Authorization", basic_auth()?)
        .query(&query)
        .map_err(|e| anyhow!(e))?
        .await
        .map_err(|e| anyhow!(e))?;

    let status = res.status();
    if status != StatusCode::Ok {
        bail!("unexpected twilio response {}", status);
    }

    let json: Value = res.body_json().await.map_err(|e| anyhow!(e))?;

    let validated_phone = match json["phone_number"].as_str() {
        Some(p) => p,
        None => bail!("missing property `phone_number`"),
    };

    Ok(String::from(validated_phone))
}

pub async fn verify_phone(phone: &str) -> Result<String>
{
    #[derive(Debug, Serialize, Deserialize)]
    #[allow(non_snake_case)]
    struct Form<'a>
    {
        To: &'a str,
        Channel: &'a str,
    }

    let form = Form { To: phone, Channel: "sms" };

    let url = build_url(Products::Verify, "Verifications")?;

    let mut res = surf::post(url.as_str())
        .header("Authorization", basic_auth()?)
        .body(Body::from_form(&form).map_err(|e| anyhow!(e))?)
        .await
        .map_err(|e| anyhow!(e))?;

    let status = res.status();
    if status != StatusCode::Created {
        bail!("unexpected twilio response {}", status);
    }

    let json: Value = res.body_json().await.map_err(|e| anyhow!(e))?;

    let status = match json["sid"].as_str() {
        Some(p) => p,
        None => bail!("missing property `sid`"),
    };

    Ok(String::from(status))
}

pub async fn verify_check_status(sid: &str) -> Result<String>
{
    let path = format!("Verifications/{}", sid);
    let url = build_url(Products::Verify, &path)?;

    let mut res = surf::get(url.as_str())
        .header("Authorization", basic_auth()?)
        .await
        .map_err(|e| anyhow!(e))?;

    let status = res.status();

    if status == StatusCode::NotFound {
        return Ok("canceled".into());
    }

    if status != StatusCode::Ok {
        bail!("unexpected twilio response {}", status);
    }

    let json: Value = res.body_json().await.map_err(|e| anyhow!(e))?;

    let status = match json["status"].as_str() {
        Some(p) => p,
        None => bail!("missing property `status`"),
    };

    Ok(String::from(status))
}

pub async fn verify_status_update(sid: &str, status: &str) -> Result<()>
{
    #[derive(Debug, Serialize, Deserialize)]
    #[allow(non_snake_case)]
    struct Form<'a>
    {
        Status: &'a str,
    }

    let form = Form { Status: status };

    let path = format!("Verifications/{}", sid);
    let url = build_url(Products::Verify, &path)?;

    let mut res = surf::post(url.as_str())
        .header("Authorization", basic_auth()?)
        .body(Body::from_form(&form).map_err(|e| anyhow!(e))?)
        .await
        .map_err(|e| anyhow!(e))?;

    let status = res.status();

    if status != StatusCode::Ok {
        bail!("unexpected twilio response {}", status);
    }

    let json: Value = res.body_json().await.map_err(|e| anyhow!(e))?;

    let status = match json["status"].as_str() {
        Some(p) => p,
        None => bail!("missing property `status`"),
    };

    if form.Status == status {
        Ok(())
    } else {
        bail!("update mismatch");
    }
}

pub async fn verify_code_submit(phone: &str, code: &str) -> Result<String>
{
    #[derive(Debug, Serialize, Deserialize)]
    #[allow(non_snake_case)]
    struct Form<'a>
    {
        To: &'a str,
        Code: &'a str,
    }

    let form = Form { To: phone, Code: code };

    let url = build_url(Products::Verify, "VerificationCheck")?;

    let mut res = surf::post(url.as_str())
        .header("Authorization", basic_auth()?)
        .body(Body::from_form(&form).map_err(|e| anyhow!(e))?)
        .await
        .map_err(|e| anyhow!(e))?;

    let status = res.status();
    if status != 200 {
        bail!("unexpected twilio response {}", status);
    }

    let json: Value = res.body_json().await.map_err(|e| anyhow!(e))?;

    let status = match json["status"].as_str() {
        Some(p) => p,
        None => bail!("missing property `status`"),
    };

    Ok(String::from(status))
}

fn build_url(product: Products, function: &str) -> Result<surf::Url>
{
    // e.g. twilio.com/v2
    let twilio_endpoint = env::var("TWILIO_API_ENDPOINT")?;

    let mut url = surf::Url::parse(&twilio_endpoint)?;

    let service_sid = env::var("TWILIO_SERVICE_SID")?;

    let host = url.host().ok_or_else(|| anyhow!("missing twilio host"))?;
    let host = format!("{}.{}", product.as_ref(), host);

    url.set_host(Some(&host))?;
    url.set_scheme("https").map_err(|_| anyhow!("bad scheme"))?;

    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("bad url path segments"))?;

        match product {
            Products::Lookups => segments.pop_if_empty().extend(&["v2"]),
            Products::Verify => segments.pop_if_empty().extend(&[
                "v2",
                "Services",
                &service_sid,
            ]),
        };

        segments.extend(function.split("/"));
    }

    Ok(url)
}

fn basic_auth() -> Result<String>
{
    let account_sid = env::var("TWILIO_ACCOUNT_SID")?;
    let auth_token = env::var("TWILIO_AUTH_TOKEN")?;

    let credential = format!("{}:{}", account_sid, auth_token);

    Ok(format!("Basic {}", base64::encode(credential)))
}
