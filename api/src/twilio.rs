//
// Twilio boilerplate
//

use anyhow::anyhow;
use anyhow::bail;

use surf::Body;
use surf::Client;
use surf::Request;
use surf::Response;

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
        PhoneNumber: &'a str,
        CountryCode: &'a str,
    }

    let query = Query { PhoneNumber: phone, CountryCode: country };

    let req = surf::get("PhoneNumbers")
        .query(&query)
        .map_err(|e| anyhow!(e))?
        .build();

    let mut res = do_twilio_request(req, Products::Lookups)
        .await
        .map_err(|e| anyhow!(e))?;

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

    let req = surf::post("Verifications")
        .body(Body::from_form(&form).map_err(|e| anyhow!(e))?)
        .build();

    let mut res = do_twilio_request(req, Products::Verify)
        .await
        .map_err(|e| anyhow!(e))?;

    let json: Value = res.body_json().await.map_err(|e| anyhow!(e))?;

    let status = match json["status"].as_str() {
        Some(p) => p,
        None => bail!("missing property `phone_number`"),
    };

    Ok(String::from(status))
}

pub async fn verify_check_status(sid: &str) -> Result<String>
{
    let path = format!("Verifications/{}", sid);

    let req = surf::get(path).build();
    let mut res = do_twilio_request(req, Products::Verify)
        .await
        .map_err(|e| anyhow!(e))?;

    let json: Value = res.body_json().await.map_err(|e| anyhow!(e))?;

    let status = match json["status"].as_str() {
        Some(p) => p,
        None => bail!("missing property `phone_number`"),
    };

    Ok(String::from(status))
}

pub async fn verify_code_submit(
    sid: &str,
    phone: &str,
    code: &str,
) -> Result<String>
{
    #[derive(Debug, Serialize, Deserialize)]
    #[allow(non_snake_case)]
    struct Form<'a>
    {
        To: &'a str,
        Code: &'a str,
    }

    let form = Form { To: phone, Code: code };

    let path = format!("VerificationCheck/{}", sid);

    let req = surf::post(path)
        .body(Body::from_form(&form).map_err(|e| anyhow!(e))?)
        .build();

    let mut res = do_twilio_request(req, Products::Verify)
        .await
        .map_err(|e| anyhow!(e))?;

    let json: Value = res.body_json().await.map_err(|e| anyhow!(e))?;

    let status = match json["status"].as_str() {
        Some(p) => p,
        None => bail!("missing property `phone_number`"),
    };

    Ok(String::from(status))
}


async fn do_twilio_request(
    req: Request,
    product: Products,
) -> surf::Result<Response>
{
    // e.g. twilio.com/v2
    let twilio_endpoint = env::var("TWILIO_API_ENDPOINT")?;

    let mut url = surf::Url::parse(&twilio_endpoint)?;

    let account_sid = env::var("TWILIO_ACCOUNT_SID")?;
    let service_sid = env::var("TWILIO_SERVICE_SID")?;
    let auth_token = env::var("TWILIO_AUTH_TOKEN")?;

    let host = url.host().ok_or_else(|| anyhow!("missing twilio host"))?;
    let host = format!("{}.{}", product.as_ref(), host);

    url.set_host(Some(&host))?;
    url.set_scheme("https").map_err(|_| anyhow!("bad scheme"))?;
    url.set_username(&account_sid).map_err(|_| anyhow!("bad username"))?;
    url.set_password(Some(&auth_token)).map_err(|_| anyhow!("bad password"))?;

    url.path_segments_mut()
        .map_err(|_| anyhow!("bad url path segments"))?
        .pop_if_empty()
        .extend(&["Services", &service_sid]);

    let client: Client = surf::Config::new().set_base_url(url).try_into()?;

    Ok(client.send(req).await?)
}
