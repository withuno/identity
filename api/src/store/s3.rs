use std::fmt;

use serde::Deserialize;
use serde_xml_rs::from_reader;

#[derive(Debug, Clone)]
pub struct DeserializationError;

#[derive(Debug, Clone)]
pub struct SerializationError;

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid data for deserialization")
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Contents {
    #[serde(rename = "Key")]
    pub key: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct ListBucketResult {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Prefix")]
    prefix: String,
    #[serde(rename = "KeyCount")]
    key_count: i32,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,

    #[serde(rename = "Contents", default)]
    pub contents: Vec<Contents>,
}

impl ListBucketResult {
    pub fn from_xml(xml: &[u8]) -> Result<ListBucketResult, DeserializationError> {
        from_reader(xml).or(Err(DeserializationError))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_bucket_response() {
        let r = r#"
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>somebucket</Name><Prefix>multi</Prefix><KeyCount>4</KeyCount><MaxKeys>4500</MaxKeys><Delimiter></Delimiter><IsTruncated>false</IsTruncated><Contents><Key>multi/key1/file1</Key><LastModified>2021-06-24T14:14:00.068Z</LastModified><ETag>&#34;3b98e2dffc6cb06a89dcb0d5c60a0206&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multi/key1/file2</Key><LastModified>2021-06-24T14:14:00.074Z</LastModified><ETag>&#34;3b98e2dffc6cb06a89dcb0d5c60a0206&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multi/key2/file1</Key><LastModified>2021-06-24T14:14:00.080Z</LastModified><ETag>&#34;9d3d9048db16a7eee539e93e3618cbe7&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>multiother/file1</Key><LastModified>2021-06-24T14:14:00.086Z</LastModified><ETag>&#34;aa53ca0b650dfd85c4f59fa156f7a2cc&#34;</ETag><Size>2</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents><EncodingType>url</EncodingType></ListBucketResult>
"#;

        let response = ListBucketResult::from_xml(r.as_bytes()).unwrap();

        assert_eq!(
            response,
            ListBucketResult {
                name: "somebucket".to_string(),
                prefix: "multi".to_string(),
                key_count: 4,
                is_truncated: false,
                contents: vec!(
                    Contents {
                        key: "multi/key1/file1".to_string()
                    },
                    Contents {
                        key: "multi/key1/file2".to_string()
                    },
                    Contents {
                        key: "multi/key2/file1".to_string()
                    },
                    Contents {
                        key: "multiother/file1".to_string()
                    }
                ),
            }
        );
    }
}
