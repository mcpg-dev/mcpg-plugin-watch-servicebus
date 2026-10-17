//! An HTTP client for tests: it stands in for Entra ID and IMDS, records
//! each request the credentials send and answers with canned JSON.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use azure_core::error::ErrorKind;
use azure_core::http::headers::Headers;
use azure_core::http::{
    AsyncRawResponse, Body, ClientOptions, HttpClient, Method, Request, StatusCode, Transport, Url,
};

/// One request, as it reached the transport.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    pub method: Method,
    pub url: Url,
    /// Each header, its name in lower case.
    pub headers: BTreeMap<String, String>,
    /// The fields of a form-encoded body; empty for any other body.
    pub form: BTreeMap<String, String>,
}

impl Recorded {
    /// The URL without its query.
    pub(crate) fn endpoint(&self) -> String {
        let mut url = self.url.clone();
        url.set_query(None);
        url.into()
    }

    /// The query parameters.
    pub(crate) fn query(&self) -> BTreeMap<String, String> {
        self.url.query_pairs().into_owned().collect()
    }
}

#[derive(Debug, Default)]
pub(crate) struct Recorder {
    requests: Mutex<Vec<Recorded>>,
    responses: Mutex<VecDeque<(StatusCode, String)>>,
}

impl Recorder {
    /// A client that answers with `responses` in turn, each a status and a
    /// JSON body.
    pub(crate) fn answering(
        responses: impl IntoIterator<Item = (StatusCode, serde_json::Value)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            requests: Mutex::default(),
            responses: Mutex::new(
                responses
                    .into_iter()
                    .map(|(status, body)| (status, body.to_string()))
                    .collect(),
            ),
        })
    }

    /// Client options whose transport is this client.
    pub(crate) fn client_options(self: &Arc<Self>) -> ClientOptions {
        ClientOptions {
            transport: Some(Transport::new(Arc::clone(self) as Arc<dyn HttpClient>)),
            ..ClientOptions::default()
        }
    }

    /// The requests so far, in order.
    pub(crate) fn requests(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[async_trait::async_trait]
impl HttpClient for Recorder {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        let form = match request.body() {
            Body::Bytes(bytes) => url::form_urlencoded::parse(bytes).into_owned().collect(),
            _ => BTreeMap::new(),
        };
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    value.as_str().to_owned(),
                )
            })
            .collect();
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Recorded {
                method: request.method(),
                url: request.url().clone(),
                headers,
                form,
            });
        let (status, body) = self
            .responses
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
            .ok_or_else(|| {
                azure_core::Error::with_message(ErrorKind::Other, "no canned response left")
            })?;
        Ok(AsyncRawResponse::from_bytes(
            status,
            Headers::new(),
            body.into_bytes(),
        ))
    }
}
