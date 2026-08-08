use reqwest::Url;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InstitutionalAccessError {
    #[error("invalid institutional proxy URL: {0}")]
    InvalidProxyUrl(String),
    #[error("invalid target URL: {0}")]
    InvalidTargetUrl(String),
    #[error("only HTTPS target URLs are supported")]
    UnsupportedTargetScheme,
    #[error("institutional URLs must use HTTPS on port 443 without embedded credentials")]
    UnsafeRemoteUrl,
    #[error("invalid institutional proxy target parameter")]
    InvalidTargetParameter,
}

#[derive(Debug, Clone)]
pub struct InstitutionalAccess {
    institution: String,
    proxy_login_url: Url,
    target_parameter: String,
}

#[derive(Debug, Serialize)]
pub struct InstitutionalAccessLink {
    pub institution: String,
    pub target_url: String,
    pub access_url: String,
    pub access_type: &'static str,
    pub interactive_authentication_required: bool,
    pub note: &'static str,
}

impl InstitutionalAccess {
    pub fn new(
        institution: String,
        proxy_login_url: String,
        target_parameter: String,
    ) -> Result<Self, InstitutionalAccessError> {
        let proxy_login_url = Url::parse(&proxy_login_url)
            .map_err(|err| InstitutionalAccessError::InvalidProxyUrl(err.to_string()))?;

        let proxy_host = proxy_login_url.host_str();
        if proxy_login_url.scheme() != "https"
            || proxy_login_url.port_or_known_default() != Some(443)
            || proxy_login_url.username() != ""
            || proxy_login_url.password().is_some()
            || proxy_host.is_none()
            || proxy_host
                .is_some_and(|host| host.ends_with('.') || psl::domain(host.as_bytes()).is_none())
        {
            return Err(InstitutionalAccessError::UnsafeRemoteUrl);
        }
        if target_parameter.is_empty()
            || target_parameter.len() > 64
            || !target_parameter
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(InstitutionalAccessError::InvalidTargetParameter);
        }

        Ok(Self {
            institution,
            proxy_login_url,
            target_parameter,
        })
    }

    pub fn access_link(
        &self,
        target_url: &str,
    ) -> Result<InstitutionalAccessLink, InstitutionalAccessError> {
        let target = Url::parse(target_url)
            .map_err(|err| InstitutionalAccessError::InvalidTargetUrl(err.to_string()))?;
        if target.scheme() != "https" {
            return Err(InstitutionalAccessError::UnsupportedTargetScheme);
        }
        if target.port_or_known_default() != Some(443)
            || target.username() != ""
            || target.password().is_some()
            || target.host_str().is_none()
        {
            return Err(InstitutionalAccessError::UnsafeRemoteUrl);
        }

        let mut access_url = self.proxy_login_url.clone();
        access_url
            .query_pairs_mut()
            .append_pair(&self.target_parameter, target.as_str());

        Ok(InstitutionalAccessLink {
            institution: self.institution.clone(),
            target_url: target.into(),
            access_url: access_url.into(),
            access_type: "institutional_browser_handoff",
            interactive_authentication_required: true,
            note: "Open access_url in a browser and complete the institution's login or MFA flow. The paper-search server does not receive or store credentials.",
        })
    }

    pub fn proxy_host(&self) -> &str {
        self.proxy_login_url
            .host_str()
            .expect("validated proxy URL has a host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ezproxy_access_link_with_encoded_target() {
        let access = InstitutionalAccess::new(
            "Example University".to_string(),
            "https://proxy.example.edu/login".to_string(),
            "url".to_string(),
        )
        .unwrap();

        let link = access
            .access_link("https://doi.org/10.1234/example?part=1")
            .unwrap();

        assert_eq!(link.institution, "Example University");
        assert_eq!(link.target_url, "https://doi.org/10.1234/example?part=1");
        assert!(link
            .access_url
            .starts_with("https://proxy.example.edu/login?"));
        let parsed = Url::parse(&link.access_url).unwrap();
        assert_eq!(
            parsed
                .query_pairs()
                .find(|(key, _)| key == "url")
                .map(|(_, value)| value.into_owned()),
            Some("https://doi.org/10.1234/example?part=1".to_string())
        );
        assert!(link.interactive_authentication_required);
    }

    #[test]
    fn rejects_non_http_target_schemes() {
        let access = InstitutionalAccess::new(
            "Example University".to_string(),
            "https://proxy.example.edu/login".to_string(),
            "url".to_string(),
        )
        .unwrap();

        assert!(matches!(
            access.access_link("file:///tmp/paper.pdf"),
            Err(InstitutionalAccessError::UnsupportedTargetScheme)
        ));
    }

    #[test]
    fn rejects_insecure_proxy_and_target_urls() {
        assert!(InstitutionalAccess::new(
            "Example University".to_string(),
            "http://proxy.example.edu/login".to_string(),
            "url".to_string(),
        )
        .is_err());

        let access = InstitutionalAccess::new(
            "Example University".to_string(),
            "https://proxy.example.edu/login".to_string(),
            "url".to_string(),
        )
        .unwrap();
        assert!(access
            .access_link("http://publisher.example/paper")
            .is_err());
        assert!(access
            .access_link("https://user:password@publisher.example/paper")
            .is_err());
        assert!(InstitutionalAccess::new(
            "Example University".to_string(),
            "https://edu/login".to_string(),
            "url".to_string(),
        )
        .is_err());
    }
}
