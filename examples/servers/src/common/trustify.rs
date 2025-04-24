use reqwest::blocking::Client;
use rmcp::{Error as McpError, Error, ServerHandler, const_string, model::*, schemars, tool};
use serde_json::Value;

#[derive(Clone)]
pub struct Trustify {
    http_client: Client,
    base_url: String,
}

#[tool(tool_box)]
impl Trustify {
    pub fn new() -> Self {
        // Initialize HTTP client
        let http_client = Client::builder()
            .user_agent("trustify-tools-server")
            .build()
            .expect("Failed to create HTTP client");
        Self {
            http_client,
            base_url: "localhost:8080".to_string(),
        }
    }

    #[tool(description = "Call the info endpoint for a trustify instance")]
    fn trustify_info(&self) -> Result<CallToolResult, McpError> {
        // Trustify /.well-known/trustify URL
        let url = format!("http://{}/.well-known/trustify", self.base_url);
        self.call_url(url)
    }

    #[tool(description = "Get a list of sboms from a trustify instance")]
    fn trustify_sbom_list(
        &self,
        #[tool(param)]
        #[schemars(description = "Search query for sboms")]
        query: String,
        #[tool(param)]
        #[schemars(description = "Maximum number of sboms to return")]
        limit: usize,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "http://{}/api/v2/sbom?q={}&limit={}",
            self.base_url, query, limit
        );
        self.call_url(url)
    }

    #[tool(description = "Get a list of packages contained in an sboms from a trustify instance")]
    fn trustify_sbom_list_packages(
        &self,
        #[tool(param)]
        #[schemars(description = "Sbom URI")]
        sbom_uri: String,
        #[tool(param)]
        #[schemars(description = "Search query for packages within the SBOM")]
        query: String,
        #[tool(param)]
        #[schemars(description = "Maximum number of packages to return")]
        limit: usize,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "http://{}/api/v2/sbom/{}/packages?q={}&limit={}",
            self.base_url, sbom_uri, query, limit
        );
        self.call_url(url)
    }

    #[tool(
        description = "Provide the SBOM ID URN UUID to get a list of all the advisories with vulnerabilities related to an SBOM from a trustify instance"
    )]
    fn trustify_sbom_list_advisories(
        &self,
        #[tool(param)]
        #[schemars(description = "Sbom URI")]
        sbom_uri: String,
    ) -> Result<CallToolResult, McpError> {
        let url = format!("http://{}/api/v2/sbom/{}/advisory", self.base_url, sbom_uri);
        self.call_url(url)
    }

    #[tool(
        description = "Provide a package url-encoded PURL to get the list of vulnerabilities affecting if from a trustify instance"
    )]
    fn trustify_purl_vulnerabilities(
        &self,
        #[tool(param)]
        #[schemars(description = "Package URI or package PURL. Values must be url-encoded")]
        package_uri_or_purl: String,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "http://{}/api/v2/purl/{}",
            self.base_url, package_uri_or_purl
        );
        self.call_url(url)
    }

    #[tool(
        description = "Get a list of vulnerabilities from a trustify instance filtering them by severity and publication date and sorted by publish date"
    )]
    fn trustify_vulnerabilities_list(
        &self,
        #[tool(param)]
        #[schemars(description = "Query for vulnerabilities, e.g. average_severity=critical|high")]
        query: String,
        #[tool(param)]
        #[schemars(description = "Maximum number of packages to return, default 1000")]
        limit: usize,
        #[tool(param)]
        #[schemars(
            description = "Date after which the vulnerability has to be published, provided in the format 2025-04-20T22:00:00.000Z"
        )]
        published_after: String,
        #[tool(param)]
        #[schemars(
            description = "Date before which the vulnerability has to be published, provided in the format 2025-04-20T22:00:00.000Z"
        )]
        published_before: String,
        #[tool(param)]
        #[schemars(
            description = "Field used to sort the vulnerabilities in the output, e.g. 'published'"
        )]
        sort_field: String,
        #[tool(param)]
        #[schemars(
            description = "Sort direction, values allowed are only 'desc' and 'asc', default is 'desc'"
        )]
        sort_direction: String,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "http://{}/api/v2/vulnerability?limit={}&offset=0&q={}%26published>{}%26published<{}&sort={}:{}",
            self.base_url,
            limit,
            query,
            published_after,
            published_before,
            sort_field,
            sort_direction
        );
        self.call_url(url)
    }

    #[tool(description = "URL encode a string")]
    fn url_encode(
        &self,
        #[tool(param)]
        #[schemars(description = "String to be URL encoded")]
        input: String,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(
            urlencoding::encode(input.as_str()),
        )]))
    }

    fn call_url(&self, url: String) -> Result<CallToolResult, Error> {
        // Send the request
        let response = match self.http_client.get(url).send() {
            Ok(response) => response,
            Err(error) => {
                return Err(Error::internal_error(
                    format!("Trustify API returned error: {}", error),
                    None,
                ));
            }
        };

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(Error::internal_error(
                format!("Trustify API returned status code: {}", response.status()),
                None,
            ));
        }

        // Parse the response
        let response_json: Value = match response.json() {
            Ok(response_json) => response_json,
            Err(error) => {
                return Err(Error::internal_error(
                    format!("Trustify API returned error: {}", error),
                    None,
                ));
            }
        };

        Ok(CallToolResult::success(vec![Content::json(response_json)?]))
        // Ok(CallToolResult::success(vec![Content::text(
        //     response_json.to_string(),
        // )]))
    }
}

const_string!(Echo = "echo");
#[tool(tool_box)]
impl ServerHandler for Trustify {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("This server provides tools for interacting with a Trustify remote instance. The tools are able to retrieve info about the Trustify instance itself, the list of the SBOMs ingested, the packages and the vulnerabilities related to each SBOM. Further it can retrieve the vulnerabilities information ingested. More information about Trustify at https://github.com/trustification/trustify".to_string()),
        }
    }
}
