use std::rc::Rc;

use envoy::error::format_err;
use envoy::extension::{filter::http, HttpFilter, InstanceId, Result};
use envoy::host::log::info;
use envoy::host::{ByteString, Clock};

use crate::{Digest, ShaSize, RequestBody};

use super::config::SampleHttpFilterConfig;
use super::stats::SampleHttpFilterStats;

// Sample HTTP Filter.
pub struct SampleHttpFilter<'a> {
    // This example shows how multiple filter instances could share
    // the same configuration.
    config: Rc<SampleHttpFilterConfig>,
    // This example shows how multiple filter instances could share
    // metrics.
    stats: Rc<SampleHttpFilterStats>,
    instance_id: InstanceId,
    // This example shows how to use Time API provided by Envoy host.
    clock: &'a dyn Clock,
    // This is the digest retrieved from the header
    digest: Digest,
}

impl<'a> SampleHttpFilter<'a> {
    /// Creates a new instance of Sample HTTP Filter.
    pub fn new(
        config: Rc<SampleHttpFilterConfig>,
        stats: Rc<SampleHttpFilterStats>,
        instance_id: InstanceId,
        clock: &'a dyn Clock,
    ) -> Self {
        // Inject dependencies on Envoy host APIs
        let digest = Digest::new(&ByteString::new(), ShaSize::TwoFiftySix);
        SampleHttpFilter {
            config,
            stats,
            instance_id,
            clock,
            digest,
        }
    }
}

impl<'a> HttpFilter for SampleHttpFilter<'a> {
    /// Called when HTTP request headers have been received.
    ///
    /// Use filter_ops to access and mutate request headers.
    fn on_request_headers(
        &mut self,
        _num_headers: usize,
        _end_of_stream: bool,
        filter_ops: &dyn http::RequestHeadersOps,
    ) -> Result<http::FilterHeadersStatus> {

        let digest_header_value = filter_ops.request_header("digest")?;
        if let Some(d) = digest_header_value {
            self.digest = Digest::from_base64_and_size(d, ShaSize::TwoFiftySix);
        }

        Ok(http::FilterHeadersStatus::Continue)
    }
   
    fn on_request_body(
        &mut self,
        data_size: usize,
        _end_of_stream: bool,
        filter_ops: &dyn http::RequestBodyOps
    ) -> Result<http::FilterDataStatus> {
        if !self.digest.is_empty() {

            let request_body = filter_ops.request_data(0, data_size)?;
            let body = RequestBody::new(&request_body);
            let digest = body.digest(ShaSize::TwoFiftySix);

            if !digest.as_string().eq(&self.digest.as_string()) {
                return Err(format_err!("received invalid digest header for the body"));
            }
        }

        Ok(http::FilterDataStatus::Continue)
    }


    /// Called when HTTP stream is complete.
    fn on_exchange_complete(&mut self, _ops: &dyn http::ExchangeCompleteOps) -> Result<()> {
        // Update stats
        self.stats.requests_total().inc()?;

        info!("#{} http exchange complete", self.instance_id);
        Ok(())
    }
}
