use std::rc::Rc;

use envoy::error::format_err;
use envoy::extension::{filter::http, HttpFilter, InstanceId, Result};
use envoy::host::log::info;
use envoy::host::{ByteString, Clock};

use chrono::{offset::Local, DateTime};

use crate::{Digest, RequestBody, ShaSize};

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
        let now: DateTime<Local> = self.clock.now()?.into();

        info!(
            "#{} new http exchange starts at {} with config: {:?}",
            self.instance_id,
            now.format("%+"),
            self.config,
        );

        info!("#{} observing request headers", self.instance_id);
        for (name, value) in &filter_ops.request_headers()? {
            info!("#{} -> {}: {}", self.instance_id, name, value);
        }

        let digest_header_value = filter_ops.request_header("digest")?;
        if let Some(d) = digest_header_value {
            self.digest = Digest::from_base64_and_size(d, ShaSize::TwoFiftySix);
            info!(
                "#{} found a digest header at {} with value: {}",
                self.instance_id,
                now.format("%+"),
                self.digest
            );
        }

        Ok(http::FilterHeadersStatus::Continue)
    }

    fn on_request_body(
        &mut self,
        data_size: usize,
        end_of_stream: bool,
        filter_ops: &dyn http::RequestBodyOps,
    ) -> Result<http::FilterDataStatus> {
        let now: DateTime<Local> = self.clock.now()?.into();

        if !self.digest.is_empty() {
            let request_body = filter_ops.request_data(0, data_size)?;
            let body = RequestBody::new(&request_body);
            let digest = body.digest(ShaSize::TwoFiftySix);

            if end_of_stream && !digest.as_string().eq(&self.digest.as_string()) {
                info!(
                    "#{} found a digest header at {} with value: {} and body digest value {}",
                    self.instance_id,
                    now.format("%+"),
                    self.digest,
                    digest.as_string()
                );
                if let Err(err) = filter_ops.send_response(
                    400,
                    &[(":status", "")],
                    Some(b"body digest different from digest header value\n"),
                ) {
                    return Err(err);
                }
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
