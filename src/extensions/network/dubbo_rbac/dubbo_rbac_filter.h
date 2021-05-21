#pragma once

#include "envoy/extensions/filters/network/rbac/v3/rbac.pb.h"
#include "extensions/filters/network/dubbo_proxy/filters/filter.h"
#include "envoy/stats/stats_macros.h"

#include "common/common/logger.h"

#include "extensions/filters/common/rbac/engine_impl.h"
#include "extensions/filters/common/rbac/utility.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DubboProxy {
namespace RBACFilter {

enum EngineResult { Unknown, None, Allow, Deny };

struct Result {
  EngineResult engine_result_;
  std::string connection_termination_details_;
};

static const std::string DubboRbacFilterName = "envoy.filters.dubbo.rbac";

class DubboRbacDynamicMetadataKeys {
public:
    const std::string ServiceField{"service"};
    const std::string MethodField{"method"};
};

using DubboRbacDynamicMetadataKeysSingleton = ConstSingleton<DubboRbacDynamicMetadataKeys>;

/**
 * Configuration for the RBAC network filter.
 */
class RoleBasedAccessControlFilterConfig {
public:
  RoleBasedAccessControlFilterConfig(
      const envoy::extensions::filters::network::rbac::v3::RBAC& proto_config, Stats::Scope& scope);

  Filters::Common::RBAC::RoleBasedAccessControlFilterStats& stats() { return stats_; }

  std::string shadowEffectivePolicyIdField() const {
    return shadow_rules_stat_prefix_ +
           Filters::Common::RBAC::DynamicMetadataKeysSingleton::get().ShadowEffectivePolicyIdField;
  }
  std::string shadowEngineResultField() const {
    return shadow_rules_stat_prefix_ +
           Filters::Common::RBAC::DynamicMetadataKeysSingleton::get().ShadowEngineResultField;
  }

  const Filters::Common::RBAC::RoleBasedAccessControlEngineImpl*
  engine(Filters::Common::RBAC::EnforcementMode mode) const {
    return mode == Filters::Common::RBAC::EnforcementMode::Enforced ? engine_.get()
                                                                    : shadow_engine_.get();
  }

  envoy::extensions::filters::network::rbac::v3::RBAC::EnforcementType enforcementType() const {
    return enforcement_type_;
  }

private:
  Filters::Common::RBAC::RoleBasedAccessControlFilterStats stats_;
  const std::string shadow_rules_stat_prefix_;

  std::unique_ptr<Filters::Common::RBAC::RoleBasedAccessControlEngineImpl> engine_;
  std::unique_ptr<Filters::Common::RBAC::RoleBasedAccessControlEngineImpl> shadow_engine_;
  const envoy::extensions::filters::network::rbac::v3::RBAC::EnforcementType enforcement_type_;
};

using RoleBasedAccessControlFilterConfigSharedPtr =
    std::shared_ptr<RoleBasedAccessControlFilterConfig>;

/**
 * Implementation of a basic RBAC network filter.
 */
class RoleBasedAccessControlFilter : public DubboFilters::DecoderFilter,
                                     public Logger::Loggable<Logger::Id::rbac> {

public:
  RoleBasedAccessControlFilter(RoleBasedAccessControlFilterConfigSharedPtr config)
      : config_(config) {}
  ~RoleBasedAccessControlFilter() override = default;

  // Network::ReadFilter
  DubboProxy::FilterStatus onMessageDecoded(MessageMetadataSharedPtr metadata, ContextSharedPtr ctx) override;
  void setDecoderFilterCallbacks(DubboFilters::DecoderFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }

  void setShadowResult(std::string shadow_engine_result, std::string shadow_policy_id);

  void onDestroy() override {};

  void setDynamicMetadata(const DubboProxy::RpcInvocation& invocation);
  void clearDynamicMetadata();

private:
  RoleBasedAccessControlFilterConfigSharedPtr config_;
  DubboFilters::DecoderFilterCallbacks* callbacks_{};
  EngineResult engine_result_{Unknown};
  EngineResult shadow_engine_result_{Unknown};

  Result checkEngine(Filters::Common::RBAC::EnforcementMode mode);
};

} // namespace RBACFilter
} // namespace DubboProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
