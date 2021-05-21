#include "src/extensions/network/dubbo_rbac/dubbo_rbac_filter.h"

#include "envoy/buffer/buffer.h"
#include "envoy/extensions/filters/network/rbac/v3/rbac.pb.h"
#include "envoy/network/connection.h"

#include "absl/strings/str_join.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DubboProxy {
namespace RBACFilter {

RoleBasedAccessControlFilterConfig::RoleBasedAccessControlFilterConfig(
    const envoy::extensions::filters::network::rbac::v3::RBAC& proto_config, Stats::Scope& scope)
    : stats_(Filters::Common::RBAC::generateStats(proto_config.stat_prefix(),
                                                  proto_config.shadow_rules_stat_prefix(), scope)),
      shadow_rules_stat_prefix_(proto_config.shadow_rules_stat_prefix()),
      engine_(Filters::Common::RBAC::createEngine(proto_config)),
      shadow_engine_(Filters::Common::RBAC::createShadowEngine(proto_config)),
      enforcement_type_(proto_config.enforcement_type()) {}

void RoleBasedAccessControlFilter::clearDynamicMetadata() {
  envoy::config::core::v3::Metadata& dynamic_metadata =
      callbacks_->streamInfo().dynamicMetadata();
  auto& metadata =
      (*dynamic_metadata.mutable_filter_metadata())[DubboRbacFilterName];
  metadata.mutable_fields()->clear();
}

void RoleBasedAccessControlFilter::setDynamicMetadata(const DubboProxy::RpcInvocation& invocation) {
  envoy::config::core::v3::Metadata& dynamic_metadata =
      callbacks_->streamInfo().dynamicMetadata();

  ProtobufWkt::Struct metadata(
      (*dynamic_metadata.mutable_filter_metadata())[DubboRbacFilterName]);
  auto& fields = *metadata.mutable_fields();

  *fields[DubboRbacDynamicMetadataKeysSingleton::get().ServiceField].mutable_string_value() = invocation.serviceName();
  *fields[DubboRbacDynamicMetadataKeysSingleton::get().MethodField].mutable_string_value() = invocation.methodName();

  callbacks_->streamInfo().setDynamicMetadata(
          DubboRbacFilterName, metadata);
}

DubboProxy::FilterStatus RoleBasedAccessControlFilter::onMessageDecoded(MessageMetadataSharedPtr metadata, ContextSharedPtr) {
  if (callbacks_->connection() == nullptr) {
    ENVOY_LOG(debug, "no connection, reject");
    return DubboProxy::FilterStatus::StopIteration;
  }

  const auto& invocation = metadata->invocationInfo();

  clearDynamicMetadata();
  setDynamicMetadata(invocation);

  ENVOY_LOG(
      debug,
      "checking connection: requestedServerName: {}, sourceIP: {}, directRemoteIP: {},"
      "remoteIP: {}, localAddress: {}, ssl: {}, dynamicMetadata: {}",
      callbacks_->connection()->requestedServerName(),
      callbacks_->connection()->addressProvider().remoteAddress()->asString(),
      callbacks_->streamInfo().downstreamAddressProvider().directRemoteAddress()->asString(),
      callbacks_->streamInfo().downstreamAddressProvider().remoteAddress()->asString(),
      callbacks_->streamInfo().downstreamAddressProvider().localAddress()->asString(),
      callbacks_->connection()->ssl()
          ? "uriSanPeerCertificate: " +
                absl::StrJoin(callbacks_->connection()->ssl()->uriSanPeerCertificate(), ",") +
                ", dnsSanPeerCertificate: " +
                absl::StrJoin(callbacks_->connection()->ssl()->dnsSansPeerCertificate(), ",") +
                ", subjectPeerCertificate: " +
                callbacks_->connection()->ssl()->subjectPeerCertificate()
          : "none",
      callbacks_->streamInfo().dynamicMetadata().DebugString());

  std::string log_policy_id = "none";
  // When the enforcement type is continuous always do the RBAC checks. If it is a one time check,
  // run the check once and skip it for subsequent onData calls.
  if (config_->enforcementType() ==
      envoy::extensions::filters::network::rbac::v3::RBAC::CONTINUOUS) {
    shadow_engine_result_ =
        checkEngine(Filters::Common::RBAC::EnforcementMode::Shadow).engine_result_;
    auto result = checkEngine(Filters::Common::RBAC::EnforcementMode::Enforced);
    engine_result_ = result.engine_result_;
    log_policy_id = result.connection_termination_details_;
  } else {
    if (shadow_engine_result_ == Unknown) {
      // TODO(quanlin): Pass the shadow engine results to other filters.
      shadow_engine_result_ =
          checkEngine(Filters::Common::RBAC::EnforcementMode::Shadow).engine_result_;
    }

    if (engine_result_ == Unknown) {
      auto result = checkEngine(Filters::Common::RBAC::EnforcementMode::Enforced);
      engine_result_ = result.engine_result_;
      log_policy_id = result.connection_termination_details_;
    }
  }

  if (engine_result_ == Allow) {
    return DubboProxy::FilterStatus::Continue;
  } else if (engine_result_ == Deny) {
    return DubboProxy::FilterStatus::StopIteration;
  }

  ENVOY_LOG(debug, "no engine, allowed by default");
  return DubboProxy::FilterStatus::Continue;
}

void RoleBasedAccessControlFilter::setShadowResult(std::string shadow_engine_result,
                                                      std::string shadow_policy_id) {
  ProtobufWkt::Struct metrics;
  auto& fields = *metrics.mutable_fields();
  if (!shadow_policy_id.empty()) {
    *fields[config_->shadowEffectivePolicyIdField()].mutable_string_value() = shadow_policy_id;
  }
  *fields[config_->shadowEngineResultField()].mutable_string_value() = shadow_engine_result;
  callbacks_->streamInfo().setDynamicMetadata(DubboRbacFilterName, metrics);
}

Result RoleBasedAccessControlFilter::checkEngine(Filters::Common::RBAC::EnforcementMode mode) {
  const auto engine = config_->engine(mode);
  std::string effective_policy_id;
  if (engine != nullptr) {
    // Check authorization decision and do Action operations
    bool allowed = engine->handleAction(
        *callbacks_->connection(), callbacks_->streamInfo(), &effective_policy_id);
    const std::string log_policy_id = effective_policy_id.empty() ? "none" : effective_policy_id;
    if (allowed) {
      if (mode == Filters::Common::RBAC::EnforcementMode::Shadow) {
        ENVOY_LOG(debug, "shadow allowed, matched policy {}", log_policy_id);
        config_->stats().shadow_allowed_.inc();
        setShadowResult(
            Filters::Common::RBAC::DynamicMetadataKeysSingleton::get().EngineResultAllowed,
            effective_policy_id);
      } else if (mode == Filters::Common::RBAC::EnforcementMode::Enforced) {
        ENVOY_LOG(debug, "enforced allowed, matched policy {}", log_policy_id);
        config_->stats().allowed_.inc();
      }
      return Result{Allow, effective_policy_id};
    } else {
      if (mode == Filters::Common::RBAC::EnforcementMode::Shadow) {
        ENVOY_LOG(debug, "shadow denied, matched policy {}", log_policy_id);
        config_->stats().shadow_denied_.inc();
        setShadowResult(
            Filters::Common::RBAC::DynamicMetadataKeysSingleton::get().EngineResultDenied,
            effective_policy_id);
      } else if (mode == Filters::Common::RBAC::EnforcementMode::Enforced) {
        ENVOY_LOG(debug, "enforced denied, matched policy {}", log_policy_id);
        config_->stats().denied_.inc();
      }
      return Result{Deny, log_policy_id};
    }
  }
  return Result{None, "none"};
}

} // namespace RBACFilter
} // namespace DubboProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
